package cluster

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	core "github.com/gantry-tools/gantry-core/cluster"
	"github.com/webfleet-cv/webfleet/internal/database"
)

type Transport struct {
	db       *database.DB
	identity *Service
	client   *http.Client
	now      func() time.Time
}

func NewTransport(db *database.DB, identity *Service, client *http.Client) *Transport {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Transport{db: db, identity: identity, client: client, now: time.Now}
}
func (t *Transport) Authenticate(r *http.Request, capability string) ([]byte, string, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, core.MaxRequestBytes+1))
	if err != nil || int64(len(body)) > core.MaxRequestBytes {
		return nil, "", errors.New("cluster request too large")
	}
	env, err := core.ReadEnvelope(r.Header, t.now().UTC())
	if err != nil {
		return nil, "", err
	}
	secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if secret == "" {
		return nil, "", errors.New("cluster credential required")
	}
	var state, capsJSON string
	var protocol int
	var inbound, pendingInbound []byte
	var pendingExpires sql.NullString
	if err = t.db.QueryRowContext(r.Context(), `SELECT state,protocol_version,capabilities_json,inbound_secret_hash,pending_inbound_secret_hash,pending_inbound_expires_at FROM cluster_members WHERE node_id=?`, env.NodeID).Scan(&state, &protocol, &capsJSON, &inbound, &pendingInbound, &pendingExpires); err != nil {
		return nil, "", errors.New("cluster member unavailable")
	}
	var caps []string
	_ = json.Unmarshal([]byte(capsJSON), &caps)
	var pendingExpiry *time.Time
	if pendingExpires.Valid {
		if parsed, parseErr := time.Parse(time.RFC3339Nano, pendingExpires.String); parseErr == nil {
			pendingExpiry = &parsed
		}
	}
	verified, err := core.VerifyIncoming(core.VerifyRequestInput{Material: core.AuthMaterial{State: state, Protocol: protocol, Capabilities: caps, CurrentHash: inbound, PendingHash: pendingInbound, PendingExpires: pendingExpiry}, RequiredCapability: capability, PresentedSecret: secret, Method: r.Method, RequestURI: r.URL.RequestURI(), Envelope: env, Body: body, Now: t.now().UTC()})
	if err != nil {
		return nil, "", err
	}
	if verified.PromotePending {
		if _, err = t.db.ExecContext(r.Context(), `UPDATE cluster_members SET inbound_secret_hash=pending_inbound_secret_hash,pending_inbound_secret_hash=NULL,pending_inbound_expires_at=NULL,credential_version=credential_version+1 WHERE node_id=?`, env.NodeID); err != nil {
			return nil, "", err
		}
	}
	_, _ = t.db.ExecContext(r.Context(), `DELETE FROM cluster_nonces WHERE seen_at<?`, t.now().UTC().Add(-2*core.ClockSkew).Format(time.RFC3339Nano))
	if _, err = t.db.ExecContext(r.Context(), `INSERT INTO cluster_nonces(node_id,nonce,seen_at) VALUES(?,?,?)`, env.NodeID, env.Nonce, t.now().UTC().Format(time.RFC3339Nano)); err != nil {
		return nil, "", errors.New("cluster replay rejected")
	}
	_, _ = t.db.ExecContext(r.Context(), `UPDATE cluster_members SET last_seen_at=? WHERE node_id=?`, t.now().UTC().Format(time.RFC3339Nano), env.NodeID)
	return body, env.RequestID, nil
}
func (t *Transport) SetHTTPClient(c *http.Client) {
	if c != nil {
		t.client = c
	}
}
func (t *Transport) Do(ctx context.Context, nodeID, method, path, capability string, body []byte) (*http.Response, error) {
	var endpoint, secret, previous, state string
	var protocol int
	if err := t.db.QueryRowContext(ctx, `SELECT public_endpoint,outbound_secret,COALESCE(previous_outbound_secret,''),state,protocol_version FROM cluster_members WHERE node_id=?`, nodeID).Scan(&endpoint, &secret, &previous, &state, &protocol); err != nil {
		return nil, err
	}
	if state != core.MemberActive || protocol != core.ProtocolVersion {
		return nil, errors.New("cluster member unavailable or incompatible")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("cluster endpoint must use https")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	target := strings.TrimRight(endpoint, "/") + path
	local, err := t.identity.EnsureIdentity(ctx, "")
	if err != nil {
		return nil, err
	}
	send := func(credential string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		nonce, _ := core.NewSecret(18)
		rid, _ := core.NewID("req_", 12)
		core.WriteEnvelope(req.Header, local.NodeID, credential, method, req.URL.RequestURI(), capability, core.ProtocolVersion, body, t.now().UTC(), nonce, rid)
		req.Header.Set("Authorization", "Bearer "+credential)
		req.Header.Set("Content-Type", "application/json")
		return t.client.Do(req)
	}
	started := t.now()
	resp, err := send(secret)
	// During a rotation overlap the peer still accepts the previous credential
	// until the pending replacement is used and promoted. If the current
	// credential is rejected and an overlap is retained, retry with the
	// previous secret so an expired or unconfirmed rotation never strands the
	// pair.
	if err == nil && previous != "" && previous != secret && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
		resp.Body.Close()
		resp, err = send(previous)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 400 {
			_, _ = t.db.ExecContext(ctx, `UPDATE cluster_members SET last_seen_at=?,last_latency_ms=? WHERE node_id=?`, t.now().UTC().Format(time.RFC3339Nano), t.now().Sub(started).Milliseconds(), nodeID)
		}
		return resp, nil
	}
	if err == nil {
		if resp.StatusCode < 400 && previous != "" {
			// The current credential was accepted, so the peer promoted the
			// pending replacement; the overlap is no longer needed.
			_, _ = t.db.ExecContext(ctx, `UPDATE cluster_members SET previous_outbound_secret=NULL,last_seen_at=?,last_latency_ms=? WHERE node_id=?`, t.now().UTC().Format(time.RFC3339Nano), t.now().Sub(started).Milliseconds(), nodeID)
		} else {
			_, _ = t.db.ExecContext(ctx, `UPDATE cluster_members SET last_seen_at=?,last_latency_ms=? WHERE node_id=?`, t.now().UTC().Format(time.RFC3339Nano), t.now().Sub(started).Milliseconds(), nodeID)
		}
	}
	return resp, err
}

type RemoteReader struct{ Transport *Transport }

func (r RemoteReader) Summary(ctx context.Context, nodeID string) (Summary, error) {
	var v Summary
	err := r.get(ctx, nodeID, "/api/cluster/v1/rpc/summary", "cluster.webfleet.summary", &v)
	return v, err
}
func (r RemoteReader) Comparison(ctx context.Context, nodeID string) (Comparison, error) {
	var v Comparison
	err := r.get(ctx, nodeID, "/api/cluster/v1/rpc/compare", "cluster.webfleet.compare", &v)
	return v, err
}
func (r RemoteReader) get(ctx context.Context, nodeID, path, capability string, out any) error {
	resp, err := r.Transport.Do(ctx, nodeID, http.MethodGet, path, capability, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("remote status %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, core.MaxRequestBytes)).Decode(out)
}
