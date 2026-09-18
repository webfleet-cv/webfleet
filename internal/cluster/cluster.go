package cluster

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	core "github.com/gantry-tools/gantry-core/cluster"
	"github.com/webfleet-cv/webfleet/internal/database"
)

const ProtocolVersion = core.ProtocolVersion

var DefaultCapabilities = []string{"cluster.health", "cluster.webfleet.summary", "cluster.webfleet.compare", "cluster.propagation", "replication"}

type Service struct {
	db                *database.DB
	now               func() time.Time
	insecurePlaintext bool
}

func New(db *database.DB) *Service { return &Service{db: db, now: time.Now} }

// SetInsecurePlaintext permits HTTP cluster endpoints when the operator has
// explicitly enabled plaintext transport for a trusted private network. It
// affects only transport confidentiality; HMAC authentication, capability
// checks and nonce/replay protection remain enabled.
func (s *Service) SetInsecurePlaintext(v bool) { s.insecurePlaintext = v }

// validateEndpointScheme permits HTTPS always; HTTP only when insecure
// plaintext transport has been explicitly enabled.
func validateEndpointScheme(endpoint string, insecure bool) error {
	if strings.TrimSpace(endpoint) == "" {
		return nil
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return errors.New("invalid cluster endpoint")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if insecure {
			return nil
		}
		return errors.New("cluster endpoint must use https unless insecure plaintext transport is explicitly enabled")
	default:
		return errors.New("cluster endpoint must use https")
	}
}

type Member struct {
	core.Identity
	State             string `json:"state"`
	Health            string `json:"health"`
	Compatible        bool   `json:"compatible"`
	CredentialVersion int    `json:"credential_version"`
	LastLatencyMS     *int64 `json:"last_latency_ms,omitempty"`
}
type PairingBundle struct {
	Identity   core.Identity `json:"identity"`
	Credential string        `json:"credential"`
}
type Summary struct {
	NodeID          string `json:"node_id"`
	Sites           int    `json:"sites"`
	EnabledMonitors int    `json:"enabled_monitors"`
	OpenIncidents   int    `json:"open_incidents"`
	SchedulerClaims int    `json:"scheduler_claims"`
}
type Comparison struct {
	NodeID          string `json:"node_id"`
	Sites           int    `json:"sites"`
	Monitors        int    `json:"monitors"`
	Groups          int    `json:"groups"`
	AlertPolicies   int    `json:"alert_policies"`
	SchedulerClaims int    `json:"scheduler_claims"`
}

func (s *Service) EnsureIdentity(ctx context.Context, productVersion string) (core.Identity, error) {
	var i core.Identity
	var pub, priv []byte
	var caps, created string
	err := s.db.QueryRowContext(ctx, `SELECT node_id,installation_id,display_name,public_endpoint,public_key,private_key,capabilities_json,protocol_version,product_version,created_at FROM cluster_identity WHERE singleton=1`).Scan(&i.NodeID, &i.InstallationID, &i.DisplayName, &i.PublicEndpoint, &pub, &priv, &caps, &i.ProtocolVersion, &i.ProductVersion, &created)
	if err == nil {
		i.PublicKey = base64.RawURLEncoding.EncodeToString(pub)
		_ = json.Unmarshal([]byte(caps), &i.Capabilities)
		i.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		return i, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return core.Identity{}, err
	}
	g, err := core.GenerateIdentity("wf_", "wi_", DefaultCapabilities, ProtocolVersion, productVersion, s.now().UTC())
	if err != nil {
		return core.Identity{}, err
	}
	pub, _ = base64.RawURLEncoding.DecodeString(g.Identity.PublicKey)
	capsB, _ := json.Marshal(g.Identity.Capabilities)
	_, err = s.db.ExecContext(ctx, `INSERT INTO cluster_identity(singleton,node_id,installation_id,public_key,private_key,capabilities_json,protocol_version,product_version,created_at) VALUES(1,?,?,?,?,?,?,?,?) ON CONFLICT(singleton) DO NOTHING`, g.Identity.NodeID, g.Identity.InstallationID, pub, []byte(ed25519.PrivateKey(g.PrivateKey)), string(capsB), ProtocolVersion, productVersion, g.Identity.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return core.Identity{}, err
	}
	// A concurrent first-run call may have created the identity between our read
	// and insert; re-read so both callers converge on the single canonical row
	// instead of the loser surfacing a unique-constraint error.
	var canonical core.Identity
	var cPub, cPriv []byte
	var cCaps, cCreated string
	err = s.db.QueryRowContext(ctx, `SELECT node_id,installation_id,display_name,public_endpoint,public_key,private_key,capabilities_json,protocol_version,product_version,created_at FROM cluster_identity WHERE singleton=1`).Scan(&canonical.NodeID, &canonical.InstallationID, &canonical.DisplayName, &canonical.PublicEndpoint, &cPub, &cPriv, &cCaps, &canonical.ProtocolVersion, &canonical.ProductVersion, &cCreated)
	if err != nil {
		return core.Identity{}, err
	}
	canonical.PublicKey = base64.RawURLEncoding.EncodeToString(cPub)
	_ = json.Unmarshal([]byte(cCaps), &canonical.Capabilities)
	canonical.CreatedAt, _ = time.Parse(time.RFC3339Nano, cCreated)
	return canonical, nil
}
func (s *Service) UpdateIdentity(ctx context.Context, name, endpoint, version string) (core.Identity, error) {
	if err := validateEndpointScheme(endpoint, s.insecurePlaintext); err != nil {
		return core.Identity{}, err
	}
	if _, err := s.EnsureIdentity(ctx, version); err != nil {
		return core.Identity{}, err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE cluster_identity SET display_name=?,public_endpoint=?,product_version=? WHERE singleton=1`, strings.TrimSpace(name), strings.TrimRight(endpoint, "/"), version)
	if err != nil {
		return core.Identity{}, err
	}
	return s.EnsureIdentity(ctx, version)
}
func (s *Service) Invite(ctx context.Context) (core.Invitation, string, error) {
	inv, token, err := core.NewInvitation(s.now().UTC())
	if err != nil {
		return inv, "", err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO cluster_invitations(id,token_hash,state,created_at,expires_at) VALUES(?,?,?,?,?)`, inv.ID, core.SecretDigest(token), inv.State, inv.CreatedAt.Format(time.RFC3339Nano), inv.ExpiresAt.Format(time.RFC3339Nano))
	return inv, token, err
}
func (s *Service) Pair(ctx context.Context, token string, remote core.Identity) (PairingBundle, error) {
	if err := remote.Validate(); err != nil {
		return PairingBundle{}, err
	}
	now := s.now().UTC()
	var id, state, expires string
	var hash []byte
	err := s.db.QueryRowContext(ctx, `SELECT id,token_hash,state,expires_at FROM cluster_invitations WHERE token_hash=?`, core.SecretDigest(token)).Scan(&id, &hash, &state, &expires)
	if err != nil {
		return PairingBundle{}, err
	}
	exp, _ := time.Parse(time.RFC3339Nano, expires)
	if err = core.ValidateInvitation(core.Invitation{ID: id, State: state, ExpiresAt: exp}, now); err != nil {
		return PairingBundle{}, err
	}
	if err = core.Compatible(ProtocolVersion, remote.ProtocolVersion, DefaultCapabilities, remote.Capabilities, ""); err != nil {
		return PairingBundle{}, err
	}
	outbound, _ := core.NewSecret(core.MinimumCredentialBytes)
	inbound, _ := core.NewSecret(core.MinimumCredentialBytes)
	pub, _ := base64.RawURLEncoding.DecodeString(remote.PublicKey)
	caps, _ := json.Marshal(core.NormalizeCapabilities(remote.Capabilities))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PairingBundle{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO cluster_members(node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,state,outbound_secret,inbound_secret_hash,created_at,paired_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, remote.NodeID, remote.InstallationID, remote.DisplayName, remote.PublicEndpoint, pub, string(caps), remote.ProtocolVersion, remote.ProductVersion, core.MemberActive, outbound, core.SecretDigest(inbound), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return PairingBundle{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE cluster_invitations SET state=?,used_at=? WHERE id=? AND state=?`, core.PairingUsed, now.Format(time.RFC3339Nano), id, core.PairingPending); err != nil {
		return PairingBundle{}, err
	}
	if err = tx.Commit(); err != nil {
		return PairingBundle{}, err
	}
	local, err := s.EnsureIdentity(ctx, "")
	if err != nil {
		return PairingBundle{}, err
	}
	return PairingBundle{Identity: local, Credential: inbound}, nil
}
func (s *Service) AddMember(ctx context.Context, remote core.Identity, outbound, inbound string) error {
	if err := core.Compatible(ProtocolVersion, remote.ProtocolVersion, DefaultCapabilities, remote.Capabilities, ""); err != nil {
		return err
	}
	now := s.now().UTC()
	pub, _ := base64.RawURLEncoding.DecodeString(remote.PublicKey)
	caps, _ := json.Marshal(core.NormalizeCapabilities(remote.Capabilities))
	_, err := s.db.ExecContext(ctx, `INSERT INTO cluster_members(node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,state,outbound_secret,inbound_secret_hash,created_at,paired_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, remote.NodeID, remote.InstallationID, remote.DisplayName, remote.PublicEndpoint, pub, string(caps), remote.ProtocolVersion, remote.ProductVersion, core.MemberActive, outbound, core.SecretDigest(inbound), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	return err
}
func (s *Service) Members(ctx context.Context) ([]Member, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id,installation_id,display_name,public_endpoint,public_key,capabilities_json,protocol_version,product_version,state,created_at,paired_at,last_seen_at,last_latency_ms,credential_version FROM cluster_members ORDER BY node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Member{}
	now := s.now().UTC()
	for rows.Next() {
		var m Member
		var pub []byte
		var caps, created, paired string
		var seen sql.NullString
		var latency sql.NullInt64
		if err = rows.Scan(&m.NodeID, &m.InstallationID, &m.DisplayName, &m.PublicEndpoint, &pub, &caps, &m.ProtocolVersion, &m.ProductVersion, &m.State, &created, &paired, &seen, &latency, &m.CredentialVersion); err != nil {
			return nil, err
		}
		m.PublicKey = base64.RawURLEncoding.EncodeToString(pub)
		_ = json.Unmarshal([]byte(caps), &m.Capabilities)
		m.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		if seen.Valid {
			t, _ := time.Parse(time.RFC3339Nano, seen.String)
			m.LastSeenAt = &t
		}
		if latency.Valid {
			v := latency.Int64
			m.LastLatencyMS = &v
		}
		m.Compatible = core.Compatible(ProtocolVersion, m.ProtocolVersion, DefaultCapabilities, m.Capabilities, "") == nil
		m.Health = health(m, now)
		out = append(out, m)
	}
	return out, rows.Err()
}
func health(m Member, now time.Time) string {
	if m.State == core.MemberDisabled {
		return core.HealthDisabled
	}
	if m.State == core.MemberRevoked {
		return core.HealthRevoked
	}
	if !m.Compatible {
		return core.HealthDegraded
	}
	if m.LastSeenAt == nil || now.Sub(*m.LastSeenAt) > 10*time.Minute {
		return core.HealthOffline
	}
	if now.Sub(*m.LastSeenAt) > 2*time.Minute {
		return core.HealthDegraded
	}
	return core.HealthOnline
}
func (s *Service) SetEnabled(ctx context.Context, id string, enabled bool) error {
	state := core.MemberDisabled
	if enabled {
		state = core.MemberActive
	}
	r, err := s.db.ExecContext(ctx, `UPDATE cluster_members SET state=? WHERE node_id=? AND state!=?`, state, id, core.MemberRevoked)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return errors.New("cluster member unavailable")
	}
	return nil
}

// EligibleVoter reports whether the target Gantry member may be admitted to Raft
// voter membership as an active, paired, replication-capable, protocol- and
// capability-compatible peer. This is the operator preflight that prevents the
// unpaired-voter availability foot-gun (an unknown voter being committed into the
// Raft configuration and then failing the Core capability gate, which would make
// the cluster read-only).
func (s *Service) EligibleVoter(ctx context.Context, nodeID string) error {
	var state, caps string
	var protocol int
	e := s.db.QueryRowContext(ctx, `SELECT state,capabilities_json,protocol_version FROM cluster_members WHERE node_id=?`, nodeID).Scan(&state, &caps, &protocol)
	if errors.Is(e, sql.ErrNoRows) {
		return fmt.Errorf("member %q is not paired; pair/authenticate the node before joining it as a voter", nodeID)
	}
	if e != nil {
		return e
	}
	if state != core.MemberActive {
		return fmt.Errorf("member %q is not active (state=%s); enable/repair the peer before joining it", nodeID, state)
	}
	var advertised []string
	_ = json.Unmarshal([]byte(caps), &advertised)
	if e := core.Compatible(ProtocolVersion, protocol, DefaultCapabilities, advertised, ""); e != nil {
		return fmt.Errorf("member %q is not a compatible replication peer: %w", nodeID, e)
	}
	return nil
}

func (s *Service) Revoke(ctx context.Context, id string) error {
	r, err := s.db.ExecContext(ctx, `UPDATE cluster_members SET state=?,revoked_at=? WHERE node_id=? AND state!=?`, core.MemberRevoked, s.now().UTC().Format(time.RFC3339Nano), id, core.MemberRevoked)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return errors.New("cluster member unavailable")
	}
	return nil
}
func (s *Service) Remove(ctx context.Context, id string) error {
	r, err := s.db.ExecContext(ctx, `DELETE FROM cluster_members WHERE node_id=? AND state=?`, id, core.MemberRevoked)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return errors.New("revoke member before removal")
	}
	return nil
}
func (s *Service) Rotate(ctx context.Context, id string, transport *Transport) (string, error) {
	sec, err := core.NewSecret(core.MinimumCredentialBytes)
	if err != nil {
		return "", err
	}
	// The peer must accept the new A->B secret or the pair breaks: rotate the
	// peer's inbound credential to a pending replacement first (authenticated
	// with the current secret), then switch our outbound secret. The peer
	// promotes the pending credential on first use; the old credential remains
	// valid during the overlap.
	if transport == nil {
		return "", errors.New("cluster transport required for rotation")
	}
	var current string
	if err = s.db.QueryRowContext(ctx, `SELECT outbound_secret FROM cluster_members WHERE node_id=?`, id).Scan(&current); err != nil {
		return "", errors.New("cluster member unavailable")
	}
	hash := core.SecretDigest(sec)
	body, _ := json.Marshal(map[string]string{"secret_hash": base64.RawURLEncoding.EncodeToString(hash), "expires_at": s.now().UTC().Add(15 * time.Minute).Format(time.RFC3339Nano)})
	resp, err := transport.Do(ctx, id, http.MethodPost, "/api/cluster/v1/rpc/rotate-inbound", "cluster.health", body)
	if err != nil {
		return "", fmt.Errorf("peer did not accept the rotation: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("peer rejected the inbound rotation (%d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	// Retain the previous outbound secret as an overlap so the pair keeps
	// working with the old credential if the pending window expires before the
	// new one is confirmed; the transport drops the overlap once the peer
	// accepts the new credential.
	r, err := s.db.ExecContext(ctx, `UPDATE cluster_members SET outbound_secret=?,previous_outbound_secret=? WHERE node_id=? AND state=?`, sec, current, id, core.MemberActive)
	if err != nil {
		return "", err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return "", errors.New("cluster member unavailable")
	}
	return sec, nil
}

// RotateInbound installs a pending inbound credential for a member. It is
// invoked by the peer through the cluster RPC during rotation: the caller has
// already switched its outbound secret, and this node accepts requests signed
// with either the current or the pending credential until the pending one is
// used and promoted.
func (s *Service) RotateInbound(ctx context.Context, nodeID string, hash []byte, expiresAt time.Time) error {
	r, err := s.db.ExecContext(ctx, `UPDATE cluster_members SET pending_inbound_secret_hash=?,pending_inbound_expires_at=? WHERE node_id=? AND state=?`, hash, expiresAt.UTC().Format(time.RFC3339Nano), nodeID, core.MemberActive)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return errors.New("cluster member unavailable")
	}
	return nil
}
func (s *Service) LocalSummary(ctx context.Context) (Summary, error) {
	i, err := s.EnsureIdentity(ctx, "")
	if err != nil {
		return Summary{}, err
	}
	v := Summary{NodeID: i.NodeID}
	qs := []struct {
		p *int
		q string
	}{{&v.Sites, `SELECT COUNT(*) FROM sites WHERE archived_at IS NULL`}, {&v.EnabledMonitors, `SELECT COUNT(*) FROM monitors m JOIN sites s ON s.id=m.site_id WHERE s.enabled=1 AND s.archived_at IS NULL`}, {&v.OpenIncidents, `SELECT COUNT(*) FROM incidents WHERE state!='closed'`}, {&v.SchedulerClaims, `SELECT COUNT(*) FROM scheduler_claims`}}
	for _, x := range qs {
		if err = s.db.QueryRowContext(ctx, x.q).Scan(x.p); err != nil {
			return Summary{}, err
		}
	}
	return v, nil
}
func (s *Service) LocalComparison(ctx context.Context) (Comparison, error) {
	i, err := s.EnsureIdentity(ctx, "")
	if err != nil {
		return Comparison{}, err
	}
	v := Comparison{NodeID: i.NodeID}
	qs := []struct {
		p *int
		q string
	}{{&v.Sites, `SELECT COUNT(*) FROM sites`}, {&v.Monitors, `SELECT COUNT(*) FROM monitors`}, {&v.Groups, `SELECT COUNT(*) FROM groups`}, {&v.AlertPolicies, `SELECT COUNT(*) FROM alert_policies`}, {&v.SchedulerClaims, `SELECT COUNT(*) FROM scheduler_claims`}}
	for _, x := range qs {
		if err = s.db.QueryRowContext(ctx, x.q).Scan(x.p); err != nil {
			return Comparison{}, err
		}
	}
	return v, nil
}
func Aggregate[T any](ctx context.Context, localID string, local T, members []Member, target string, read func(context.Context, string) (T, error)) (core.Report[T], error) {
	parsed, err := core.ParseTarget(target)
	if err != nil {
		return core.Report[T]{}, err
	}
	req, _ := core.NewID("fan_", 10)
	results := []core.NodeResult[T]{}
	if parsed.Kind != core.TargetMembers && (parsed.Kind != core.TargetNode || parsed.NodeID == localID) {
		v := local
		results = append(results, core.NodeResult[T]{NodeID: localID, OwnerNode: localID, OK: true, Value: &v})
	}
	ids := []string{}
	for _, m := range members {
		if m.State != core.MemberActive || parsed.Kind == core.TargetLocal {
			continue
		}
		if parsed.Kind == core.TargetNode && m.NodeID != parsed.NodeID {
			continue
		}
		ids = append(ids, m.NodeID)
	}
	results = append(results, core.FanOut(ctx, ids, 4, read)...)
	sort.Slice(results, func(i, j int) bool { return results[i].NodeID < results[j].NodeID })
	return core.Report[T]{RequestID: req, Partial: core.IsPartial(results), Results: results}, nil
}
