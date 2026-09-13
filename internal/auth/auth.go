package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	coreauth "github.com/gantry-tools/gantry-core/auth"
	"github.com/webfleet-cv/webfleet/internal/password"
	"github.com/webfleet-cv/webfleet/internal/sqlite"
	"github.com/webfleet-cv/webfleet/internal/store"
)

const MinPasswordLength = 7

type Session struct {
	UserID      int64
	Email, CSRF string
	Expires     time.Time
}
type Service struct {
	store    *store.Store
	accounts *coreauth.Model
}

var ErrInvalidCurrentPassword = errors.New("current password is incorrect")

func New(s *store.Store) *Service {
	accounts, err := coreauth.NewModel(accountPersistence{store: s}, webfleetAccountPolicy())
	if err != nil {
		panic(err)
	}
	return &Service{store: s, accounts: accounts}
}
func (a *Service) NeedsSetup() (bool, error) {
	if err := a.accounts.Reload(); err != nil {
		return false, err
	}
	return a.accounts.Empty(), nil
}
func (a *Service) CreateAdmin(email, pw string) error {
	email = strings.TrimSpace(strings.ToLower(email))
	if !strings.Contains(email, "@") || len(pw) < MinPasswordLength {
		return errors.New("valid email and password of at least 7 characters required")
	}
	need, e := a.NeedsSetup()
	if e != nil {
		return e
	}
	if !need {
		return errors.New("setup already completed")
	}
	h, e := password.Hash(pw)
	if e != nil {
		return e
	}
	ctx := context.Background()
	org, e := a.store.PrimaryOrgID(ctx)
	if e != nil {
		return e
	}
	tx, e := a.store.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	// PostgreSQL serializes first-run setup through an advisory lock so two
	// concurrent first-admin requests cannot both pass the NOT EXISTS guard.
	// SQLite's single owned connection already serializes writers.
	if a.store.Dialect() == "postgres" {
		if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(761234567)`); e != nil {
			return e
		}
	}
	res, e := tx.ExecContext(ctx, `INSERT INTO users(email,password_hash,role,created_at) SELECT ?,?,'admin',? WHERE NOT EXISTS(SELECT 1 FROM users)`, email, h, store.Now())
	if e != nil {
		return e
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("setup already completed")
	}
	var uid int64
	if e = tx.QueryRow(`SELECT id FROM users WHERE lower(email)=?`, email).Scan(&uid); e != nil {
		return e
	}
	// The first administrator owns the deployment organization; the user and
	// its owner membership must be created atomically so RBAC never sees an
	// administrator without a membership.
	if _, e = tx.ExecContext(ctx, `INSERT INTO organization_memberships(organization_id,user_id,role,created_at) VALUES(?,?,'owner',?)`, org, uid, store.Now()); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	if e = a.accounts.Reload(); e != nil {
		return e
	}
	return a.audit("first_admin_created", email)
}
func (a *Service) Login(email, pw string) (string, Session, error) {
	if err := a.accounts.Reload(); err != nil {
		return "", Session{}, err
	}
	account, _, valid := a.accounts.AuthenticatePassword(email, pw)
	if !valid {
		return "", Session{}, errors.New("invalid credentials")
	}
	userID, e := strconv.ParseInt(account.ID, 10, 64)
	if e != nil {
		return "", Session{}, e
	}
	raw := token(32)
	csrf := token(24)
	sum := sha256.Sum256([]byte(raw))
	exp := time.Now().UTC().Add(24 * time.Hour)
	if e = sqlite.Exec(a.store.DB, `INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,created_at) VALUES(?,?,?,?,?)`, sum[:], userID, csrf, exp.Format(time.RFC3339Nano), store.Now()); e != nil {
		return "", Session{}, e
	}
	_ = a.audit("login", account.DisplayName)
	return raw, Session{UserID: userID, Email: account.DisplayName, CSRF: csrf, Expires: exp}, nil
}
func (a *Service) CreateSessionForUser(userID int64, email string) (string, Session, error) {
	if err := a.accounts.Reload(); err != nil {
		return "", Session{}, err
	}
	raw := token(32)
	csrf := token(24)
	sum := sha256.Sum256([]byte(raw))
	exp := time.Now().UTC().Add(24 * time.Hour)
	if e := sqlite.Exec(a.store.DB, `INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,created_at) VALUES(?,?,?,?,?)`, sum[:], userID, csrf, exp.Format(time.RFC3339Nano), store.Now()); e != nil {
		return "", Session{}, e
	}
	_ = a.audit("oidc_login", email)
	return raw, Session{UserID: userID, Email: email, CSRF: csrf, Expires: exp}, nil
}
func (a *Service) Session(raw string) (Session, error) {
	if raw == "" {
		return Session{}, errors.New("no session")
	}
	sum := sha256.Sum256([]byte(raw))
	r, e := sqlite.Query(a.store.DB, `SELECT s.user_id,s.csrf_token,s.expires_at,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? LIMIT 1`, sum[:])
	if e != nil || len(r) == 0 {
		return Session{}, errors.New("invalid session")
	}
	exp, e := time.Parse(time.RFC3339Nano, r[0]["expires_at"].Text)
	if e != nil || time.Now().After(exp) {
		_ = sqlite.Exec(a.store.DB, `DELETE FROM sessions WHERE token_hash=?`, sum[:])
		return Session{}, errors.New("expired session")
	}
	return Session{UserID: r[0]["user_id"].Int64, Email: r[0]["email"].Text, CSRF: r[0]["csrf_token"].Text, Expires: exp}, nil
}
func (a *Service) Logout(raw string) {
	sum := sha256.Sum256([]byte(raw))
	_ = sqlite.Exec(a.store.DB, `DELETE FROM sessions WHERE token_hash=?`, sum[:])
	_ = a.audit("logout", "")
}

// ChangePassword verifies the caller's current password, updates the stored
// hash atomically and revokes every other browser session for that user. The
// session making the change remains valid so the response can complete and
// the user is not unexpectedly signed out of the current browser.
func (a *Service) ChangePassword(ctx context.Context, userID int64, currentPassword, newPassword, keepToken string) error {
	if len(newPassword) < MinPasswordLength {
		return errors.New("password must be at least 7 characters")
	}
	var currentHash string
	if err := a.store.DB.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id=?`, userID).Scan(&currentHash); err != nil || !password.Verify(currentHash, currentPassword) {
		return ErrInvalidCurrentPassword
	}
	nextHash, err := password.Hash(newPassword)
	if err != nil {
		return err
	}
	keepHash := sha256.Sum256([]byte(keepToken))
	tx, err := a.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE users SET password_hash=? WHERE id=?`, nextHash, userID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=? AND token_hash<>?`, userID, keepHash[:]); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(kind,detail,created_at) VALUES(?,?,?)`, "password_changed", "self-service password change", store.Now()); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return a.accounts.Reload()
}
func (a *Service) audit(kind, detail string) error {
	return sqlite.Exec(a.store.DB, `INSERT INTO audit_events(kind,detail,created_at) VALUES(?,?,?)`, kind, detail, store.Now())
}
func token(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

var _ = sqlite.Row{}
