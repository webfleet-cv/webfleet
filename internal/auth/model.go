package auth

import (
	"errors"
	"strconv"
	"time"

	coreauth "github.com/gantry-tools/gantry-core/auth"
	"github.com/webfleet-cv/webfleet/internal/store"
)

const accountSchemaVersion = 1

var webfleetRoles = coreauth.RolesFile{Version: accountSchemaVersion, Roles: []coreauth.Role{
	{ID: "administrator", Name: "Administrator", Capabilities: []string{"*"}, BuiltIn: true},
	{ID: "user", Name: "User", Capabilities: []string{"organizations.use"}, BuiltIn: true},
	{ID: "viewer", Name: "Viewer", Capabilities: []string{"organizations.read"}, BuiltIn: true},
}}

type accountPersistence struct{ store *store.Store }

func (p accountPersistence) LoadAccounts() (coreauth.AccountsFile, error) {
	result := coreauth.AccountsFile{Version: accountSchemaVersion, Accounts: []coreauth.Account{}}
	rows, err := p.store.DB.Query("SELECT id,email,password_hash,role,created_at FROM users ORDER BY email")
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var email, hash, role, created string
		if err := rows.Scan(&id, &email, &hash, &role, &created); err != nil {
			return result, err
		}
		createdAt, err := time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return result, err
		}
		accountID := strconv.FormatInt(id, 10)
		roleID := role
		if role == "admin" {
			roleID = "administrator"
		}
		identity := coreauth.Identity{ID: "email_" + accountID, Type: "email", Email: email, Enabled: true}
		if hash != "" {
			identity = coreauth.Identity{ID: "pwd_" + accountID, Type: "password", Username: email, Email: email, PasswordHash: hash, Enabled: true}
		}
		result.Accounts = append(result.Accounts, coreauth.Account{
			ID: accountID, DisplayName: email, Enabled: true, Roles: []string{roleID}, Identities: []coreauth.Identity{identity}, CreatedAt: createdAt,
		})
	}
	return result, rows.Err()
}

func (p accountPersistence) LoadRoles() (coreauth.RolesFile, error) { return webfleetRoles, nil }
func (p accountPersistence) SaveAccounts(coreauth.AccountsFile) error {
	return errors.New("Webfleet account mutations use the transactional SQL adapter")
}
func (p accountPersistence) SaveRoles(coreauth.RolesFile) error {
	return errors.New("Webfleet built-in account roles are immutable")
}

func webfleetAccountPolicy() coreauth.AccountPolicy {
	return coreauth.AccountPolicy{SchemaVersion: accountSchemaVersion, ProductName: "Webfleet", KnownCapability: func(key string) bool {
		return key == "organizations.use" || key == "organizations.read"
	}}
}
