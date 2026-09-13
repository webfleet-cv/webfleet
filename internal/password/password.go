// Package password exposes Webfleet's local-password boundary while using
// the single canonical Gantry account hash format.
package password

import coreauth "github.com/gantry-tools/gantry-core/auth"

func Hash(value string) (string, error) { return coreauth.HashPassword(value) }

func Verify(encoded, value string) bool { return coreauth.VerifyPassword(encoded, value) }
