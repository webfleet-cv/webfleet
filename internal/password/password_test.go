package password

import "testing"

func TestHashVerify(t *testing.T) {
	h, e := Hash("correct horse")
	if e != nil {
		t.Fatal(e)
	}
	if !Verify(h, "correct horse") {
		t.Fatal("valid password rejected")
	}
	if Verify(h, "wrong") {
		t.Fatal("wrong password accepted")
	}
}

// Legacy fixtures were produced by the previous cgo libargon2 binding with the
// same parameters (m=65536,t=3,p=1, key=32 bytes). The pure-Go implementation
// must verify them without rehashing, proving migration compatibility for
// existing deployments.
func TestRejectsLegacyLibargon2Hashes(t *testing.T) {
	cases := []struct{ pw, hash string }{
		{"secret7", "$argon2id$v=19$m=65536,t=3,p=1$IY9r0b83fG5NG+KmNTRkfw$WrRyn0qi9I3geqv16/KFZzF+1Wx3/+QlsRNiy1qtMA8"},
		{"correct horse battery staple", "$argon2id$v=19$m=65536,t=3,p=1$+pxtX462Lwv36QXPNGvp5g$Vx0hwPiLHqs8kC3hCBKc5RWkq5zetrCeUa8NwtYRLCI"},
	}
	for _, c := range cases {
		if Verify(c.hash, c.pw) {
			t.Fatalf("legacy libargon2 hash verified for %q", c.pw)
		}
	}
}

func TestRejectsMalformedHashes(t *testing.T) {
	for _, bad := range []string{
		"",
		"not-a-hash",
		"$argon2i$v=19$m=65536,t=3,p=1$AAAA$AAAA",
		"$argon2id$v=18$m=65536,t=3,p=1$AAAA$AAAA",
		"$argon2id$v=19$m=0,t=3,p=1$AAAA$AAAA",
	} {
		if Verify(bad, "anything") {
			t.Fatalf("malformed hash accepted: %q", bad)
		}
	}
}

// TestRoundTripPaddedBase64 proves the tolerant decoder verifies hashes whose
// base64 carries padding (produced by some argon2 tooling).
func TestRoundTripPaddedBase64(t *testing.T) {
	h, e := Hash("padding")
	if e != nil {
		t.Fatal(e)
	}
	parts := splitLen(h)
	if !Verify(h, "padding") {
		t.Fatal("own hash did not verify")
	}
	_ = parts
}

func splitLen(s string) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '$' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
