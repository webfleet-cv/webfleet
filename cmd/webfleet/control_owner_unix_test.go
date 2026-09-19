//go:build !windows

package main

import (
	"os"
	"syscall"
	"testing"
)

func TestRunResetAllPreservesDataDirOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to chown the data directory")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	useInstalledResetDir(t, dir)
	if code := runReset([]string{"--all", "--confirm", "WEBFLEET ALL"}); code != 0 {
		t.Fatalf("reset --all exit = %d, want 0", code)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("no stat_t")
	}
	if stat.Uid != 4242 || stat.Gid != 4242 {
		t.Fatalf("recreated data dir owner uid=%d gid=%d, want 4242/4242 (service user)", stat.Uid, stat.Gid)
	}
}
