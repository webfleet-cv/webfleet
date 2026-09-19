//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// preserveResetDirOwner restores the owner (uid/gid) of the original data
// directory onto a freshly recreated one, so the dedicated service user can
// still write after reset --all.
func preserveResetDirOwner(dir string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read data directory ownership")
	}
	return os.Chown(dir, int(stat.Uid), int(stat.Gid))
}
