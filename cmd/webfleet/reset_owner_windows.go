//go:build windows

package main

import "os"

// preserveResetDirOwner is a no-op on platforms without Unix ownership
// semantics; there is no dedicated service user to preserve.
func preserveResetDirOwner(dir string, info os.FileInfo) error {
	return nil
}
