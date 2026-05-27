package sync

import "os"

// readFile is a tiny shim so the test file does not need to import os directly.
func readFile(p string) ([]byte, error) { return os.ReadFile(p) }
