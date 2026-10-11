//go:build !windows

package windowssecuritycoverageworker

// A non-nil empty environment prevents os/exec from inheriting ambient secrets.
func workerEnvironment() ([]string, error) { return []string{}, nil }
