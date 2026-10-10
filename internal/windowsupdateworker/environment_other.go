//go:build !windows

package windowsupdateworker

// A non-nil empty environment prevents os/exec from inheriting ambient secrets.
func workerEnvironment() ([]string, error) { return []string{}, nil }
