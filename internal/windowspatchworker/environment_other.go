//go:build !windows

package windowspatchworker

// A non-nil empty environment prevents os/exec from inheriting ambient secrets.
func workerEnvironment() ([]string, error) { return []string{}, nil }
