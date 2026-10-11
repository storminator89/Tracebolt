//go:build !windows

package windowsstorageioworker

// A non-nil empty environment prevents os/exec from inheriting ambient secrets.
func workerEnvironment() ([]string, error) { return []string{}, nil }
