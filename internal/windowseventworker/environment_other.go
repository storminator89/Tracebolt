//go:build !windows

package windowseventworker

// A nonnil empty environment prevents inheritance of ambient credentials.
func workerEnvironment() ([]string, error) { return []string{}, nil }
