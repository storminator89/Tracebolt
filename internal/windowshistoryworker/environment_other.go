//go:build !windows

package windowshistoryworker

// A nonnil empty environment prevents inheritance of ambient credentials.
func workerEnvironment() ([]string, error) { return []string{}, nil }
