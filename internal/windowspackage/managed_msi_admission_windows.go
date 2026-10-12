//go:build windows

package windowspackage

import (
	"context"
	"golang.org/x/sys/windows"
	"localrmm/internal/windowspath"
)

// CheckManagedMSIExclusive rejects every co-enabled Tracebolt mutation domain.
// The inverse setup guard uses the same stopped-observer lifecycle lease. This
// is a bounded setup exclusion, not a mutex against external administrators.
func CheckManagedMSIExclusive(ctx context.Context) error {
	p, e := openManagedMSIParents(ctx)
	if e != nil {
		return e
	}
	defer p.Close()
	for _, name := range []string{"windows-update-executor", "windows-software-executor", "windows-agent-update-job-relay", "windows-agent-software-job-relay", "windows-agent-action-relay"} {
		if e = absentManagedChild(p.parent.handle, name); e != nil {
			return e
		}
	}
	root := p.state.directories[p.state.layout.ProgramData]
	if root == nil {
		return failure("path-binding")
	}
	if e = absentManagedChild(root.handle, "Tracebolt-action-broker"); e != nil {
		return e
	}
	return p.state.checkBindings(ctx)
}
func CheckManagedMSIAbsent(ctx context.Context) error {
	p, e := openManagedMSIParents(ctx)
	if e != nil {
		return e
	}
	defer p.Close()
	for _, name := range []string{"windows-managed-msi-service", "windows-managed-msi-package", "windows-agent-managed-msi-relay"} {
		if e = absentManagedChild(p.parent.handle, name); e != nil {
			return e
		}
	}
	return p.state.checkBindings(ctx)
}
func absentManagedChild(parent windows.Handle, name string) error {
	h, e := windowspath.OpenChild(parent, name, true, windowspath.DirectoryAccess, windowspath.DirectoryShare)
	if e == nil {
		windows.CloseHandle(h)
		return failure("coenabled-mutator")
	}
	if !missingDirectChild(e) {
		return failure("absence-unverified")
	}
	return nil
}
