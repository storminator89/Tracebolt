//go:build windows

package windowspackage

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"localrmm/internal/windowspath"
)

// CheckManagedMSIExclusive rejects every co-enabled Tracebolt mutation domain.
// The inverse setup guard uses the same stopped-observer lifecycle lease. This
// is a bounded setup exclusion, not a mutex against external administrators.
func CheckManagedMSIExclusive(ctx context.Context) error {
	if e := checkBackgroundUpdateServiceAbsent(ctx); e != nil {
		return e
	}
	p, e := openManagedMSIParents(ctx)
	if e != nil {
		return e
	}
	defer p.Close()
	for _, name := range []string{"windows-update-service", "windows-agent-background-update-job-relay", "windows-update-executor", "windows-software-executor", "windows-agent-update-job-relay", "windows-agent-software-job-relay", "windows-agent-action-relay", "windows-mutation-fence"} {
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
	if e := checkBackgroundUpdateServiceAbsent(ctx); e != nil {
		return e
	}
	p, e := openManagedMSIParents(ctx)
	if e != nil {
		return e
	}
	defer p.Close()
	for _, name := range []string{"windows-update-service", "windows-agent-background-update-job-relay", "windows-managed-msi-service", "windows-managed-msi-package", "windows-agent-managed-msi-relay", "windows-mutation-fence"} {
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

// CheckCoordinatedMutationExclusive rejects all nonparticipants. The caller must
// separately verify its exact active immutable MSI/WUA roster; this is no grant.
func CheckCoordinatedMutationExclusive(ctx context.Context) error {
	if e := checkBackgroundUpdateServiceAbsent(ctx); e != nil {
		return e
	}
	return checkMutationExclusive(ctx, false)
}
func CheckBackgroundMutationExclusive(ctx context.Context) error {
	return checkMutationExclusive(ctx, true)
}
func checkMutationExclusive(ctx context.Context, background bool) error {
	p, e := openManagedMSIParents(ctx)
	if e != nil {
		return e
	}
	defer p.Close()
	names := []string{"windows-software-executor", "windows-agent-software-job-relay", "windows-agent-action-relay"}
	if background {
		names = append(names, "windows-update-executor", "windows-agent-update-job-relay")
	} else {
		names = append(names, "windows-update-service", "windows-agent-background-update-job-relay")
	}
	for _, name := range names {
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

// CheckManagedMSIParticipantAbsent is used only after the fresh coordinator has
// verified its staged shared roster. It never adopts an existing MSI participant.
func CheckManagedMSIParticipantAbsent(ctx context.Context) error {
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

func CheckBackgroundUpdateFresh(ctx context.Context) error {
	if e := CheckManagedMSIAbsent(ctx); e != nil {
		return e
	}
	return CheckBackgroundMutationExclusive(ctx)
}
func checkBackgroundUpdateServiceAbsent(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return failure("cancelled")
	}
	h, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return e
	}
	defer windows.CloseServiceHandle(h)
	s, e := windows.OpenService(h, windows.StringToUTF16Ptr("TraceboltWindowsCachedUpdate"), windows.SERVICE_QUERY_STATUS)
	if e == nil {
		windows.CloseServiceHandle(s)
		return failure("coenabled-mutator")
	}
	if !errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return failure("absence-unverified")
	}
	return ctx.Err()
}
