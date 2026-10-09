package setupgate

import "localrmm/internal/windowsservice"

// PrepareControllerEnvironment restores only the drive required by KnownFolder
// expansion in the allowlisted controller environment. The caller must supply
// GetSystemWindowsDirectory, never an ambient environment value. Invalid native
// output or a failed process-local update stops before layout resolution.
func PrepareControllerEnvironment(systemDirectory func() (string, error), setenv func(string, string) error) error {
	if systemDirectory == nil || setenv == nil {
		return ErrGuard
	}
	root, err := systemDirectory()
	if err != nil {
		return ErrGuard
	}
	drive, err := windowsservice.SystemDriveFromWindowsDirectory(root)
	if err != nil {
		return ErrGuard
	}
	if setenv("SystemDrive", drive) != nil {
		return ErrGuard
	}
	return nil
}

// FreshPrerequisites is injected so portable tests exercise the same ordered,
// fail-closed boundary as the native controller, without invoking Windows APIs.
type FreshPrerequisites struct {
	Environment, Layout, Service, ProgramFiles, ProgramData func() error
}

// CheckFreshPrerequisites exposes only finite stages, never callback errors. The
// caller may start fixtures or native actions only after all checks succeed.
func CheckFreshPrerequisites(stage func(string), checks FreshPrerequisites) error {
	if stage == nil {
		return ErrGuard
	}
	for _, step := range []struct {
		stage string
		check func() error
	}{
		{"fresh-environment", checks.Environment},
		{"fresh-layout", checks.Layout},
		{"fresh-service", checks.Service},
		{"fresh-program-files", checks.ProgramFiles},
		{"fresh-program-data", checks.ProgramData},
	} {
		stage(step.stage)
		if step.check == nil || step.check() != nil {
			return ErrGuard
		}
	}
	return nil
}
