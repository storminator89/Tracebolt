//go:build windows

package lanclientstate

// Windows inspection takes the existing exclusive store lock and verifies the
// exact binding. It does not create, clean, recover or mutate any state.
func InspectExisting(dir, binding string) error { return ValidateExisting(dir, binding) }
