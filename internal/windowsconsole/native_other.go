//go:build !windows

package windowsconsole

func openConsole() (console, error) { return nil, failure(CategoryUnsupported) }
