//go:build !windows

package windowsresourcecontext

import "context"

func nativeProcessors(context.Context) (Processors, error) { return Processors{}, ErrUnsupported }
func nativeInstalledMemory(context.Context) (InstalledMemory, error) {
	return InstalledMemory{}, ErrUnsupported
}
func nativeMemory(context.Context) (Memory, error)       { return Memory{}, ErrUnsupported }
func nativePagefiles(context.Context) (Pagefiles, error) { return Pagefiles{}, ErrUnsupported }
