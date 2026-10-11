//go:build !windows

package windowspatchcontext

import "context"

func NativeMachine(context.Context) (OS, Reboot) {
	v := Value{Quality: "unavailable"}
	return OS{v, v, v, v}, Reboot{"unavailable", "unavailable", "unavailable"}
}
