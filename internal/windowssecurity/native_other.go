//go:build !windows

package windowssecurity

import "context"

func nativeDefender(context.Context) (Defender, error) { return Defender{}, ErrUnsupported }
func nativeFirewall(context.Context) (Firewall, error) { return Firewall{}, ErrUnsupported }
