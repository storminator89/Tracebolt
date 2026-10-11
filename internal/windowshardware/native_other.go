//go:build !windows

package windowshardware

import "context"

func nativeSystem(context.Context) (System, error)     { return System{}, ErrUnsupported }
func nativeFirmware(context.Context) (Firmware, error) { return Firmware{}, ErrUnsupported }
func nativePower(context.Context) (Power, error)       { return Power{}, ErrUnsupported }

func nativeChassis(context.Context) (Chassis, error) { return Chassis{}, ErrUnsupported }
