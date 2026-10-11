package windowshardware

import "context"

func CollectNativeSystem(ctx context.Context, r Request) (Snapshot, error) {
	return CollectWithSources(ctx, r, nativeSystem, nil, nil, nil)
}
func CollectNativeFirmware(ctx context.Context, r Request) (Snapshot, error) {
	return CollectWithSources(ctx, r, nil, nativeFirmware, nil, nil)
}
func CollectNativePower(ctx context.Context, r Request) (Snapshot, error) {
	return CollectWithSources(ctx, r, nil, nil, nativePower, nil)
}

func CollectNativeChassis(ctx context.Context, r Request) (Snapshot, error) {
	return CollectWithSources(ctx, r, nil, nil, nil, nativeChassis)
}
