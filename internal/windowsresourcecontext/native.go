package windowsresourcecontext

import "context"

func CollectNativeProcessors(ctx context.Context, r Request) (Snapshot, error) {
	return CollectWithSources(ctx, r, nativeProcessors, nil, nil, nil)
}
func CollectNativeInstalledMemory(ctx context.Context, r Request) (Snapshot, error) {
	return CollectWithSources(ctx, r, nil, nativeInstalledMemory, nil, nil)
}
func CollectNativeMemory(ctx context.Context, r Request) (Snapshot, error) {
	return CollectWithSources(ctx, r, nil, nil, nativeMemory, nil)
}
func CollectNativePagefiles(ctx context.Context, r Request) (Snapshot, error) {
	return CollectWithSources(ctx, r, nil, nil, nil, nativePagefiles)
}
