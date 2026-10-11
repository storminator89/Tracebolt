package windowssecurity

import "context"

// Each entry is called only from its separately authenticated fixed child mode.
func CollectNativeDefender(ctx context.Context, r Request) (Snapshot, error) {
	return CollectWithSources(ctx, r, nativeDefender, nil)
}
func CollectNativeFirewall(ctx context.Context, r Request) (Snapshot, error) {
	return CollectWithSources(ctx, r, nil, nativeFirewall)
}
