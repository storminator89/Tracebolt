package windowssecuritycoverage

import "context"

// Each entry is called only from its separately authenticated fixed child mode.
func CollectNativeAntivirus(ctx context.Context, r Request) (Snapshot, error) {
	return CollectWithSources(ctx, r, nativeAntivirus, nil)
}
func CollectNativeTPM(ctx context.Context, r Request) (Snapshot, error) {
	return CollectWithSources(ctx, r, nil, nativeTPM)
}
