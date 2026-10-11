package windowssessions

import "context"

func CollectNativeSessions(ctx context.Context, r Request) (Snapshot, error) {
	return CollectWithSources(ctx, r, nativeSessions, nil)
}
func CollectNativeJoin(ctx context.Context, r Request) (Snapshot, error) {
	return CollectWithSources(ctx, r, nil, nativeJoin)
}
