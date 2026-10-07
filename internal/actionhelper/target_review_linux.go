//go:build linux

package actionhelper

import (
	"context"
	"encoding/json"
	"path"
	"runtime"
	"time"

	"localrmm/internal/actionpermit"
)

// DiscoverSetupTargetReview performs bounded, read-only local inspection. It
// neither provisions authority nor calls an action/helper endpoint. Its sole
// commands are fixed systemctl list-unit-files and show with a clean environment.
// This source candidate has no native host acceptance claim.
func DiscoverSetupTargetReview(ctx context.Context) (SetupTargetReview, error) {
	if ctx == nil {
		return SetupTargetReview{}, ErrRejected
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return inspectSetupTargetReview(bounded, setupReviewSource{run: runSystemctl, read: readSetupReviewInput, identity: rootIdentity}, runtime.GOARCH)
}

func readSetupReviewInput(name string) (setupReviewFile, error) {
	if !safeInputPath(name) || rootIdentity() != nil {
		return setupReviewFile{}, ErrRejected
	}
	d, err := (authorityFS{root: "/", owner: 0}).openDirectories(path.Dir(name))
	if err != nil {
		return setupReviewFile{}, ErrRejected
	}
	defer d.close()
	f, err := d.readFile(path.Base(name), maxPinnedInputBytes, false)
	if err != nil {
		return setupReviewFile{}, ErrRejected
	}
	defer f.close()
	if !d.unchanged() || !f.unchanged() {
		return setupReviewFile{}, ErrRejected
	}
	metadata := make([][]byte, 0, len(d.dirs)+1)
	for _, ancestor := range d.dirs {
		metadata = append(metadata, authorityMetadata(ancestor.stat))
	}
	metadata = append(metadata, authorityMetadata(f.stat))
	raw, _ := json.Marshal(metadata)
	return setupReviewFile{raw: f.raw, revision: actionpermit.Digest(raw)}, nil
}
