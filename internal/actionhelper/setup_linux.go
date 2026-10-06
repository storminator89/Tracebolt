//go:build linux

package actionhelper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path"
)

func beginSetupInitialization(ctx context.Context, p Policy, key ed25519.PublicKey) error {
	if rootIdentity() != nil {
		return ErrRejected
	}
	a, err := loadAuthority()
	if err != nil || !bytes.Equal(a.PublicKey, key) {
		return ErrRejected
	}
	want, _ := json.Marshal(p)
	actual, _ := json.Marshal(a.Policy)
	if !bytes.Equal(want, actual) {
		return ErrRejected
	}
	return beginSetupInitializationFrom(ctx, authorityFS{root: "/", owner: 0}, p, key)
}

func beginSetupInitializationFrom(ctx context.Context, fs authorityFS, p Policy, key ed25519.PublicKey) error {
	if ctx == nil || ctx.Err() != nil || path.Dir(SetupIntentPath) != path.Dir(SetupStartedPath) {
		return ErrRejected
	}
	d, err := fs.openDirectories(path.Dir(SetupIntentPath))
	if err != nil {
		return ErrRejected
	}
	defer d.close()
	// This existing installer directory must retain its private root-only mode.
	if d.dirs[len(d.dirs)-1].stat.Mode&07777 != 0700 {
		return ErrRejected
	}
	f, err := d.readFile(path.Base(SetupIntentPath), 4096, true)
	if err != nil {
		return ErrRejected
	}
	defer f.close()
	intent, err := decodeSetupIntent(f.raw, p, key)
	if err != nil || !d.unchanged() || !f.unchanged() || ctx.Err() != nil {
		return ErrRejected
	}
	// Any completion evidence blocks a new initialization, even if an independent
	// loss removed both the used ledger and its started fence. Do not adopt or fix
	// malformed receipts. Complete backup rollback remains outside this contract.
	var complete unix.Stat_t
	if err := unix.Fstatat(d.fd(), path.Base(SetupCompletePath), &complete, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return ErrRejected
	}
	intent.Version = SetupStartedVersion
	raw, _ := json.Marshal(intent)
	fd, err := unix.Openat(d.fd(), path.Base(SetupStartedPath), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrRejected
	}
	started := os.NewFile(uintptr(fd), "action-ledger-started-fence")
	defer started.Close()
	// Never unlink a partial fence. A failed write/sync intentionally blocks a
	// future attempt even if no ledger file was created.
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !safeAuthorityFile(before, fs.owner, 4096, false) || before.Mode&07777 != 0600 || before.Size != 0 {
		return ErrRejected
	}
	if n, err := started.Write(raw); err != nil || n != len(raw) || unix.Fsync(fd) != nil || unix.Fsync(d.fd()) != nil {
		return ErrRejected
	}
	if unix.Fstat(fd, &after) != nil || unix.Fstatat(d.fd(), path.Base(SetupStartedPath), &named, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!sameAuthorityObject(after, named) || before.Dev != after.Dev || before.Ino != after.Ino || !safeAuthorityFile(after, fs.owner, 4096, true) || after.Size != int64(len(raw)) || !f.unchanged() || ctx.Err() != nil {
		return ErrRejected
	}
	// Creating our own entry changes the final directory metadata. Verify its
	// identity and permissions plus every ancestor rather than the old mtime.
	current, err := fs.openDirectories(path.Dir(SetupStartedPath))
	if err != nil {
		return ErrRejected
	}
	defer current.close()
	if len(current.dirs) != len(d.dirs) {
		return ErrRejected
	}
	for i, held := range d.dirs {
		var st unix.Stat_t
		if unix.Fstat(held.fd, &st) != nil || st.Dev != current.dirs[i].stat.Dev || st.Ino != current.dirs[i].stat.Ino || held.stat.Dev != st.Dev || held.stat.Ino != st.Ino || !safeAuthorityDirectory(st, fs.owner) {
			return ErrRejected
		}
		if i == len(d.dirs)-1 && st.Mode&07777 != 0700 {
			return ErrRejected
		}
	}
	return nil
}

// CheckSetupTargetFile accepts only one explicitly supplied root-protected
// canonical review record. It never reads a request-selected execution command.
func CheckSetupTargetFile(ctx context.Context, reviewPath string) (SetupTargetResult, error) {
	if rootIdentity() != nil {
		return SetupTargetResult{}, ErrRejected
	}
	return checkSetupTargetFileFrom(ctx, authorityFS{root: "/", owner: 0}, reviewPath, CheckSetupTarget)
}

func checkSetupTargetFileFrom(ctx context.Context, fs authorityFS, reviewPath string, check func(context.Context, Target) (SetupTargetResult, error)) (SetupTargetResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return SetupTargetResult{}, ErrRejected
	}
	if _, err := authorityPathParts(reviewPath); err != nil {
		return SetupTargetResult{}, ErrRejected
	}
	d, err := fs.openDirectories(path.Dir(reviewPath))
	if err != nil {
		return SetupTargetResult{}, ErrRejected
	}
	defer d.close()
	f, err := d.readFile(path.Base(reviewPath), MaxPolicyBytes, true)
	if err != nil {
		return SetupTargetResult{}, ErrRejected
	}
	defer f.close()
	var target Target
	if json.Unmarshal(f.raw, &target) != nil {
		return SetupTargetResult{}, ErrRejected
	}
	canonical, _ := json.Marshal(target)
	if !bytes.Equal(f.raw, canonical) {
		return SetupTargetResult{}, ErrRejected
	}
	if _, err := targetDigest(target); err != nil || !d.unchanged() || !f.unchanged() {
		return SetupTargetResult{}, ErrRejected
	}
	result, err := check(ctx, target)
	if err != nil || !d.unchanged() || !f.unchanged() || ctx.Err() != nil {
		return SetupTargetResult{}, ErrRejected
	}
	return result, nil
}
