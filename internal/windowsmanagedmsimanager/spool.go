// Package windowsmanagedmsimanager implements the separately configured central
// MSI manager. Uploaded bytes never enter the enrollment database.
package windowsmanagedmsimanager

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	msi "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowssoftwarejob"
	"path/filepath"
	"sync"
)

var ErrSpool = errors.New("managed_msi_spool_unavailable_preserve_existing_files")

const MaxArtifactBytes int64 = 128 << 20
const ChunkBytes = 32 << 10

// The only spool object is server-named. Partial and complete are the same
// inode, not two files; an interrupted write permanently consumes upload intent.
const artifactName = "artifact.msi"
const spoolName = "windows-managed-msi-spool"

type Spool struct {
	mu          sync.Mutex
	directory   string
	failed      bool
	cache       *artifactCache
	uploadCache *uploadCache
}

func SpoolPath(stateDirectory string) string  { return filepath.Join(stateDirectory, spoolName) }
func CreateSpool(stateDirectory string) error { return createSetupDirectory(SpoolPath(stateDirectory)) }
func OpenSpool(stateDirectory string) (*Spool, error) {
	if !filepath.IsAbs(stateDirectory) || filepath.Clean(stateDirectory) != stateDirectory {
		return nil, ErrSpool
	}
	s := &Spool{directory: SpoolPath(stateDirectory)}
	if err := s.check(); err != nil {
		return nil, err
	}
	return s, nil
}

// Append is a single bounded raw chunk. Its exact pending intent is durable
// before entry. Identical unacknowledged tail bytes may be resumed, never changed.
func (s *Spool) Append(ctx context.Context, a msi.Artifact, data []byte, final func() error) (string, error) {
	if s == nil || ctx == nil || final == nil || !msi.ValidSelection(a.Package) || a.Offset < 0 || a.Offset >= a.Package.Size || !msi.ValidDigest(a.PrefixDigest) || len(data) != int(min(int64(ChunkBytes), a.Package.Size-a.Offset)) || a.PendingDigest == "" || len(data) != a.PendingSize || len(data) == 0 || len(data) > ChunkBytes || msi.Digest(data) != a.PendingDigest || int64(a.PendingIndex)*ChunkBytes != a.Offset {
		return "", ErrSpool
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || s.check() != nil || final() != nil {
		return "", ErrSpool
	}
	prefix, e := s.appendChunk(ctx, a, data, final)
	if e != nil {
		s.failed = true
	}
	return prefix, e
}
func (s *Spool) ReadChunk(ctx context.Context, selection windowssoftwarejob.Selection, index uint32, final func() error) ([]byte, error) {
	if s == nil || ctx == nil || final == nil || !windowssoftwarejob.ValidSelection(selection) || selection.Size > MaxArtifactBytes || uint64(index) >= 4096 || int64(index)*ChunkBytes >= selection.Size {
		return nil, ErrSpool
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return nil, ErrSpool
	}
	if s.check() != nil {
		s.failed = true
		return nil, ErrSpool
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := final(); e != nil {
		return nil, e
	}
	data, e := s.readChunk(ctx, selection, index)
	if e != nil {
		if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
			s.cache = nil
		} else {
			s.failed = true
		}
		return nil, e
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := final(); e != nil {
		return nil, e
	}
	return data, nil
}
func byteDigest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
