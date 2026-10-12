package windowspackage

import (
	"context"
	"runtime"
	"strings"
	"sync"

	"localrmm/internal/windowspath"
	"localrmm/internal/windowsservice"
)

const SoftwareExecutorImageName = "tracebolt-windows-software-executor.exe"
const SoftwareExecutorImageVersion = "tracebolt.windows-software-executor-image.v1"

// SoftwareExecutorImageReceipt records the original successful creation, not just
// matching bytes found later. Keep it in the protected setup transaction. A
// missing receipt or incomplete create must never be repaired by adopting an
// existing image. The receipt itself is ownership evidence, not authorization.
type SoftwareExecutorImageReceipt struct {
	Version            string `json:"version"`
	Path               string `json:"path"`
	SHA256             string `json:"sha256"`
	Size               int64  `json:"size"`
	VolumeSerialNumber uint32 `json:"volumeSerialNumber"`
	FileIndexHigh      uint32 `json:"fileIndexHigh"`
	FileIndexLow       uint32 `json:"fileIndexLow"`
}

func (r SoftwareExecutorImageReceipt) Validate() error {
	if r.Version != SoftwareExecutorImageVersion || !windowspath.Canonical(r.Path) || !strings.HasSuffix(r.Path, `\Tracebolt\`+SoftwareExecutorImageName) || !strings.HasPrefix(r.SHA256, "sha256:") || !lowerHex(strings.TrimPrefix(r.SHA256, "sha256:"), 64) || r.Size < 512 || r.Size > MaxPayloadBytes || r.VolumeSerialNumber == 0 && r.FileIndexHigh == 0 && r.FileIndexLow == 0 {
		return failure("image-receipt")
	}
	return nil
}

// SoftwareExecutorImage pins the existing protected KnownFolder parent chain.
// The caller must hold its observer lifecycle lease from receipt loading until
// Close, and the executor-state lock throughout removal. Every operation also
// rechecks the exact owned stopped observer. No method grants authority, changes
// a shared-directory ACL, installs a service, or launches the executor.
//
// Persist intent before Create/Remove and original creation evidence afterward.
// Any failed mutation is uncertain and retained; it is never retried here.
type SoftwareExecutorImage interface {
	CheckAbsent(context.Context) error
	Create(context.Context, []byte, Manifest) (SoftwareExecutorImageReceipt, error)
	Verify(context.Context, SoftwareExecutorImageReceipt) error
	Remove(context.Context, SoftwareExecutorImageReceipt) error
	Close() error
}

type softwareImageBackend interface {
	Path() string
	Check(context.Context) error
	CheckAbsent(context.Context) error
	Create(context.Context, []byte) (SoftwareExecutorImageReceipt, error)
	Read(context.Context, bool) (SoftwareExecutorImageReceipt, error)
	Delete(context.Context, SoftwareExecutorImageReceipt) error
	Close() error
}

type softwareExecutorImage struct {
	mu           sync.Mutex
	backend      softwareImageBackend
	architecture string
	created      bool
	removed      bool
	failed       bool
	closed       bool
	closeErr     error
}

func OpenSoftwareExecutorImage(ctx context.Context, observer windowsservice.Receipt) (SoftwareExecutorImage, error) {
	return openSoftwareExecutorImageWith(ctx, observer, runtime.GOARCH, nativeSoftwareImageBackend)
}

func openSoftwareExecutorImageWith(ctx context.Context, observer windowsservice.Receipt, architecture string, open func(context.Context, windowsservice.Receipt) (softwareImageBackend, error)) (SoftwareExecutorImage, error) {
	if cancelled(ctx) {
		return nil, failure("cancelled")
	}
	b, err := open(ctx, observer)
	if err != nil {
		return nil, err
	}
	if err = b.Check(ctx); err != nil {
		_ = b.Close()
		return nil, err
	}
	return &softwareExecutorImage{backend: b, architecture: architecture}, nil
}

func (s *softwareExecutorImage) checkRead(ctx context.Context) error {
	if cancelled(ctx) {
		return failure("cancelled")
	}
	if s.closed || s.failed {
		return failure("image-session")
	}
	return s.backend.Check(ctx)
}

func (s *softwareExecutorImage) check(ctx context.Context) error {
	if s.removed {
		return failure("image-session")
	}
	return s.checkRead(ctx)
}

func (s *softwareExecutorImage) CheckAbsent(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The coordinator may confirm absence before completing its removal
	// tombstone. Successful removal permits this read, never another mutation.
	if err := s.checkRead(ctx); err != nil {
		return err
	}
	if err := s.backend.CheckAbsent(ctx); err != nil {
		return err
	}
	return s.checkRead(ctx)
}

func (s *softwareExecutorImage) Create(ctx context.Context, payload []byte, manifest Manifest) (result SoftwareExecutorImageReceipt, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cancelled(ctx) {
		return result, failure("cancelled")
	}
	if len(payload) < 512 || len(payload) > MaxPayloadBytes {
		return result, failure("payload-size")
	}
	payload = append([]byte(nil), payload...)
	if err = manifest.Validate(payload); err != nil {
		return result, err
	}
	if manifest.Architecture != s.architecture {
		return result, failure("architecture-mismatch")
	}
	if s.created {
		return result, failure("existing-resource")
	}
	if err = s.check(ctx); err != nil {
		return result, err
	}
	if err = s.backend.CheckAbsent(ctx); err != nil {
		return result, err
	}
	if err = s.check(ctx); err != nil {
		return result, err
	}
	// A failed create consumes this session even if the native outcome is unknown.
	s.failed = true
	r, err := s.backend.Create(ctx, payload)
	if err != nil {
		return result, err
	}
	if err = r.Validate(); err != nil || r.Path != s.backend.Path() || r.SHA256 != "sha256:"+manifest.SHA256 || r.Size != int64(len(payload)) {
		return result, failure("image-receipt")
	}
	if err = s.backend.Check(ctx); err != nil {
		return result, err
	}
	if cancelled(ctx) {
		return result, failure("cancelled")
	}
	s.failed, s.created = false, true
	return r, nil
}

func (s *softwareExecutorImage) verify(ctx context.Context, original SoftwareExecutorImageReceipt, removing bool) error {
	if err := original.Validate(); err != nil {
		return err
	}
	if original.Path != s.backend.Path() {
		return failure("path-binding")
	}
	if err := s.check(ctx); err != nil {
		return err
	}
	observed, err := s.backend.Read(ctx, removing)
	if err != nil {
		return err
	}
	if observed.Validate() != nil || observed != original {
		return failure("image-identity")
	}
	return s.check(ctx)
}

func (s *softwareExecutorImage) Verify(ctx context.Context, original SoftwareExecutorImageReceipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verify(ctx, original, false)
}

func (s *softwareExecutorImage) Remove(ctx context.Context, original SoftwareExecutorImageReceipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.verify(ctx, original, true); err != nil {
		return err
	}
	s.failed = true
	if err := s.backend.Delete(ctx, original); err != nil {
		return err
	}
	if err := s.backend.Check(ctx); err != nil {
		return err
	}
	if err := s.backend.CheckAbsent(ctx); err != nil {
		return err
	}
	if cancelled(ctx) {
		return failure("cancelled")
	}
	s.failed, s.removed = false, true
	return nil
}

func (s *softwareExecutorImage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.closeErr = s.backend.Close()
	}
	return s.closeErr
}
