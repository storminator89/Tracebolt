package windowspackage

import (
	"bytes"
	"context"
	"sync"

	"localrmm/internal/actionpermit"
	"localrmm/internal/windowsservice"
	job "localrmm/internal/windowssoftwarejob"
)

const PreparedMSIVersion = "tracebolt.windows-prepared-msi-custody.v1"
const preparedMSIDirectory = "windows-software-package"
const preparedMSIName = "prepared.msi"

// PreparedMSIReceipt proves an original successful create, including NTFS object
// identity. Matching bytes later found at a path are never adopted. The setup
// coordinator durably retains this receipt beside the exact package consent.
type PreparedMSIReceipt struct {
	Version                     string        `json:"version"`
	Package                     job.Selection `json:"package"`
	VolumeSerialNumber          uint32        `json:"volumeSerialNumber"`
	FileIndexHigh               uint32        `json:"fileIndexHigh"`
	FileIndexLow                uint32        `json:"fileIndexLow"`
	DirectoryVolumeSerialNumber uint32        `json:"directoryVolumeSerialNumber"`
	DirectoryFileIndexHigh      uint32        `json:"directoryFileIndexHigh"`
	DirectoryFileIndexLow       uint32        `json:"directoryFileIndexLow"`
}

func (r PreparedMSIReceipt) Validate() error {
	if r.Version != PreparedMSIVersion || !job.ValidSelection(r.Package) || r.VolumeSerialNumber == 0 && r.FileIndexHigh == 0 && r.FileIndexLow == 0 || r.DirectoryVolumeSerialNumber == 0 && r.DirectoryFileIndexHigh == 0 && r.DirectoryFileIndexLow == 0 {
		return failure("msi-receipt")
	}
	return nil
}
func ValidatePreparedMSIBytes(payload []byte, selection job.Selection) error {
	if !job.ValidSelection(selection) || int64(len(payload)) != selection.Size || len(payload) < 512 || len(payload) > MaxPayloadBytes || !bytes.Equal(payload[:8], []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}) || actionpermit.Digest(payload) != selection.SHA256 {
		return failure("msi-bytes")
	}
	return nil
}

// StagePreparedMSI is create-only local custody, not installation. The caller
// must hold the exact stopped observer's lifecycle lease and persist intent
// before calling. Partial creations are retained, never reset or overwritten.
// Database metadata is inspected read-only from the protected staged object;
// no installer session, consistency repair, custom action or Win32_Product runs.
func StagePreparedMSI(ctx context.Context, observer windowsservice.Receipt, payload []byte, selection job.Selection) (PreparedMSIReceipt, error) {
	if cancelled(ctx) || len(payload) < 512 || len(payload) > MaxPayloadBytes {
		return PreparedMSIReceipt{}, failure("msi-bytes")
	}
	payload = bytes.Clone(payload)
	if ValidatePreparedMSIBytes(payload, selection) != nil {
		return PreparedMSIReceipt{}, failure("msi-bytes")
	}
	return stagePreparedMSINative(ctx, observer, payload, selection)
}

type preparedMSIPin interface {
	Verify(context.Context, PreparedMSIReceipt) error
	PinnedPath() string
	Close() error
}

// PreparedMSI keeps the exact file and every protected ancestor pinned, with no
// write/delete sharing, through metadata checks, native dispatch and post-state.
type PreparedMSI struct {
	mu      sync.Mutex
	pin     preparedMSIPin
	receipt PreparedMSIReceipt
	closed  bool
}

func OpenPreparedMSI(ctx context.Context, r PreparedMSIReceipt) (*PreparedMSI, error) {
	if r.Validate() != nil || cancelled(ctx) {
		return nil, failure("msi-receipt")
	}
	p, e := openPreparedMSINative(ctx, r)
	if e != nil {
		return nil, e
	}
	if e = p.Verify(ctx, r); e != nil {
		_ = p.Close()
		return nil, e
	}
	return &PreparedMSI{pin: p, receipt: r}, nil
}
func (p *PreparedMSI) Verify(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return failure("msi-closed")
	}
	return p.pin.Verify(ctx, p.receipt)
}
func (p *PreparedMSI) Path() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ""
	}
	return p.pin.PinnedPath()
}
func (p *PreparedMSI) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	return p.pin.Close()
}

// CheckPreparedMSIAbsent is the nonmutating fresh-plan gate. An existing or
// partially staged directory is never treated as a package available for reuse.
func CheckPreparedMSIAbsent(ctx context.Context, observer windowsservice.Receipt) error {
	return checkPreparedMSIAbsentNative(ctx, observer)
}
