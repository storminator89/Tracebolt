package windowspackage

import (
	"context"
	"sync"

	job "localrmm/internal/windowssoftwarejob"
)

const ManagedMSIVersion = "tracebolt.windows-managed-msi-custody.v1"
const managedMSIDirectory = "windows-managed-msi-package"
const managedMSIName = "managed.msi"

// ManagedMSIReceipt proves an original successful create, including NTFS object
// identity. Matching bytes later found at a path are never adopted. The setup
// coordinator durably retains this receipt beside the exact package consent.
type ManagedMSIReceipt struct {
	Version                     string        `json:"version"`
	Package                     job.Selection `json:"package"`
	VolumeSerialNumber          uint32        `json:"volumeSerialNumber"`
	FileIndexHigh               uint32        `json:"fileIndexHigh"`
	FileIndexLow                uint32        `json:"fileIndexLow"`
	DirectoryVolumeSerialNumber uint32        `json:"directoryVolumeSerialNumber"`
	DirectoryFileIndexHigh      uint32        `json:"directoryFileIndexHigh"`
	DirectoryFileIndexLow       uint32        `json:"directoryFileIndexLow"`
}

func (r ManagedMSIReceipt) Validate() error {
	if r.Version != ManagedMSIVersion || !job.ValidSelection(r.Package) || r.VolumeSerialNumber == 0 && r.FileIndexHigh == 0 && r.FileIndexLow == 0 || r.DirectoryVolumeSerialNumber == 0 && r.DirectoryFileIndexHigh == 0 && r.DirectoryFileIndexLow == 0 {
		return failure("msi-receipt")
	}
	return nil
}

type managedMSIPin interface {
	Verify(context.Context, ManagedMSIReceipt) error
	PinnedPath() string
	Close() error
}

// ManagedMSI keeps the exact file and every protected ancestor pinned, with no
// write/delete sharing, through metadata checks, native dispatch and post-state.
type ManagedMSI struct {
	mu      sync.Mutex
	pin     managedMSIPin
	receipt ManagedMSIReceipt
	closed  bool
}

func OpenManagedMSI(ctx context.Context, r ManagedMSIReceipt) (*ManagedMSI, error) {
	if r.Validate() != nil || cancelled(ctx) {
		return nil, failure("msi-receipt")
	}
	p, e := openManagedMSINative(ctx, r)
	if e != nil {
		return nil, e
	}
	if e = p.Verify(ctx, r); e != nil {
		_ = p.Close()
		return nil, e
	}
	return &ManagedMSI{pin: p, receipt: r}, nil
}
func (p *ManagedMSI) Verify(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return failure("msi-closed")
	}
	return p.pin.Verify(ctx, p.receipt)
}
func (p *ManagedMSI) Path() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ""
	}
	return p.pin.PinnedPath()
}
func (p *ManagedMSI) Close() error {
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
