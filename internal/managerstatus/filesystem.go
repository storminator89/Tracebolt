package managerstatus

import (
	"context"
	"errors"
	"os"
	"sync"
)

var ErrFilesystemProbe = errors.New("manager filesystem probe is unavailable")

// FilesystemProbe owns only two reserved, zero-content diagnostic file names.
// Copies share their lock. It never opens an authority file, changes permissions,
// or infers DB durability.
type FilesystemProbe struct {
	mu        *sync.Mutex
	directory string
	original  os.FileInfo
	openNext  func(string) (*os.File, error)
	syncFile  func(*os.File) error
}

func (FilesystemProbe) String() string               { return "managerstatus.FilesystemProbe{path:redacted}" }
func (FilesystemProbe) GoString() string             { return "managerstatus.FilesystemProbe{path:redacted}" }
func (FilesystemProbe) MarshalJSON() ([]byte, error) { return []byte(`{"pathRedacted":true}`), nil }

// NewFilesystemProbe requires an already approved private runtime state directory.
// Construction writes nothing. Only Check creates its bounded diagnostic files.
func NewFilesystemProbe(directory string) (*FilesystemProbe, error) {
	return newFilesystemProbe(directory)
}

func (p *FilesystemProbe) Check(ctx context.Context) ProbeResult { return p.checkFilesystem(ctx) }
