package lanstore

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
)

// PrepareProfileDirectory prevents accidental TLS/plaintext state reuse. An
// existing unmarked, nonempty directory is never adopted or chmodded.
func PrepareProfileDirectory(dir, profile string) error {
	if profile != "tls" && profile != "http-test" {
		return ErrStorage
	}
	absolute, e := safePath(dir)
	if e != nil {
		return e
	}
	if os.MkdirAll(absolute, 0700) != nil {
		return ErrStorage
	}
	if privateStateDirectory(absolute) != nil {
		return ErrStorage
	}
	path := filepath.Join(absolute, "profile")
	expected := []byte("tracebolt.lan-state.v1\n" + profile + "\n")
	if _, e = os.Lstat(path); os.IsNotExist(e) {
		entries, e := os.ReadDir(absolute)
		if e != nil || len(entries) != 0 {
			return ErrStorage
		}
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return ErrStorage
		}
		_, e = f.Write(expected)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil || ce != nil {
			return ErrStorage
		}
		d, e := os.Open(absolute)
		if e != nil {
			return ErrStorage
		}
		e = d.Sync()
		d.Close()
		if e != nil {
			return ErrStorage
		}
	}
	if privateStateFile(path) != nil {
		return ErrStorage
	}
	f, e := os.Open(path)
	if e != nil {
		return ErrStorage
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, 128))
	if e != nil || !bytes.Equal(raw, expected) {
		return ErrStorage
	}
	return nil
}

// ValidateStateFile covers other fixed database filenames in the same private
// deployment directory before their owning storage package opens them.
func ValidateStateFile(path string) error {
	absolute, e := safePath(path)
	if e != nil {
		return e
	}
	if privateStateDirectory(filepath.Dir(absolute)) != nil {
		return ErrStorage
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if privateStateFile(absolute+suffix) != nil {
			return ErrStorage
		}
	}
	return nil
}
