package agentinstall

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

const MaxBinaryBytes = int64(128 << 20)
const MaxSourceBytes = int64(256 << 20)

var ErrArtifact = errors.New("local artifact integrity or native binary identity could not be verified")

type BinaryRole string

const (
	SenderBinary     BinaryRole = "lan-agent"
	EnrollmentBinary BinaryRole = "enroll-agent"
)

type VerifiedArtifact struct{ state *artifactState }
type artifactState struct {
	mu     sync.Mutex
	closed bool
	file   *os.File
	info   os.FileInfo
	digest string
	role   BinaryRole
	size   int64
}

func (VerifiedArtifact) String() string               { return "agentinstall.VerifiedArtifact{contents:redacted}" }
func (VerifiedArtifact) GoString() string             { return "agentinstall.VerifiedArtifact{contents:redacted}" }
func (v VerifiedArtifact) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, v.String()) }
func (VerifiedArtifact) MarshalJSON() ([]byte, error) {
	return []byte(`{"contentsRedacted":true}`), nil
}
func (v *VerifiedArtifact) Close() error {
	if v == nil || v.state == nil {
		return nil
	}
	s := v.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.file.Close()
}
func (v *VerifiedArtifact) SHA256() string {
	if v == nil || v.state == nil {
		return ""
	}
	s := v.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ""
	}
	return s.digest
}
func (v *VerifiedArtifact) Role() BinaryRole {
	if v == nil || v.state == nil {
		return ""
	}
	s := v.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ""
	}
	return s.role
}

// VerifyBinary opens a bounded regular native Go artifact once. The expected
// digest is operator-supplied trust input, not publisher signature verification.
// CopyVerified hashes that same open descriptor again while staging, closing
// the hash-then-path-open race. It never executes the source path.
func VerifyBinary(ctx context.Context, path, expected string, role BinaryRole) (*VerifiedArtifact, error) {
	if ctx == nil || !validDigest(expected) || (role != SenderBinary && role != EnrollmentBinary) || runtime.GOOS != "linux" {
		return nil, ErrArtifact
	}
	f, info, e := openArtifact(path, MaxBinaryBytes)
	if e != nil {
		return nil, e
	}
	fail := func() (*VerifiedArtifact, error) { f.Close(); return nil, ErrArtifact }
	if e = hashReader(ctx, io.NewSectionReader(f, 0, info.Size()), expected); e != nil {
		return fail()
	}
	var header [64]byte
	if _, e = f.ReadAt(header[:], 0); e != nil || string(header[:4]) != "\x7fELF" || header[4] != 2 || header[5] != 1 || header[6] != 1 {
		return fail()
	}
	machine := binary.LittleEndian.Uint16(header[18:20])
	wanted := uint16(0)
	switch runtime.GOARCH {
	case "amd64":
		wanted = 62
	case "arm64":
		wanted = 183
	default:
		return fail()
	}
	kind := binary.LittleEndian.Uint16(header[16:18])
	if machine != wanted || (kind != 2 && kind != 3) || binary.LittleEndian.Uint32(header[20:24]) != 1 {
		return fail()
	}
	build, e := buildinfo.Read(f)
	if e != nil || build.Path != "localrmm/cmd/"+string(role) || build.Main.Path != "localrmm" {
		return fail()
	}
	if current, e := f.Stat(); e != nil || !sameArtifact(info, current) {
		return fail()
	}
	return &VerifiedArtifact{&artifactState{file: f, info: info, digest: expected, role: role, size: info.Size()}}, nil
}

// VerifySource checks a bounded local source archive as bytes only. It neither
// extracts it nor claims a reproducible relationship between source and binaries.
func VerifySource(ctx context.Context, path, expected string) error {
	if ctx == nil || !validDigest(expected) {
		return ErrArtifact
	}
	f, info, e := openArtifact(path, MaxSourceBytes)
	if e != nil {
		return e
	}
	defer f.Close()
	if hashReader(ctx, io.NewSectionReader(f, 0, info.Size()), expected) != nil {
		return ErrArtifact
	}
	current, e := f.Stat()
	if e != nil || !sameArtifact(info, current) {
		return ErrArtifact
	}
	return nil
}

// CopyVerified writes only into a caller-owned non-executable private staging
// file. The caller may publish/chmod it only after this returns successfully.
func (v *VerifiedArtifact) CopyVerified(ctx context.Context, destination io.Writer) error {
	if v == nil || v.state == nil || ctx == nil || destination == nil {
		return ErrArtifact
	}
	s := v.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrArtifact
	}
	current, e := s.file.Stat()
	if e != nil || !sameArtifact(s.info, current) {
		return ErrArtifact
	}
	hash := sha256.New()
	reader := &contextReader{ctx: ctx, reader: io.NewSectionReader(s.file, 0, s.size)}
	n, e := io.Copy(io.MultiWriter(destination, hash), reader)
	if e != nil || n != s.size || hex.EncodeToString(hash.Sum(nil)) != s.digest {
		return ErrArtifact
	}
	current, e = s.file.Stat()
	if e != nil || !sameArtifact(s.info, current) {
		return ErrArtifact
	}
	return nil
}
func openArtifact(path string, limit int64) (*os.File, os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, nil, ErrArtifact
	}
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() || before.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || before.Mode().Perm()&0022 != 0 || before.Size() <= 0 || before.Size() > limit {
		return nil, nil, ErrArtifact
	}
	f, e := openArtifactFile(path)
	if e != nil {
		return nil, nil, ErrArtifact
	}
	opened, e := f.Stat()
	if e != nil || !sameArtifact(before, opened) {
		f.Close()
		return nil, nil, ErrArtifact
	}
	return f, opened, nil
}
func sameArtifact(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime() == b.ModTime()
}
func hashReader(ctx context.Context, r io.Reader, expected string) error {
	h := sha256.New()
	if _, e := io.Copy(h, &contextReader{ctx: ctx, reader: r}); e != nil || hex.EncodeToString(h.Sum(nil)) != expected {
		return ErrArtifact
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(b []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.reader.Read(b)
}
