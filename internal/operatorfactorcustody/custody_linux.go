//go:build linux

package operatorfactorcustody

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/json"
	"encoding/pem"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanconfig"
	"localrmm/internal/operatorfactorclient"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type pinnedFile struct {
	path    string
	digest  [32]byte
	info    os.FileInfo
	private bool
	limit   int64
}
type linuxPlan struct {
	config                 lanconfig.Config
	reference              lanconfig.AccountAuthorityReference
	files                  []pinnedFile
	stateInfo, handoffInfo os.FileInfo
	// Deterministic test-only filesystem failure seam; production defaults below.
	write func(*os.File, []byte) (int, error)
	sync  func(*os.File) error
}

func inside(path, dir string) bool {
	rel, e := filepath.Rel(dir, path)
	return e == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
func canonical(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }
func secureDirectory(path string) (*os.File, error) {
	if !canonical(path) {
		return nil, ErrConfiguration
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, ErrConfiguration
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	check := func(fd int, leaf bool) bool {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil {
			return false
		}
		uid := uint32(os.Geteuid())
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != uid && st.Uid != 0) || (st.Mode&0022 != 0 && st.Mode&unix.S_ISVTX == 0) {
			return false
		}
		return !leaf || (st.Uid == uid && st.Mode&0777 == 0700)
	}
	if !check(fd, path == "/") {
		unix.Close(fd)
		return nil, ErrConfiguration
	}
	for i, part := range parts {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(fd)
		if e != nil {
			return nil, ErrConfiguration
		}
		fd = next
		if !check(fd, i == len(parts)-1) {
			unix.Close(fd)
			return nil, ErrConfiguration
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}
func pin(path string, private bool, limit int64) ([]byte, pinnedFile, error) {
	raw, e := lanconfig.ReadProtected(path, private, limit)
	if e != nil {
		return nil, pinnedFile{}, ErrConfiguration
	}
	info, e := os.Lstat(path)
	if e != nil {
		clear(raw)
		return nil, pinnedFile{}, ErrConfiguration
	}
	return raw, pinnedFile{path, sha256.Sum256(raw), info, private, limit}, nil
}

// A configured public chain may contain certificates only. The transport pins
// the first certificate; the remaining public chain is validated but not used
// as ambient authority. A private-key PEM block is never accepted as a cert.
func publicLeaf(raw []byte) ([]byte, error) {
	data := bytes.TrimSpace(raw)
	if !bytes.HasPrefix(data, []byte("-----BEGIN")) {
		cert, e := x509.ParseCertificate(data)
		if e != nil {
			return nil, ErrConfiguration
		}
		return append([]byte(nil), cert.Raw...), nil
	}
	var leaf []byte
	for len(data) > 0 {
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrConfiguration
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrConfiguration
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return nil, ErrConfiguration
		}
		if leaf == nil {
			leaf = append([]byte(nil), cert.Raw...)
		}
		data = bytes.TrimSpace(rest)
	}
	if len(leaf) == 0 {
		return nil, ErrConfiguration
	}
	return leaf, nil
}

func absentAt(dir *os.File, leaf string) bool {
	var st unix.Stat_t
	return unix.Fstatat(int(dir.Fd()), leaf, &st, unix.AT_SYMLINK_NOFOLLOW) == unix.ENOENT
}
func PlanFor(o Options) (*Plan, error) {
	if !o.Acknowledge || o.RuntimeUID <= 0 || o.RuntimeUID != os.Geteuid() || !enrollmentcrypto.ValidID(o.ActorID, "operator_") || o.ExpectedRevision == 0 || !canonical(o.LanConfig) || !canonical(o.HandoffFile) {
		return nil, ErrConfiguration
	}
	raw, configPin, e := pin(o.LanConfig, false, 16384)
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	c, e := lanconfig.Parse(raw)
	if e != nil || c.Profile != lanconfig.TLS {
		return nil, ErrConfiguration
	}
	if c.TLSCertificateFile == c.TLSPrivateKeyFile || c.OperatorAuthFile == c.TLSPrivateKeyFile || filepath.Join(c.StateDirectory, lanconfig.AccountAuthorityMarkerFile) == c.TLSPrivateKeyFile {
		return nil, ErrConfiguration
	}
	if inside(o.HandoffFile, c.StateDirectory) || inside(o.HandoffFile, c.WebDirectory) || o.HandoffFile == o.LanConfig || o.HandoffFile == c.OperatorAuthFile || o.HandoffFile == c.TLSCertificateFile || o.HandoffFile == c.TLSPrivateKeyFile || o.HandoffFile == c.AgentClientCAFile || inside(c.StateDirectory, c.WebDirectory) || inside(c.WebDirectory, c.StateDirectory) || inside(c.OperatorAuthFile, c.WebDirectory) {
		return nil, ErrConfiguration
	}
	state, e := secureDirectory(c.StateDirectory)
	if e != nil {
		return nil, e
	}
	defer state.Close()
	handoff, e := secureDirectory(filepath.Dir(o.HandoffFile))
	if e != nil {
		return nil, e
	}
	defer handoff.Close()
	if !absentAt(handoff, filepath.Base(o.HandoffFile)) {
		return nil, ErrExisting
	}
	refRaw, refPin, e := pin(c.OperatorAuthFile, true, 4096)
	if e != nil {
		return nil, e
	}
	defer clear(refRaw)
	ref, e := lanconfig.ParseAccountAuthority(refRaw, c.Profile)
	if e != nil {
		return nil, ErrConfiguration
	}
	expected, e := lanconfig.AccountAuthorityMarkerBytes(c.StateDirectory, *ref)
	if e != nil {
		return nil, ErrConfiguration
	}
	markerRaw, markerPin, e := pin(filepath.Join(c.StateDirectory, lanconfig.AccountAuthorityMarkerFile), true, 4096)
	if e != nil {
		return nil, e
	}
	defer clear(markerRaw)
	var compact bytes.Buffer
	if json.Compact(&compact, markerRaw) != nil || !bytes.Equal(compact.Bytes(), expected) {
		return nil, ErrConfiguration
	}
	cert, certPin, e := pin(c.TLSCertificateFile, false, 65536)
	if e != nil {
		return nil, e
	}
	leafCert, e := publicLeaf(cert)
	clear(cert)
	if e != nil {
		return nil, e
	}
	stateInfo, e := state.Stat()
	if e != nil {
		return nil, ErrConfiguration
	}
	handoffInfo, e := handoff.Stat()
	if e != nil {
		return nil, ErrConfiguration
	}
	data := &linuxPlan{config: c, reference: *ref, files: []pinnedFile{configPin, refPin, markerPin, certPin}, stateInfo: stateInfo, handoffInfo: handoffInfo}
	return &Plan{options: o, client: operatorfactorclient.Config{Origin: c.OperatorOrigin, ServerCertificate: leafCert}, data: data}, nil
}
func (d *linuxPlan) unchanged() bool {
	for _, p := range d.files {
		raw, e := lanconfig.ReadProtected(p.path, p.private, p.limit)
		if e != nil {
			return false
		}
		digest := sha256.Sum256(raw)
		clear(raw)
		info, e := os.Lstat(p.path)
		if e != nil || !os.SameFile(info, p.info) || info.Mode() != p.info.Mode() || digest != p.digest {
			return false
		}
	}
	return true
}
func privateFile(f *os.File) bool {
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1
}
func readAt(dir *os.File, leaf string) ([]byte, *os.File, error) {
	fd, e := unix.Openat(int(dir.Fd()), leaf, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, nil, ErrExisting
	}
	f := os.NewFile(uintptr(fd), leaf)
	if !privateFile(f) {
		f.Close()
		return nil, nil, ErrConfiguration
	}
	raw, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil || len(raw) == 0 || len(raw) > 4096 {
		clear(raw)
		f.Close()
		return nil, nil, ErrConfiguration
	}
	return raw, f, nil
}

type proposal struct {
	Version          string `json:"version"`
	AuthorityID      string `json:"authorityId"`
	ActorID          string `json:"actorId"`
	ExpectedRevision uint64 `json:"expectedRevision"`
	Secret           string `json:"secret"`
}

func validOld(raw []byte, ref lanconfig.AccountAuthorityReference, o Options) (uint64, bool) {
	var p proposal
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&p) != nil {
		return 0, false
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return 0, false
	}
	defer clear(compact.Bytes())
	canonical, e := json.Marshal(p)
	defer clear(canonical)
	if e != nil || !bytes.Equal(compact.Bytes(), canonical) || p.Version != "tracebolt.operator-factor-proposal.v1" || p.AuthorityID != ref.AuthorityID || p.ActorID != o.ActorID || p.ExpectedRevision == 0 || p.ExpectedRevision >= o.ExpectedRevision {
		return 0, false
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	secret, e := enc.DecodeString(p.Secret)
	defer clear(secret)
	return p.ExpectedRevision, e == nil && len(secret) == 32 && enc.EncodeToString(secret) == p.Secret
}
func (d *linuxPlan) syncFile(f *os.File) error {
	if d.sync != nil {
		return d.sync(f)
	}
	return f.Sync()
}
func (d *linuxPlan) create(dir *os.File, leaf string, raw []byte) (bool, error) {
	fd, e := unix.Openat(int(dir.Fd()), leaf, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		if e == unix.EEXIST {
			return false, ErrExisting
		}
		return false, ErrUncertain
	}
	f := os.NewFile(uintptr(fd), leaf)
	if !privateFile(f) {
		f.Close()
		return true, ErrUncertain
	}
	var n int
	if d.write != nil {
		n, e = d.write(f, raw)
	} else {
		n, e = f.Write(raw)
	}
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = d.syncFile(f)
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e == nil {
		e = d.syncFile(dir)
	}
	if e != nil {
		return true, ErrUncertain
	}
	return true, nil
}
func (p *Plan) Stage(ctx context.Context, target operatorfactorclient.Account) (Result, error) {
	var result Result
	if p == nil || ctx == nil {
		return result, ErrConfiguration
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used {
		return result, ErrUncertain
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	o := p.options
	d, ok := p.data.(*linuxPlan)
	if !ok {
		return result, ErrUnsupported
	}
	if target.ID != o.ActorID || target.Revision != o.ExpectedRevision || target.Disabled || target.Uncertain || (target.FactorState != "" && target.FactorState != "enrollment_required") {
		return result, ErrTarget
	}
	if !d.unchanged() {
		return result, ErrChanged
	}
	state, e := secureDirectory(d.config.StateDirectory)
	if e != nil {
		return result, ErrChanged
	}
	defer state.Close()
	handoff, e := secureDirectory(filepath.Dir(o.HandoffFile))
	if e != nil {
		return result, ErrChanged
	}
	defer handoff.Close()
	si, e := state.Stat()
	if e != nil || !os.SameFile(si, d.stateInfo) {
		return result, ErrChanged
	}
	hi, e := handoff.Stat()
	if e != nil || !os.SameFile(hi, d.handoffInfo) {
		return result, ErrChanged
	}
	if !absentAt(handoff, filepath.Base(o.HandoffFile)) {
		return result, ErrExisting
	}
	leaf := filepath.Base(d.reference.AuthorityFile) + ".factor-" + o.ActorID + ".json"
	var old *os.File
	var archive string
	var oldDigest [32]byte
	if !absentAt(state, leaf) {
		if !o.ReplaceStale {
			return result, ErrExisting
		}
		raw, f, e := readAt(state, leaf)
		if e != nil {
			return result, e
		}
		old = f
		defer old.Close()
		revision, valid := validOld(raw, d.reference, o)
		oldDigest = sha256.Sum256(raw)
		clear(raw)
		if !valid {
			return result, ErrExisting
		}
		archive = leaf + ".retired-" + strconv.FormatUint(revision, 10)
		if !absentAt(state, archive) {
			return result, ErrExisting
		}
	}
	secretBytes := make([]byte, 32)
	if _, e = rand.Read(secretBytes); e != nil {
		p.used = true
		return result, ErrUncertain
	}
	defer clear(secretBytes)
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)
	pr := proposal{"tracebolt.operator-factor-proposal.v1", d.reference.AuthorityID, o.ActorID, o.ExpectedRevision, secret}
	proposalRaw, e := json.Marshal(pr)
	if e != nil {
		return result, ErrConfiguration
	}
	defer clear(proposalRaw)
	handoffRaw, e := json.Marshal(struct {
		Version          string `json:"version"`
		AuthorityID      string `json:"authorityId"`
		ActorID          string `json:"actorId"`
		ExpectedRevision uint64 `json:"expectedRevision"`
		Algorithm        string `json:"algorithm"`
		Digits           int    `json:"digits"`
		Period           int    `json:"period"`
		Secret           string `json:"secret"`
	}{"tracebolt.operator-factor-handoff.v1", d.reference.AuthorityID, o.ActorID, o.ExpectedRevision, "SHA256", 8, 30, secret})
	if e != nil {
		return result, ErrConfiguration
	}
	defer clear(handoffRaw)
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if !d.unchanged() {
		return result, ErrChanged
	}
	p.used = true
	if old != nil {
		info, e := old.Stat()
		var current unix.Stat_t
		if e != nil || !privateFile(old) || unix.Fstatat(int(state.Fd()), leaf, &current, unix.AT_SYMLINK_NOFOLLOW) != nil {
			return result, ErrChanged
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Dev != uint64(current.Dev) || st.Ino != current.Ino {
			return result, ErrChanged
		}
		if renameErr := unix.Renameat2(int(state.Fd()), leaf, int(state.Fd()), archive, unix.RENAME_NOREPLACE); renameErr != nil {
			if renameErr == unix.EEXIST {
				return result, ErrExisting
			}
			return result, ErrUncertain
		}
		result.Archived = true
		archivedRaw, archivedFile, readErr := readAt(state, archive)
		if readErr != nil {
			return result, ErrUncertain
		}
		archivedFile.Close()
		unchanged := sha256.Sum256(archivedRaw) == oldDigest
		clear(archivedRaw)
		if !unchanged || d.syncFile(state) != nil {
			return result, ErrUncertain
		}
	}
	created, e := d.create(handoff, filepath.Base(o.HandoffFile), handoffRaw)
	result.HandoffCreated = created
	if e != nil {
		if result.Archived || created {
			return result, ErrUncertain
		}
		return result, e
	}
	if ctx.Err() != nil {
		return result, ErrUncertain
	}
	created, e = d.create(state, leaf, proposalRaw)
	result.ProposalCreated = created
	if e != nil {
		return result, ErrUncertain
	}
	return result, nil
}
