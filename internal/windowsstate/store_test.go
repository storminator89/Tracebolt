package windowsstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
)

// This backend is entirely in memory. No test in this package creates a file,
// ACL, service, identity, key, host grant, or native persistent state.
type fixtureFile struct {
	id   fileID
	data []byte
}
type fixtureBackend struct {
	id       fileID
	o        Options
	files    map[string]fixtureFile
	children map[string]*fixtureBackend
	seq      *uint64
	events   []string
	failAt   string
	badRoot  bool
	closed   bool
}

func (b *fixtureBackend) nextID() fileID {
	*b.seq++
	var id fileID
	binary.LittleEndian.PutUint64(id[:8], 123)
	binary.LittleEndian.PutUint64(id[8:16], *b.seq)
	return id
}
func newFixture(o Options, seq *uint64) *fixtureBackend {
	if seq == nil {
		seq = new(uint64)
	}
	b := &fixtureBackend{o: o, files: map[string]fixtureFile{}, children: map[string]*fixtureBackend{}, seq: seq}
	b.id = b.nextID()
	b.files[o.LockName] = fixtureFile{id: b.nextID()}
	b.files[o.TempName] = fixtureFile{id: b.nextID()}
	return b
}
func (b *fixtureBackend) event(s string) error {
	b.events = append(b.events, s)
	if b.failAt == s {
		return ErrStorage
	}
	return nil
}
func (b *fixtureBackend) rootID() fileID { return b.id }
func (b *fixtureBackend) verify() error {
	if b.badRoot {
		return ErrIntegrity
	}
	return b.event("verify")
}
func (b *fixtureBackend) list() ([]string, error) {
	if e := b.event("list"); e != nil {
		return nil, e
	}
	var out []string
	for n := range b.files {
		out = append(out, n)
	}
	for n := range b.children {
		out = append(out, n)
	}
	return out, nil
}
func (b *fixtureBackend) read(n string, max int64) ([]byte, fileID, error) {
	if e := b.event("read:" + n); e != nil {
		return nil, fileID{}, e
	}
	f, ok := b.files[n]
	if !ok {
		return nil, fileID{}, fs.ErrNotExist
	}
	if int64(len(f.data)) > max {
		return nil, fileID{}, ErrIntegrity
	}
	return slices.Clone(f.data), f.id, nil
}
func (b *fixtureBackend) writeLock(data []byte) error {
	phase := "commit"
	if bytes.Contains(data, []byte(`"pending":true`)) {
		phase = "pending"
	}
	if e := b.event(phase); e != nil {
		return e
	}
	f := b.files[b.o.LockName]
	f.data = slices.Clone(data)
	b.files[b.o.LockName] = f
	return b.event("flush:" + phase)
}
func (b *fixtureBackend) replace(n string, data []byte) (fileID, fileID, error) {
	f, ok := b.files[b.o.TempName]
	if !ok {
		return fileID{}, fileID{}, ErrIntegrity
	}
	if e := b.event("temp-write"); e != nil {
		return fileID{}, fileID{}, e
	}
	f.data = slices.Clone(data)
	b.files[b.o.TempName] = f
	if e := b.event("temp-flush"); e != nil {
		return fileID{}, fileID{}, e
	}
	if e := b.event("rename"); e != nil {
		return fileID{}, fileID{}, e
	}
	delete(b.files, b.o.TempName)
	b.files[n] = f
	if e := b.event("temp-create"); e != nil {
		return fileID{}, fileID{}, e
	}
	tmp := fixtureFile{id: b.nextID()}
	b.files[b.o.TempName] = tmp
	if e := b.event("new-temp-flush"); e != nil {
		return fileID{}, fileID{}, e
	}
	return f.id, tmp.id, nil
}
func (b *fixtureBackend) directoryID(n string) (fileID, error) {
	if e := b.event("directory:" + n); e != nil {
		return fileID{}, e
	}
	c, ok := b.children[n]
	if !ok {
		return fileID{}, fs.ErrNotExist
	}
	return c.id, nil
}
func (b *fixtureBackend) createChild(n string, o Options) (backend, error) {
	if e := b.event("child-create"); e != nil {
		return nil, e
	}
	if _, ok := b.children[n]; ok {
		return nil, ErrIntegrity
	}
	c := newFixture(o, b.seq)
	b.children[n] = c
	return c, nil
}
func (b *fixtureBackend) close() error { b.closed = true; return b.event("close") }
func createFixture(t *testing.T) (*Store, *fixtureBackend) {
	t.Helper()
	o := optionsFixture()
	o.Create = true
	b := newFixture(o, nil)
	s, e := openBackend(`C:\ProgramData\Tracebolt`, o, b)
	if e != nil {
		t.Fatal(e)
	}
	b.events = nil
	return s, b
}
func reopenFixture(b *fixtureBackend) (*Store, error) {
	o := b.o
	o.Create = false
	return openBackend(`C:\ProgramData\Tracebolt`, o, b)
}

func TestFixtureFreshWriteReadReopen(t *testing.T) {
	s, b := createFixture(t)
	if _, e := s.Read("state.json"); e != fs.ErrNotExist {
		t.Fatal("never-written state is not distinguished")
	}
	secret := []byte("test-only-private-payload")
	if e := s.Write("state.json", secret); e != nil {
		t.Fatal(e)
	}
	got, e := s.Read("state.json")
	if e != nil || !bytes.Equal(got, secret) {
		t.Fatal("read mismatch")
	}
	got[0] = 'x'
	got, e = s.Read("state.json")
	if e != nil || !bytes.Equal(got, secret) {
		t.Fatal("returned buffer aliased store")
	}
	s2, e := reopenFixture(b)
	if e != nil {
		t.Fatal(e)
	}
	got, e = s2.Read("state.json")
	if e != nil || !bytes.Equal(got, secret) {
		t.Fatal("reopen mismatch")
	}
	if e = s2.Write("state.json", []byte{}); e != nil {
		t.Fatal(e)
	}
	if _, e = s2.Read("state.json"); e != nil {
		t.Fatal("written empty file became fresh")
	}
	if e = s2.Close(); e != nil {
		t.Fatal(e)
	}
	if e = s2.Close(); e != nil {
		t.Fatal(e)
	}
	if e = s2.Verify(); e != ErrClosed {
		t.Fatal("closed store usable")
	}
}
func TestFixtureWriteOrderingAndGeneration(t *testing.T) {
	s, b := createFixture(t)
	if e := s.Write("state.json", []byte("v1")); e != nil {
		t.Fatal(e)
	}
	var phases []string
	for _, e := range b.events {
		switch e {
		case "pending", "flush:pending", "temp-write", "temp-flush", "rename", "temp-create", "new-temp-flush", "commit", "flush:commit":
			phases = append(phases, e)
		}
	}
	want := []string{"pending", "flush:pending", "temp-write", "temp-flush", "rename", "temp-create", "new-temp-flush", "commit", "flush:commit"}
	if !slices.Equal(phases, want) {
		t.Fatalf("bad operation ordering: %v", phases)
	}
	if s.state.Generation != 2 {
		t.Fatal("missing generation increment")
	}
	old := s.state.Files[0].ID
	if e := s.Write("state.json", []byte("v2")); e != nil {
		t.Fatal(e)
	}
	if s.state.Generation != 3 || s.state.Files[0].ID == old {
		t.Fatal("replacement did not bind new identity")
	}
}
func TestFixtureInterruptedWritesFailClosed(t *testing.T) {
	for _, phase := range []string{"pending", "flush:pending", "temp-write", "temp-flush", "rename", "temp-create", "new-temp-flush", "commit", "flush:commit"} {
		t.Run(phase, func(t *testing.T) {
			s, b := createFixture(t)
			if e := s.Write("state.json", []byte("initial")); e != nil {
				t.Fatal(e)
			}
			b.failAt = phase
			if e := s.Write("state.json", []byte("replacement")); e == nil {
				t.Fatal("injected failure lost")
			}
			if e := s.Verify(); e != ErrPoisoned {
				t.Fatalf("handle not poisoned: %v", e)
			}
			if e := s.Write("state.json", nil); e != ErrPoisoned {
				t.Fatal("poisoned handle retried")
			}
			b.failAt = ""
			_, e := reopenFixture(b)
			// A failed pending write made no mutation in this fixture. A failed final
			// flush may have fully committed. All intervening states must refuse reopen.
			if phase != "pending" && phase != "flush:commit" && e == nil {
				t.Fatal("interrupted state silently recovered")
			}
		})
	}
}
func TestFixtureUsedStateLossAndTampering(t *testing.T) {
	cases := map[string]func(*fixtureBackend){
		"missing-lock":      func(b *fixtureBackend) { delete(b.files, b.o.LockName) },
		"missing-temp":      func(b *fixtureBackend) { delete(b.files, b.o.TempName) },
		"missing-used-data": func(b *fixtureBackend) { delete(b.files, "state.json") },
		"data-edit": func(b *fixtureBackend) {
			f := b.files["state.json"]
			f.data = []byte("changed")
			b.files["state.json"] = f
		},
		"same-bytes-new-id": func(b *fixtureBackend) { f := b.files["state.json"]; f.id = b.nextID(); b.files["state.json"] = f },
		"lock-edit":         func(b *fixtureBackend) { f := b.files[b.o.LockName]; f.data[0] = 'X'; b.files[b.o.LockName] = f },
		"lock-new-id":       func(b *fixtureBackend) { f := b.files[b.o.LockName]; f.id = b.nextID(); b.files[b.o.LockName] = f },
		"temp-content": func(b *fixtureBackend) {
			f := b.files[b.o.TempName]
			f.data = []byte("orphan")
			b.files[b.o.TempName] = f
		},
		"extra-file":        func(b *fixtureBackend) { b.files["unexpected"] = fixtureFile{id: b.nextID()} },
		"ancestor-replaced": func(b *fixtureBackend) { b.badRoot = true },
		"root-replaced":     func(b *fixtureBackend) { b.id = b.nextID() },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			s, b := createFixture(t)
			if e := s.Write("state.json", []byte("initial")); e != nil {
				t.Fatal(e)
			}
			tamper(b)
			if e := s.Verify(); e == nil {
				t.Fatal("tampered live store accepted")
			}
			if e := s.Verify(); e != ErrPoisoned {
				t.Fatal("failed store not poisoned")
			}
			if _, e := reopenFixture(b); e == nil || e == fs.ErrNotExist {
				t.Fatalf("used state reinitialized or reported fresh: %v", e)
			}
		})
	}
}
func TestFixtureSchemaAndBoundedIO(t *testing.T) {
	s, b := createFixture(t)
	for _, name := range []string{"missing", "store.lock", "store.tmp", "../state.json", "STATE.JSON", "state.json:ads"} {
		if e := s.Write(name, nil); e != ErrPolicy {
			t.Fatal("unconfigured write permitted")
		}
		if _, e := s.Read(name); e != ErrPolicy {
			t.Fatal("unconfigured read permitted")
		}
	}
	if e := s.Write("state.json", make([]byte, 1025)); e != ErrPolicy {
		t.Fatal("oversized write permitted")
	}
	if e := s.Verify(); e != nil {
		t.Fatal("caller policy error poisoned healthy store")
	}
	o := b.o
	o.Create = false
	o.MaxBytes++
	if _, e := openBackend(`C:\ProgramData\Tracebolt`, o, b); e == nil {
		t.Fatal("bound changed")
	}
	o = b.o
	o.Create = false
	o.RuntimeSID = "S-1-5-80-5-4-3-2-1"
	if _, e := openBackend(`C:\ProgramData\Tracebolt`, o, b); e == nil {
		t.Fatal("SID changed")
	}
	o = b.o
	o.Create = false
	if _, e := openBackend(`C:\ProgramData\Elsewhere`, o, b); e == nil {
		t.Fatal("store relocated")
	}
	if _, e := openBackend(`C:\ProgramData\Tracebolt`, b.o, b); e == nil {
		t.Fatal("existing metadata adopted in create mode")
	}
}
func TestFixtureDirectoriesBoundWithoutFreezingContents(t *testing.T) {
	s, b := createFixture(t)
	o := optionsFixture()
	o.Create = true
	o.Directories = nil
	child, e := s.CreateDirectoryStore("telemetry", o)
	if e != nil {
		t.Fatal(e)
	}
	if e = child.Write("state.json", []byte("child data")); e != nil {
		t.Fatal(e)
	}
	if e = s.Verify(); e != nil {
		t.Fatal("child's own updates invalidated parent")
	}
	names, e := s.Entries()
	if e != nil || !slices.Equal(names, []string{"telemetry"}) {
		t.Fatal("tracked directory missing")
	}
	if _, e = s.CreateDirectoryStore("telemetry", o); e != ErrPolicy {
		t.Fatal("used child recreated")
	}
	b.children["telemetry"].id = b.nextID()
	if e = s.Verify(); e == nil {
		t.Fatal("child replaced without rejection")
	}
	if _, e = reopenFixture(b); e == nil {
		t.Fatal("replaced child adopted on reopen")
	}
}
func TestFixtureMissingAndUnrecordedChildren(t *testing.T) {
	s, b := createFixture(t)
	b.children["telemetry"] = newFixture(optionsFixture(), b.seq)
	if e := s.Verify(); e == nil {
		t.Fatal("unrecorded pre-existing child adopted")
	}
	s, b = createFixture(t)
	o := optionsFixture()
	o.Create = true
	o.Directories = nil
	c, e := s.CreateDirectoryStore("telemetry", o)
	if e != nil {
		t.Fatal(e)
	}
	_ = c.Close()
	delete(b.children, "telemetry")
	if _, e = reopenFixture(b); e == nil || e == fs.ErrNotExist {
		t.Fatal("used child loss reset")
	}
}
func TestFixtureStoreFormattingRedacts(t *testing.T) {
	s, _ := createFixture(t)
	secret := []byte("fixture-private-key-redact-me")
	if e := s.Write("state.json", secret); e != nil {
		t.Fatal(e)
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		out := fmt.Sprintf(format, s)
		if strings.Contains(out, string(secret)) || out != "<protected Windows state>" {
			t.Fatalf("unsafe format %s", format)
		}
	}
}
func TestManifestParserStrictFixtures(t *testing.T) {
	s, _ := createFixture(t)
	encoded, e := encodeManifest(s.state)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = decodeManifest(encoded); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < len(encoded); i++ {
		if _, e = decodeManifest(encoded[:i]); e == nil {
			t.Fatalf("truncated manifest %d accepted", i)
		}
	}
	variants := []func(*manifest){func(m *manifest) { m.Pending = true }, func(m *manifest) { m.Version = 2 }, func(m *manifest) { m.Generation = 0 }, func(m *manifest) { m.LockID = m.RootID }, func(m *manifest) { m.Files[0].ID = m.RootID }, func(m *manifest) { m.Files[0].Hash = sha256.Sum256([]byte("unrecorded")) }, func(m *manifest) { m.TempID = fileID{} }, func(m *manifest) { m.RuntimeSID = administratorsSID }, func(m *manifest) { m.Path = `\\server\share` }}
	for i, change := range variants {
		m := s.state
		m.Files = slices.Clone(m.Files)
		m.Directories = slices.Clone(m.Directories)
		change(&m)
		data, _ := encodeManifest(m)
		if _, e := decodeManifest(data); e == nil {
			t.Errorf("invalid manifest %d accepted", i)
		}
	}
}
func FuzzManifestParser(f *testing.F) {
	f.Add([]byte("TBWS1\n"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = decodeManifest(b) })
}

func TestManifestRejectsNoncanonicalJSON(t *testing.T) {
	s, _ := createFixture(t)
	valid, _ := encodeManifest(s.state)
	payload := string(valid[71:])
	for _, body := range []string{
		payload + "\n",
		strings.Replace(payload, `"version":1,`, `"version":1,"version":1,`, 1),
		strings.Replace(payload, `"version":1,`, `"version":1,"unknown":true,`, 1),
	} {
		sum := sha256.Sum256([]byte(body))
		encoded := []byte(fmt.Sprintf("TBWS1\n%x\n%s", sum, body))
		if _, e := decodeManifest(encoded); e == nil {
			t.Fatal("noncanonical or duplicate-key manifest accepted")
		}
	}
}
func TestFixtureInterruptedChildCreation(t *testing.T) {
	for _, phase := range []string{"flush:pending", "child-create", "commit"} {
		t.Run(phase, func(t *testing.T) {
			s, b := createFixture(t)
			b.failAt = phase
			o := optionsFixture()
			o.Create = true
			o.Directories = nil
			if _, e := s.CreateDirectoryStore("telemetry", o); e == nil {
				t.Fatal("injected child failure ignored")
			}
			if e := s.Verify(); e != ErrPoisoned {
				t.Fatal("parent not poisoned")
			}
			b.failAt = ""
			if _, e := reopenFixture(b); e == nil || e == fs.ErrNotExist {
				t.Fatal("partial child creation adopted")
			}
		})
	}
}
func TestFixtureExplicitInstallerSchema(t *testing.T) {
	o := optionsFixture()
	o.RuntimeSID = ""
	o.InstallerOnly = true
	o.Create = true
	b := newFixture(o, nil)
	s, e := openBackend(`C:\ProgramData\Tracebolt`, o, b)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Write("state.json", []byte("public installer phase")); e != nil {
		t.Fatal(e)
	}
	o.Create = false
	if _, e = openBackend(`C:\ProgramData\Tracebolt`, o, b); e != nil {
		t.Fatal(e)
	}
	o.InstallerOnly = false
	o.RuntimeSID = testSID
	if _, e = openBackend(`C:\ProgramData\Tracebolt`, o, b); e == nil {
		t.Fatal("admin-only metadata reused as runtime scope")
	}
}
