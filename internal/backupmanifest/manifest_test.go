package backupmanifest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func hash(raw []byte) string {
	s := sha256.Sum256(raw)
	return hex.EncodeToString(s[:])
}

func fixture() (Manifest, Expected, map[string][]byte) {
	b := Binding{BuildSHA256: hash([]byte("build")), ConfigSHA256: hash([]byte("config")), IssuerSHA256: hash([]byte("issuer")), InstanceSHA256: hash([]byte("immutable-instance")), Profile: "tls", RuntimeUID: 1000, RuntimeGID: 1000}
	m := Manifest{SchemaVersion: SchemaVersion, CaptureMode: CaptureMode, Binding: b, Databases: []Database{
		{Name: "state/agents.db", Schema: "fixture-agents-v1", WAL: true, SHM: true},
		{Name: "state/operator.db", Schema: "fixture-operator-v1", Journal: true},
	}}
	data := map[string][]byte{}
	e := Expected{Binding: b}
	for _, spec := range []ObjectSpec{
		{"state/agents.db", "database"}, {"state/agents.db-wal", "sidecar"}, {"state/agents.db-shm", "sidecar"},
		{"state/operator.db", "database"}, {"state/operator.db-journal", "sidecar"},
		{"state/profile", "state"}, {"external/action-ledger", "state"}, {"config/manager", "configuration"}, {"custodian/issuer-key", "credential"},
	} {
		data[spec.Name] = []byte("invented offline fixture bytes: " + spec.Name)
		m.Objects = append(m.Objects, Object{Name: spec.Name, Kind: spec.Kind, Size: int64(len(data[spec.Name])), SHA256: hash(data[spec.Name])})
		e.Objects = append(e.Objects, spec)
	}
	e.Databases = append([]Database(nil), m.Databases...)
	return m, e, data
}

func encode(t *testing.T, m Manifest, e Expected) ([]byte, Expected) {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	e.ManifestSHA256 = hash(raw)
	return raw, e
}

func readers(data map[string][]byte) map[string]io.Reader {
	r := map[string]io.Reader{}
	for name, raw := range data {
		r[name] = bytes.NewReader(raw)
	}
	return r
}

type observedReader struct{ calls *int }

func (r observedReader) Read([]byte) (int, error) {
	*r.calls++
	return 0, errors.New("invented-private-reader-error")
}

func expectRejectedBeforeRead(t *testing.T, raw []byte, e Expected, data map[string][]byte, want error) {
	t.Helper()
	calls := 0
	r := readers(data)
	for name := range r {
		r[name] = observedReader{&calls}
	}
	if err := Verify(context.Background(), raw, e, r); err != want || calls != 0 {
		t.Fatalf("error=%v calls=%d; want fixed error %v before reads", err, calls, want)
	}
}

func TestBackupManifestExactInventoryIntegrityOnly(t *testing.T) {
	m, e, data := fixture()
	raw, e := encode(t, m, e)
	// Expected inventory ordering is not authority; exact named entries are.
	e.Databases[0], e.Databases[1] = e.Databases[1], e.Databases[0]
	e.Objects[0], e.Objects[1] = e.Objects[1], e.Objects[0]
	if err := Verify(context.Background(), raw, e, readers(data)); err != nil {
		t.Fatal(err)
	}
	// A genuine historical capture receipt still verifies the same old bytes.
	// There is deliberately no clock, freshness flag or quarantine-release API.
	if err := Verify(context.Background(), raw, e, readers(data)); err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-2] ^= 1
	expectRejectedBeforeRead(t, raw, e, data, ErrIntegrity)
}

func TestBackupManifestExactBindingBeforeReads(t *testing.T) {
	for _, field := range []string{"build", "config", "issuer", "instance", "profile", "uid", "gid", "root"} {
		t.Run(field, func(t *testing.T) {
			m, e, data := fixture()
			raw, e := encode(t, m, e)
			switch field {
			case "build":
				e.Binding.BuildSHA256 = hash([]byte("other"))
			case "config":
				e.Binding.ConfigSHA256 = hash([]byte("other"))
			case "issuer":
				e.Binding.IssuerSHA256 = hash([]byte("other"))
			case "instance":
				e.Binding.InstanceSHA256 = hash([]byte("other"))
			case "profile":
				e.Binding.Profile = "http-test"
			case "uid":
				e.Binding.RuntimeUID++
			case "gid":
				e.Binding.RuntimeGID++
			case "root":
				e.Binding.RuntimeUID = 0
			}
			expectRejectedBeforeRead(t, raw, e, data, ErrBinding)
		})
	}
}

func TestBackupManifestStrictClosedJSON(t *testing.T) {
	m, e, data := fixture()
	raw, e := encode(t, m, e)
	for name, change := range map[string]func(string) string{
		"root-duplicate": func(s string) string {
			return strings.Replace(s, `"schemaVersion":`, `"schemaVersion":"x","schemaVersion":`, 1)
		},
		"nested-duplicate": func(s string) string { return strings.Replace(s, `"wal":true`, `"wal":false,"wal":true`, 1) },
		"alias":            func(s string) string { return strings.Replace(s, `"runtimeUid"`, `"RuntimeUid"`, 1) },
		"unknown":          func(s string) string { return strings.Replace(s, `"wal":true`, `"wal":true,"release":true`, 1) },
		"missing-sidecar":  func(s string) string { return strings.Replace(s, `"shm":true,`, ``, 1) },
		"null-sidecar":     func(s string) string { return strings.Replace(s, `"wal":true`, `"wal":null`, 1) },
		"null-binding":     func(s string) string { return strings.Replace(s, `"runtimeUid":1000`, `"runtimeUid":null`, 1) },
		"null-row":         func(s string) string { return strings.Replace(s, `"objects":[`, `"objects":[null,`, 1) },
		"unknown-schema":   func(s string) string { return strings.Replace(s, SchemaVersion, SchemaVersion+".future", 1) },
		"online-mode":      func(s string) string { return strings.Replace(s, CaptureMode, "running-writers", 1) },
		"trailing-value":   func(s string) string { return s + `{}` },
		"partial":          func(s string) string { return s[:len(s)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			changed := []byte(change(string(raw)))
			receipt := e
			receipt.ManifestSHA256 = hash(changed)
			expectRejectedBeforeRead(t, changed, receipt, data, ErrManifest)
		})
	}
	// Size admission happens before JSON decoding or reading any object.
	oversized := bytes.Repeat([]byte(" "), MaxManifestBytes+1)
	e.ManifestSHA256 = hash(oversized)
	expectRejectedBeforeRead(t, oversized, e, data, ErrManifest)
}

func TestBackupManifestClosedRosterAndSidecars(t *testing.T) {
	for _, name := range []string{"missing-wal", "undeclared-shm", "wrong-schema", "duplicate-object", "duplicate-db", "missing-expected", "missing-reader", "extra-reader", "path-key", "orphan-sidecar", "negative-size", "object-bound", "aggregate-bound"} {
		t.Run(name, func(t *testing.T) {
			m, e, data := fixture()
			switch name {
			case "missing-wal":
				m.Objects = append(m.Objects[:1], m.Objects[2:]...)
			case "undeclared-shm":
				m.Databases[0].SHM = false
				e.Databases[0].SHM = false
			case "wrong-schema":
				m.Databases[0].Schema = "unexpected-v2"
			case "duplicate-object":
				m.Objects[1] = m.Objects[0]
			case "duplicate-db":
				m.Databases[1] = m.Databases[0]
			case "missing-expected":
				e.Objects = e.Objects[:len(e.Objects)-1]
			case "missing-reader":
				delete(data, m.Objects[0].Name)
			case "extra-reader":
				data["unexpected"] = nil
			case "path-key":
				m.Objects[0].Name = "../agents.db"
				e.Objects[0].Name = m.Objects[0].Name
			case "orphan-sidecar":
				m.Objects[5].Kind = "sidecar"
				e.Objects[5].Kind = "sidecar"
			case "negative-size":
				m.Objects[0].Size = -1
			case "object-bound":
				m.Objects[0].Size = MaxObjectBytes + 1
			case "aggregate-bound":
				for i := 0; i < 5; i++ {
					m.Objects[i].Size = MaxObjectBytes
				}
			}
			raw, e := encode(t, m, e)
			expectRejectedBeforeRead(t, raw, e, data, ErrInventory)
		})
	}
}

type noProgressReader struct{}

func (noProgressReader) Read([]byte) (int, error) { return 0, nil }

type finalReader struct{ raw []byte }

func (r finalReader) Read(p []byte) (int, error) { return copy(p, r.raw), io.EOF }

func TestBackupManifestStreamsAndFixedDiagnostics(t *testing.T) {
	for _, name := range []string{"short", "extra", "corrupt", "read-error", "no-progress", "data-with-eof", "empty", "multi-buffer", "multi-buffer-extra"} {
		t.Run(name, func(t *testing.T) {
			m, e, data := fixture()
			key := m.Objects[0].Name
			if name == "empty" {
				data[key] = nil
				m.Objects[0].Size = 0
				m.Objects[0].SHA256 = hash(nil)
			}
			if strings.HasPrefix(name, "multi-buffer") {
				data[key] = bytes.Repeat([]byte("x"), 3*32*1024)
				m.Objects[0].Size = int64(len(data[key]))
				m.Objects[0].SHA256 = hash(data[key])
			}
			raw, e := encode(t, m, e)
			r := readers(data)
			want := ErrIntegrity
			switch name {
			case "short":
				r[key] = bytes.NewReader(data[key][:len(data[key])-1])
			case "extra":
				r[key] = io.MultiReader(bytes.NewReader(data[key]), strings.NewReader("x"))
			case "corrupt":
				r[key] = bytes.NewReader(bytes.Repeat([]byte("x"), len(data[key])))
			case "read-error":
				calls := 0
				r[key] = observedReader{&calls}
			case "no-progress":
				r[key] = noProgressReader{}
			case "data-with-eof":
				r[key] = finalReader{data[key]}
				want = nil
			case "empty":
				want = nil
			case "multi-buffer":
				want = nil
			case "multi-buffer-extra":
				r[key] = io.MultiReader(bytes.NewReader(data[key]), strings.NewReader("x"))
			}
			if err := Verify(context.Background(), raw, e, r); err != want {
				t.Fatalf("error=%v; want fixed error %v", err, want)
			}
		})
	}
}

type cancelReader struct{ cancel context.CancelFunc }

func (r cancelReader) Read([]byte) (int, error) { r.cancel(); return 0, io.EOF }

func TestBackupManifestCancellation(t *testing.T) {
	m, e, data := fixture()
	raw, e := encode(t, m, e)
	ctx, cancel := context.WithCancel(context.Background())
	r := readers(data)
	r[m.Objects[0].Name] = cancelReader{cancel}
	if err := Verify(ctx, raw, e, r); err != ErrCanceled {
		t.Fatal(err)
	}
	if err := Verify(ctx, raw, e, readers(data)); err != ErrCanceled {
		t.Fatal(err)
	}
	if err := Verify(nil, raw, e, readers(data)); err != ErrCanceled {
		t.Fatal(err)
	}
}
