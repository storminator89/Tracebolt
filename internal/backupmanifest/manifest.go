// Package backupmanifest verifies a finite, offline backup inventory and its
// byte integrity. It never opens paths/databases, copies state, changes
// quarantine or establishes authority freshness. No runtime uses it yet.
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
	"unicode/utf8"
)

const (
	SchemaVersion    = "tracebolt.manager-backup-manifest.v1"
	CaptureMode      = "stopped-writers-offline-v1"
	MaxManifestBytes = 256 * 1024
	MaxObjects       = 1024
	MaxDatabases     = 32
	MaxObjectBytes   = int64(64 << 30)
	MaxTotalBytes    = int64(256 << 30)
)

// Errors are fixed diagnostics; no names, hashes, raw bytes or reader errors
// escape. None of these results authorizes a restore or quarantine release.
var (
	ErrManifest  = errors.New("backup manifest invalid")
	ErrBinding   = errors.New("backup binding mismatch")
	ErrInventory = errors.New("backup inventory mismatch")
	ErrIntegrity = errors.New("backup integrity unverified")
	ErrCanceled  = errors.New("backup verification canceled")
)

// Binding must come independently from the approved recovery plan, not from the
// untrusted backup. The capture adapter must derive these declarations from the
// exact selected artifact/config/issuer/instance bytes. Verify compares them; it
// does not derive their semantic association with object streams or prove that
// historical authority is still current.
type Binding struct {
	BuildSHA256    string `json:"buildSha256"`
	ConfigSHA256   string `json:"configSha256"`
	IssuerSHA256   string `json:"issuerSha256"`
	InstanceSHA256 string `json:"instanceSha256"`
	Profile        string `json:"profile"`
	RuntimeUID     uint32 `json:"runtimeUid"`
	RuntimeGID     uint32 `json:"runtimeGid"`
}

// Names are logical object keys, never filesystem paths. Each database must
// explicitly inventory all three possible SQLite sidecars, including absence.
// Schema is an exact, independently expected schema identifier; it is not read
// from or checked against SQLite by this package.
type Database struct {
	Name    string `json:"name"`
	Schema  string `json:"schema"`
	WAL     bool   `json:"wal"`
	SHM     bool   `json:"shm"`
	Journal bool   `json:"journal"`
}

type ObjectSpec struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type Object struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	SchemaVersion string     `json:"schemaVersion"`
	CaptureMode   string     `json:"captureMode"`
	Binding       Binding    `json:"binding"`
	Databases     []Database `json:"databases"`
	Objects       []Object   `json:"objects"`
}

// Expected is a trusted, independently inventoried capture receipt. Its digest
// must not be read from the same untrusted backup as raw. A genuine old receipt
// can still verify an old snapshot: it is never a freshness anchor. The caller
// must account for every configured external ledger, custody/configuration and
// secret object; this package cannot discover omissions in that trusted plan.
type Expected struct {
	ManifestSHA256 string
	Binding        Binding
	Databases      []Database
	Objects        []ObjectSpec
}

// Verify checks an exact closed roster of read-only streams. It returns nil for
// integrity ONLY; it does not certify atomic capture, SQL validity, permissions,
// schema compatibility, authentic receipt custody or current authority. Streams
// are neither closed nor retained. Callers must bound blocking reads themselves;
// context is checked between reads, but cannot interrupt an arbitrary io.Reader.
func Verify(ctx context.Context, raw []byte, expected Expected, objects map[string]io.Reader) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrCanceled
	}
	if len(raw) == 0 || len(raw) > MaxManifestBytes || !digest(expected.ManifestSHA256) {
		return ErrManifest
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != expected.ManifestSHA256 {
		return ErrIntegrity
	}
	m, err := decode(raw)
	if err != nil {
		return err
	}
	if !validBinding(m.Binding) || !validBinding(expected.Binding) || m.Binding != expected.Binding {
		return ErrBinding
	}
	if len(m.Databases) == 0 || len(m.Databases) > MaxDatabases || len(expected.Databases) != len(m.Databases) ||
		len(m.Objects) == 0 || len(m.Objects) > MaxObjects || len(expected.Objects) != len(m.Objects) || len(objects) != len(m.Objects) {
		return ErrInventory
	}
	want := make(map[string]string, len(expected.Objects))
	for _, o := range expected.Objects {
		if !key(o.Name) || !kind(o.Kind) || want[o.Name] != "" {
			return ErrInventory
		}
		want[o.Name] = o.Kind
	}
	files := make(map[string]Object, len(m.Objects))
	var total int64
	for _, o := range m.Objects {
		if !key(o.Name) || !kind(o.Kind) || want[o.Name] != o.Kind || files[o.Name].Kind != "" ||
			o.Size < 0 || o.Size > MaxObjectBytes || o.Size > MaxTotalBytes-total || !digest(o.SHA256) || objects[o.Name] == nil {
			return ErrInventory
		}
		files[o.Name] = o
		total += o.Size
	}
	wantDB := make(map[string]Database, len(expected.Databases))
	for _, db := range expected.Databases {
		if !key(db.Name) || !label(db.Schema) || wantDB[db.Name].Name != "" {
			return ErrInventory
		}
		wantDB[db.Name] = db
	}
	linked := make(map[string]bool)
	for _, db := range m.Databases {
		if !key(db.Name) || !label(db.Schema) || wantDB[db.Name] != db || linked[db.Name] || files[db.Name].Kind != "database" {
			return ErrInventory
		}
		linked[db.Name] = true
		for suffix, present := range map[string]bool{"-wal": db.WAL, "-shm": db.SHM, "-journal": db.Journal} {
			name := db.Name + suffix
			o, exists := files[name]
			if present != exists || exists && (o.Kind != "sidecar" || linked[name]) {
				return ErrInventory
			}
			linked[name] = exists
		}
	}
	for _, o := range m.Objects {
		if (o.Kind == "database" || o.Kind == "sidecar" || strings.HasSuffix(o.Name, "-wal") || strings.HasSuffix(o.Name, "-shm") || strings.HasSuffix(o.Name, "-journal")) && !linked[o.Name] {
			return ErrInventory
		}
	}
	// All binding/roster checks finish before any stream is consumed.
	buffer := make([]byte, 32*1024)
	for _, o := range m.Objects {
		if err := verifyObject(ctx, objects[o.Name], o, buffer); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return ErrCanceled
	}
	return nil
}

func verifyObject(ctx context.Context, r io.Reader, o Object, buffer []byte) error {
	h := sha256.New()
	var size int64
	empty := 0
	for {
		if ctx.Err() != nil {
			return ErrCanceled
		}
		limit := min(int64(len(buffer)), o.Size-size+1)
		n, err := r.Read(buffer[:int(limit)])
		if ctx.Err() != nil {
			return ErrCanceled
		}
		if n < 0 || n > int(limit) || int64(n) > o.Size-size {
			return ErrIntegrity
		}
		if n > 0 {
			_, _ = h.Write(buffer[:n])
			size += int64(n)
			empty = 0
		} else {
			empty++
		}
		if err == io.EOF {
			if size != o.Size || hex.EncodeToString(h.Sum(nil)) != o.SHA256 {
				return ErrIntegrity
			}
			return nil
		}
		if err != nil || empty >= 100 {
			return ErrIntegrity
		}
	}
}

func decode(raw []byte) (Manifest, error) {
	var m Manifest
	fields, ok := object(raw, "schemaVersion", "captureMode", "binding", "databases", "objects")
	if !ok || json.Unmarshal(raw, &m) != nil || m.SchemaVersion != SchemaVersion || m.CaptureMode != CaptureMode {
		return Manifest{}, ErrManifest
	}
	if _, ok = object(fields["binding"], "buildSha256", "configSha256", "issuerSha256", "instanceSha256", "profile", "runtimeUid", "runtimeGid"); !ok {
		return Manifest{}, ErrManifest
	}
	for name, keys := range map[string][]string{
		"databases": {"name", "schema", "wal", "shm", "journal"},
		"objects":   {"name", "kind", "size", "sha256"},
	} {
		var rows []json.RawMessage
		if json.Unmarshal(fields[name], &rows) != nil || len(rows) > MaxObjects {
			return Manifest{}, ErrManifest
		}
		for _, row := range rows {
			if _, ok = object(row, keys...); !ok {
				return Manifest{}, ErrManifest
			}
		}
	}
	return m, nil
}

// object rejects aliases, unknown/missing/duplicate keys and null at every
// object level. Raw input is already bounded, and object nesting is fixed.
func object(raw []byte, keys ...string) (map[string]json.RawMessage, bool) {
	if !utf8.Valid(raw) || bytes.ContainsRune(raw, '\ufffd') {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, false
	}
	allowed := make(map[string]bool, len(keys))
	for _, k := range keys {
		allowed[k] = true
	}
	fields := make(map[string]json.RawMessage, len(keys))
	for d.More() {
		t, err = d.Token()
		k, ok := t.(string)
		if err != nil || !ok || !allowed[k] || fields[k] != nil {
			return nil, false
		}
		var v json.RawMessage
		if d.Decode(&v) != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return nil, false
		}
		fields[k] = v
	}
	if _, err = d.Token(); err != nil || len(fields) != len(keys) {
		return nil, false
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, false
	}
	return fields, true
}

func validBinding(b Binding) bool {
	return digest(b.BuildSHA256) && digest(b.ConfigSHA256) && digest(b.IssuerSHA256) && digest(b.InstanceSHA256) &&
		(b.Profile == "tls" || b.Profile == "http-test") && b.RuntimeUID != 0
}

func digest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func kind(s string) bool {
	return s == "database" || s == "sidecar" || s == "state" || s == "configuration" || s == "credential"
}

func key(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if !label(part) || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func label(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
