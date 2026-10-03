package assessment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func provenanceFor(data []byte) SourceSnapshot {
	hash := sha256.Sum256(data)
	return SourceSnapshot{ID: "synthetic-pinned-001", Provider: "debian-security-tracker", Kind: "advisory", SHA256: hex.EncodeToString(hash[:]), Trust: "synthetic_fixture", Synthetic: true, FetchedAt: testNow(), ValidatedAt: testNow(), ExpiresAt: testNow().Add(time.Hour)}
}
func TestSnapshotStrictBoundsAndFields(t *testing.T) {
	original, err := os.ReadFile("testdata/debian-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"duplicate key":           []byte(strings.Replace(string(original), `"schema":`, `"schema":"ambiguous","schema":`, 1)),
		"case duplicate":          []byte(strings.Replace(string(original), `"schema":`, `"Schema":"ambiguous","schema":`, 1)),
		"unknown field":           []byte(strings.Replace(string(original), `"schema":`, `"downloadUrl":"http://127.0.0.1/private","schema":`, 1)),
		"unsupported schema":      bytes.Replace(original, []byte(DebianSnapshotSchema), []byte("debian-tracker-normalized-9"), 1),
		"invalid utf8":            append(append([]byte(nil), original...), 0xff),
		"trailing document":       append(append([]byte(nil), original...), []byte("{}")...),
		"oversize":                bytes.Repeat([]byte(" "), MaxSnapshotBytes+1),
		"xml entity is not json":  []byte(`<!DOCTYPE x [<!ENTITY ext SYSTEM "file:///etc/passwd">]><x>&ext;</x>`),
		"oversize value":          bytes.Replace(original, []byte("1:2.0-1+deb13u2"), []byte(strings.Repeat("1", maxIdentityLength+1)), 1),
		"null rules":              []byte(`{"schema":"debian-tracker-normalized-1","synthetic":true,"coveredSources":["fixture"],"rules":null}`),
		"missing rules":           []byte(`{"schema":"debian-tracker-normalized-1","synthetic":true,"coveredSources":["fixture"]}`),
		"empty coverage":          []byte(`{"schema":"debian-tracker-normalized-1","synthetic":true,"coveredSources":[],"rules":[]}`),
		"invalid fix":             bytes.Replace(original, []byte("1:2.0-1+deb13u2"), []byte("bad fix"), 1),
		"self-attested authority": []byte(strings.Replace(string(original), `"schema":`, `"trust":"vendor_signature_verified","schema":`, 1)),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			snapshot, err := ParseDebianSnapshot(bytes.NewReader(data), provenanceFor(data))
			if err == nil || snapshot != nil {
				t.Fatal("malformed snapshot promoted")
			}
			if strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), "passwd") {
				t.Fatal("raw malicious input leaked")
			}
		})
	}
}
func TestSnapshotDigestOriginAndDuplicateRecords(t *testing.T) {
	data, err := os.ReadFile("testdata/debian-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	source := provenanceFor(data)
	source.SHA256 = strings.Repeat("0", 64)
	if _, err := ParseDebianSnapshot(bytes.NewReader(data), source); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	for _, url := range []string{"http://security-tracker.debian.org/tracker/data/json", "https://attacker.invalid/feed", "https://user:password@security-tracker.debian.org/tracker/data/json", "file:///etc/passwd", "https://security-tracker.debian.org/tracker/data/json?inventory=secret"} {
		source := provenanceFor(data)
		source.PublicURL = url
		if _, err := ParseDebianSnapshot(bytes.NewReader(data), source); err == nil {
			t.Fatal("unapproved/secret-bearing source URL accepted")
		}
	}
	doc := fixtureDocument(t)
	doc.Rules = append(doc.Rules, doc.Rules[0])
	duplicates, _ := json.Marshal(doc)
	if _, err := ParseDebianSnapshot(bytes.NewReader(duplicates), provenanceFor(duplicates)); err == nil {
		t.Fatal("duplicate rule identity accepted")
	}
	doc = fixtureDocument(t)
	doc.CoveredSources = append(doc.CoveredSources, doc.CoveredSources[0])
	duplicates, _ = json.Marshal(doc)
	if _, err := ParseDebianSnapshot(bytes.NewReader(duplicates), provenanceFor(duplicates)); err == nil {
		t.Fatal("duplicate coverage accepted")
	}
	source = provenanceFor(data)
	source.Synthetic = false
	source.Trust = "https_origin_only"
	if _, err := ParseDebianSnapshot(bytes.NewReader(data), source); err == nil {
		t.Fatal("fixture relabeled as vendor data")
	}
}
func TestSnapshotJSONDepthAndArrayBounds(t *testing.T) {
	depth := []byte(strings.Repeat("[", 18) + "null" + strings.Repeat("]", 18))
	if err := validateJSONShape(depth); err == nil {
		t.Fatal("unbounded nesting accepted")
	}
	array := []byte("[" + strings.Repeat("null,", MaxSnapshotRules) + "null]")
	if err := validateJSONShape(array); err == nil {
		t.Fatal("unbounded array accepted")
	}
}
func FuzzSnapshotRejectsSafely(f *testing.F) {
	data, err := os.ReadFile("testdata/debian-synthetic.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte(`{"schema":"wrong"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		snapshot, err := ParseDebianSnapshot(bytes.NewReader(data), provenanceFor(data))
		if err != nil && snapshot != nil {
			t.Fatal("invalid snapshot retained")
		}
	})
}
