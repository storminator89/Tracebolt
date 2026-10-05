package fullinventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"localrmm/internal/linuxpackages"
	"os"
	"strings"
	"testing"
)

// Vectors captured from the unchanged 424bff2 builder before extraction. These
// synthetic cases pin exact canonical manifest and chunk bytes, not just totals.
type originalWireVector struct {
	Name           string `json:"name"`
	SHA256         string `json:"sha256"`
	ManifestSHA256 string `json:"manifestSha256"`
	Bytes          int    `json:"bytes"`
	ChunkRows      []int  `json:"chunkRows"`
}

func originalWireSources() map[string]SourceInventory {
	out := map[string]SourceInventory{"empty": sourceFixture(0), "one": sourceFixture(1), "row-boundary": sourceFixture(128), "boundary-plus-one": sourceFixture(129), "many": sourceFixture(513)}
	reversed := sourceFixture(513)
	for i, j := 0, len(reversed.Rows)-1; i < j; i, j = i+1, j-1 {
		reversed.Rows[i], reversed.Rows[j] = reversed.Rows[j], reversed.Rows[i]
	}
	out["reversed"] = reversed
	long := sourceFixture(129)
	for i := range long.Rows {
		long.Rows[i].Version = "1" + strings.Repeat("a", 511)
		long.Rows[i].SourceVersion = long.Rows[i].Version
	}
	out["byte-boundary"] = long
	unknown := sourceFixture(2)
	unknown.Release = linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}
	out["unknown-release"] = unknown
	denied := sourceFixture(0)
	denied.Release = linuxpackages.ReleaseObservation{Quality: linuxpackages.Denied, Reason: linuxpackages.ReasonPermissionDenied}
	out["denied-release-empty"] = denied
	return out
}
func originalWire(t *testing.T, name string, source SourceInventory) originalWireVector {
	t.Helper()
	m, chunks, e := Build(context.Background(), source, nil)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	wire := append(raw, '\n')
	counts := []int{}
	for _, c := range chunks {
		b, _ := json.Marshal(c)
		wire = append(wire, b...)
		wire = append(wire, '\n')
		counts = append(counts, len(c.Items))
	}
	hash := sha256.Sum256(wire)
	md, e := ManifestDigest(m)
	if e != nil {
		t.Fatal(e)
	}
	return originalWireVector{name, hex.EncodeToString(hash[:]), md, len(wire), counts}
}
func TestOriginal424WireBytesRemainUnchanged(t *testing.T) {
	raw, e := os.ReadFile("testdata/original-424-wire-sha256.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors []originalWireVector
	if e = json.Unmarshal(raw, &vectors); e != nil {
		t.Fatal(e)
	}
	sources := originalWireSources()
	if len(vectors) != len(sources) {
		t.Fatal("missing pinned case")
	}
	for _, want := range vectors {
		t.Run(want.Name, func(t *testing.T) {
			source, ok := sources[want.Name]
			if !ok {
				t.Fatal("unknown case")
			}
			got := originalWire(t, want.Name, source)
			a, _ := json.Marshal(got)
			b, _ := json.Marshal(want)
			if string(a) != string(b) {
				t.Fatalf("old canonical wire changed\nwant %s\ngot %s", b, a)
			}
		})
	}
}
