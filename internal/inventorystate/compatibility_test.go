package inventorystate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"localrmm/internal/inventorywire"
	"os"
	"testing"
)

// The fixture is captured from the unmodified package spool/wire implementation
// at bdb84f4. It pins complete request, receipt, pack and ledger bytes rather than
// only checking that the refactored encoder agrees with its own decoder.
func TestOriginalPackageTransferBytes(t *testing.T) {
	type sample struct {
		Name   string `json:"name"`
		Bytes  int    `json:"bytes"`
		SHA256 string `json:"sha256"`
	}
	var got []sample
	add := func(name string, raw []byte) { got = append(got, sample{name, len(raw), digest(raw)}) }
	for _, n := range []int{0, 1, 129, 513} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			s, _ := newFixture(t)
			prefix := fmt.Sprintf("rows-%d/", n)
			record := func(name string) {
				raw, err := encodeRecord(s.inner.record)
				if err != nil {
					t.Fatal(err)
				}
				add(prefix+name, raw)
			}
			record("idle")
			a := reserve(t, s)
			record("allocated")
			add(prefix+"fallback", s.inner.record.Failure)
			manifest, chunks := payloads(t, a, n)
			if n == 513 {
				manifest = append([]byte(" \n"), manifest...)
				chunks[0] = append(chunks[0], []byte(" \n")...)
			}
			if err := s.Stage(context.Background(), a, manifest, chunks); err != nil {
				t.Fatal(err)
			}
			record("staged")
			add(prefix+"pack", s.inner.pack.raw)
			status, err := s.StatusWork()
			if err != nil {
				t.Fatal(err)
			}
			add(prefix+"status", status.Body())
			abort, err := inventorywire.EncodeMessage("abort", a.Sequence, a.GenerationID, s.inner.record.ManifestHash, struct{}{})
			if err != nil {
				t.Fatal(err)
			}
			add(prefix+"abort", abort)
			for i := 0; ; i++ {
				w := next(t, s)
				add(fmt.Sprintf("%srequest-%d-%s", prefix, i, w.Operation), w.Body())
				ack := receipt(t, w)
				add(fmt.Sprintf("%sreceipt-%d-%s", prefix, i, w.Operation), ack)
				if err := s.Acknowledge(w, ack); err != nil {
					t.Fatal(err)
				}
				record(fmt.Sprintf("acknowledged-%d", i))
				if w.Operation == "finalize" {
					break
				}
			}
		})
	}
	raw, _ := json.Marshal(got)
	golden, err := os.ReadFile("testdata/original-package-transfer.json")
	if err != nil {
		t.Fatalf("missing original fixture: %s", raw)
	}
	if !bytes.Equal(bytes.TrimSpace(golden), raw) {
		t.Fatalf("original package bytes changed: %s", raw)
	}
}
