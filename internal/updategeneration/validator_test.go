package updategeneration

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestValidatorRejectsReorderReplayAndWrongLinkage(t *testing.T) {
	m, chunks := built(t, 400)
	for name, mutate := range map[string]func(*Chunk){
		"generation": func(c *Chunk) { c.GenerationID = "sample_ffffffffffffffffffffffffffffffff" },
		"manifest":   func(c *Chunk) { c.ManifestSHA256 = strings.Repeat("1", 64) },
		"ordinal":    func(c *Chunk) { c.Ordinal++ },
		"count":      func(c *Chunk) { c.ChunkCount++ },
		"offset":     func(c *Chunk) { c.RowOffset++ },
		"previous":   func(c *Chunk) { c.PreviousSHA256 = strings.Repeat("2", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			v, _ := NewValidator(context.Background(), m)
			if err := v.Add(chunks[0]); err != nil {
				t.Fatal(err)
			}
			c := chunks[1]
			mutate(&c)
			c.SHA256 = chunkDigest(c)
			if err := v.Add(c); err == nil {
				t.Fatal("bad linkage accepted")
			}
			if err := v.Add(chunks[1]); err == nil {
				t.Fatal("terminal failure recovered implicitly")
			}
			if proof, err := v.Finish(); err == nil || proof.Valid() {
				t.Fatal("invalid generation completed")
			}
		})
	}
	for name, sequence := range map[string][]Chunk{"reordered": {chunks[1], chunks[0]}, "replayed": {chunks[0], chunks[0]}} {
		t.Run(name, func(t *testing.T) {
			v, _ := NewValidator(context.Background(), m)
			failed := false
			for _, c := range sequence {
				if v.Add(c) != nil {
					failed = true
					break
				}
			}
			if !failed {
				t.Fatal("reorder/replay accepted")
			}
		})
	}
}
func TestChunkRejectsReorderedRowsDuplicateRowsAndHashMutation(t *testing.T) {
	_, chunks := built(t, 400)
	for name, mutate := range map[string]func(*Chunk){
		"reordered":         func(c *Chunk) { c.Items[0], c.Items[1] = c.Items[1], c.Items[0] },
		"duplicate":         func(c *Chunk) { c.Items[1] = c.Items[0] },
		"not-newer":         func(c *Chunk) { c.Items[1].CandidateVersion = c.Items[1].InstalledVersion },
		"unsupported-state": func(c *Chunk) { c.Items[1].State = "installable" },
		"installability":    func(c *Chunk) { c.Items[1].Installability = "confirmed" },
		"unescaped-name":    func(c *Chunk) { c.Items[1].Name = "pkg\nsecret" },
	} {
		t.Run(name, func(t *testing.T) {
			c := chunks[0]
			c.Items = append(c.Items[:0:0], c.Items...)
			mutate(&c)
			c.SHA256 = chunkDigest(c)
			if ValidateChunk(c) == nil {
				t.Fatal("invalid canonical row accepted")
			}
		})
	}
	c := chunks[0]
	c.SHA256 = strings.Repeat("0", 64)
	if ValidateChunk(c) == nil {
		t.Fatal("wrong self hash accepted")
	}
}
func TestValidatorRejectsIncompleteRowsAndWrongFinalDigest(t *testing.T) {
	m, chunks := built(t, 400)
	for _, prefix := range []int{0, 1, len(chunks) - 1} {
		v, _ := NewValidator(context.Background(), m)
		for _, c := range chunks[:prefix] {
			if err := v.Add(c); err != nil {
				t.Fatal(err)
			}
		}
		if proof, err := v.Finish(); !errors.Is(err, ErrIncomplete) || proof.Valid() {
			t.Fatal("prefix completed", prefix, err)
		}
		if err := v.Add(chunks[prefix]); !errors.Is(err, ErrIncomplete) {
			t.Fatal("premature finish not terminal", err)
		}
	}
	wrong := m
	wrong.RowsSHA256 = strings.Repeat("a", 64)
	md, err := ManifestDigest(wrong)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := NewValidator(context.Background(), wrong)
	previous := ""
	for _, original := range chunks {
		c := original
		c.ManifestSHA256 = md
		c.PreviousSHA256 = previous
		c.SHA256 = chunkDigest(c)
		if err := v.Add(c); err != nil {
			t.Fatal(err)
		}
		previous = c.SHA256
	}
	if proof, err := v.Finish(); !errors.Is(err, ErrIncomplete) || proof.Valid() {
		t.Fatal("forged final row digest completed", err)
	}
}
func TestManifestBindsOriginalMetadataAndCounts(t *testing.T) {
	m, chunks := built(t, 400)
	for name, mutate := range map[string]func(*Manifest){
		"time":     func(m *Manifest) { m.CollectedAt = m.CollectedAt.Add(1000000000); *m.Metadata.AgeSeconds++ },
		"duration": func(m *Manifest) { m.DurationMS++ },
		"release": func(m *Manifest) {
			id, version, code := "ubuntu", "24.04", "noble"
			m.Release.ID = &id
			m.Release.VersionID = &version
			m.Release.VersionCodename = &code
		},
		"held": func(m *Manifest) { m.HeldCount++ },
		"unknown": func(m *Manifest) {
			m.UnknownCount++
			m.CheckedCount--
			m.ComparisonCoverage = "partial"
			m.ComparisonReason = "candidate_unknown"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneManifest(m)
			mutate(&changed)
			if ValidateManifest(changed) != nil {
				t.Fatal("invalid changed fixture")
			}
			v, err := NewValidator(context.Background(), changed)
			if err != nil {
				t.Fatal(err)
			}
			if v.Add(chunks[0]) == nil {
				t.Fatal("chunk not bound to original metadata")
			}
		})
	}
	for name, mutate := range map[string]func(*Manifest){
		"missing-cache-age": func(m *Manifest) { m.Metadata.AgeSeconds = nil },
		"false-freshness":   func(m *Manifest) { m.Metadata.Freshness = "fresh" },
		"wrapped-counts":    func(m *Manifest) { m.CheckedCount = ^uint32(0); m.UnknownCount = m.InstalledCount + 1 },
		"unknown-complete":  func(m *Manifest) { m.UnknownCount++; m.CheckedCount-- },
		"chunk-limit":       func(m *Manifest) { m.ChunkCount = MaxGenerationChunks + 1 },
		"row-byte-limit":    func(m *Manifest) { m.CanonicalRowBytes = MaxCanonicalRowBytes + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneManifest(m)
			mutate(&changed)
			if ValidateManifest(changed) == nil {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
}
func TestValidatorCancellationAndSharedHandleAreTerminal(t *testing.T) {
	s := sourceFixture(t, 400)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := Build(ctx, s, nil); !errors.Is(err, ErrCanceled) {
		t.Fatal(err)
	}
	if _, _, err := Build(nil, s, nil); !errors.Is(err, ErrCanceled) {
		t.Fatal(err)
	}
	m, chunks := built(t, 400)
	ctx, cancel = context.WithCancel(context.Background())
	v, err := NewValidator(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Add(chunks[0]); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err = v.Add(chunks[1]); !errors.Is(err, ErrCanceled) {
		t.Fatal(err)
	}
	if proof, err := v.Finish(); !errors.Is(err, ErrCanceled) || proof.Valid() {
		t.Fatal("canceled completed", err)
	}
	v, _ = NewValidator(context.Background(), m)
	alias := *v
	if err = v.Add(chunks[0]); err != nil {
		t.Fatal(err)
	}
	if err = alias.Add(chunks[0]); err == nil {
		t.Fatal("copy bypassed sequence progress")
	}
	if err = v.Add(chunks[1]); err == nil {
		t.Fatal("copy did not share terminal failure")
	}
	v, _ = NewValidator(context.Background(), m)
	for _, c := range chunks {
		if err = v.Add(c); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = v.Finish(); err != nil {
		t.Fatal(err)
	}
	if _, err = v.Finish(); !errors.Is(err, ErrClosed) {
		t.Fatal("second finish", err)
	}
	if err = v.Add(chunks[0]); !errors.Is(err, ErrClosed) {
		t.Fatal("completed handle reopened", err)
	}
	var zero Validator
	if zero.Add(chunks[0]) == nil {
		t.Fatal("zero validator")
	}
	if (Complete{}).Valid() {
		t.Fatal("zero receipt valid")
	}
}
