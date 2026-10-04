package fullinventory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/linuxpackages"
	"reflect"
	"strings"
	"testing"
	"time"
)

func pointer[T any](v T) *T { return &v }
func sourceFixture(n int) SourceInventory {
	s := SourceInventory{GenerationID: "sample_0123456789abcdef0123456789abcdef", CollectedAt: time.Date(2026, 10, 4, 9, 0, 0, 123, time.UTC), DurationMS: 42,
		Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone,
			Fields: linuxpackages.ReleaseFields{ID: pointer("debian"), VersionID: pointer("13"), VersionCodename: pointer("trixie")}},
		Rows: make([]linuxpackages.PackageRow, n)}
	for i := range s.Rows {
		name := fmt.Sprintf("pkg-%06d", i)
		state := "installed"
		if i%7 == 0 {
			state = "incomplete"
		}
		s.Rows[i] = linuxpackages.PackageRow{Name: name, Version: "1:2.0~rc1-1+b1", Architecture: "amd64", SourcePackage: name,
			SourceVersion: "1:2.0~rc1-1+b1", SourceMapping: "binary-default", InstallState: state}
	}
	return s
}
func buildFixture(t *testing.T, n int) (Manifest, []Chunk) {
	t.Helper()
	m, c, err := Build(context.Background(), sourceFixture(n), nil)
	if err != nil {
		t.Fatal(err)
	}
	return m, c
}
func verifyAll(t *testing.T, m Manifest, chunks []Chunk) Complete {
	t.Helper()
	v, err := NewValidator(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range chunks {
		if err := v.Add(c); err != nil {
			t.Fatal(err)
		}
	}
	complete, err := v.Finish()
	if err != nil || !complete.Valid() {
		t.Fatalf("incomplete: %v", err)
	}
	return complete
}
func cloneChunk(c Chunk) Chunk { c.Items = append([]linuxpackages.PackageRow{}, c.Items...); return c }
func rehash(c *Chunk)          { c.SHA256 = chunkDigest(*c) }

func TestCompleteBeyondLegacyPrefixPreservesFullSource(t *testing.T) {
	s := sourceFixture(513)
	for i, j := 0, len(s.Rows)-1; i < j; i, j = i+1, j-1 {
		s.Rows[i], s.Rows[j] = s.Rows[j], s.Rows[i]
	}
	before, _ := json.Marshal(s)
	m, chunks, err := Build(context.Background(), s, nil)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(s)
	if !bytes.Equal(before, after) {
		t.Fatal("mutated source")
	}
	if m.ObservedCount != 513 || m.ChunkCount != 5 || m.CollectedAt != s.CollectedAt || m.DurationMS != s.DurationMS {
		t.Fatal("source facts lost")
	}
	if len(chunks[0].Items) != MaxChunkRows || len(chunks[len(chunks)-1].Items) != 1 {
		t.Fatal("wrong chunk limits")
	}
	if chunks[len(chunks)-1].Items[0].Name != "pkg-000512" {
		t.Fatal("exported global prefix")
	}
	m2, c2, err := Build(context.Background(), sourceFixture(513), nil)
	if err != nil || !reflect.DeepEqual(m, m2) || !reflect.DeepEqual(chunks, c2) {
		t.Fatal("unstable ordering")
	}
	complete := verifyAll(t, m, chunks)
	if complete.Manifest().ObservedCount != 513 {
		t.Fatal("lost full receipt")
	}
	s.Rows[0].Version = "9"
	*s.Release.Fields.ID = "changed"
	if chunks[len(chunks)-1].Items[0].Version == "9" || *m.Release.Fields.ID != "debian" {
		t.Fatal("source alias")
	}
	returned := complete.Manifest()
	*returned.Release.Fields.ID = "changed"
	if *complete.Manifest().Release.Fields.ID != "debian" {
		t.Fatal("receipt alias")
	}
	if (Complete{}).Valid() {
		t.Fatal("zero receipt valid")
	}
}
func TestFullSupportedRowCeiling(t *testing.T) {
	if testing.Short() {
		t.Skip("full 100,000-row budget boundary")
	}
	m, chunks := buildFixture(t, MaxGenerationRows)
	if m.ObservedCount != MaxGenerationRows || chunks[len(chunks)-1].Items[len(chunks[len(chunks)-1].Items)-1].Name != "pkg-099999" {
		t.Fatal("lost supported tail")
	}
	verifyAll(t, m, chunks)
}
func TestEmptyGenerationAndIndependentRelease(t *testing.T) {
	for _, release := range []linuxpackages.ReleaseObservation{
		sourceFixture(0).Release,
		{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing},
		{Quality: linuxpackages.Denied, Reason: linuxpackages.ReasonPermissionDenied},
	} {
		for _, n := range []int{0, 1} {
			s := sourceFixture(n)
			s.Release = release
			m, c, err := Build(context.Background(), s, nil)
			if err != nil {
				t.Fatal(err)
			}
			verifyAll(t, m, c)
			if n == 0 {
				expected := sha256.Sum256([]byte(rowDomain))
				if m.ChunkCount != 0 || len(c) != 0 || c == nil || m.CanonicalRowBytes != 0 || m.RowsSHA256 != hex.EncodeToString(expected[:]) {
					t.Fatal("noncanonical empty source")
				}
			}
		}
	}
}
func TestBuildFailureNeverReturnsPrefix(t *testing.T) {
	cases := map[string]func(*SourceInventory) error{
		"missing rows":                 func(s *SourceInventory) error { s.Rows = nil; return nil },
		"read failed with prefix":      func(s *SourceInventory) error { return errors.New("private failure") },
		"source changed":               func(s *SourceInventory) error { return errors.New("source_changed") },
		"duplicate":                    func(s *SourceInventory) error { s.Rows[1] = s.Rows[0]; return nil },
		"invalid row":                  func(s *SourceInventory) error { s.Rows[0].Version = "not-a-version"; return nil },
		"invalid metadata":             func(s *SourceInventory) error { s.CollectedAt = time.Time{}; return nil },
		"release inconsistent quality": func(s *SourceInventory) error { s.Release.Quality = linuxpackages.Unknown; return nil },
		"too many rows": func(s *SourceInventory) error {
			s.Rows = make([]linuxpackages.PackageRow, MaxGenerationRows+1)
			return nil
		},
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			s := sourceFixture(2)
			sourceErr := modify(&s)
			m, c, err := Build(context.Background(), s, sourceErr)
			if err == nil || !reflect.DeepEqual(m, Manifest{}) || c != nil {
				t.Fatalf("partial result: %v", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if m, c, err := Build(ctx, sourceFixture(2), nil); err != ErrCanceled || c != nil || !reflect.DeepEqual(m, Manifest{}) {
		t.Fatal("canceled prefix")
	}
}
func largeSource(n int) SourceInventory {
	s := sourceFixture(n)
	for i := range s.Rows {
		p := &s.Rows[i]
		p.Name = fmt.Sprintf("%s%06d", strings.Repeat("a", 250), i)
		p.SourcePackage = p.Name
		p.Version = "1" + strings.Repeat("a", 511)
		p.SourceVersion = p.Version
		p.Architecture = "a" + strings.Repeat("b", 63)
	}
	return s
}
func TestDynamicByteSplitAndWholeGenerationLimit(t *testing.T) {
	m, c, err := Build(context.Background(), largeSource(128), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c) < 2 || len(c[0].Items) >= 128 {
		t.Fatal("missing dynamic byte split")
	}
	for _, chunk := range c {
		b, _ := json.Marshal(chunk)
		if len(b) > MaxChunkBytes {
			t.Fatal("chunk over cap")
		}
	}
	verifyAll(t, m, c)
	m, c, err = Build(context.Background(), largeSource(20000), nil)
	if err != ErrLimit || c != nil || !reflect.DeepEqual(m, Manifest{}) {
		t.Fatal("over-budget prefix escaped")
	}
}
func TestMultiarchitectureAndRowValidatorParity(t *testing.T) {
	s := sourceFixture(2)
	s.Rows[1] = s.Rows[0]
	s.Rows[0].Architecture = "arm64"
	s.Rows[1].Architecture = "amd64"
	m, c, err := Build(context.Background(), s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c[0].Items[0].Architecture != "amd64" || c[0].Items[1].Architecture != "arm64" {
		t.Fatal("architecture ordering")
	}
	verifyAll(t, m, c)
	changes := map[string]func(*linuxpackages.PackageRow){
		"source default": func(p *linuxpackages.PackageRow) { p.SourceVersion = "3" },
		"wildcard":       func(p *linuxpackages.PackageRow) { p.Architecture = "linux-any" },
		"state":          func(p *linuxpackages.PackageRow) { p.InstallState = "removed" },
		"mapping":        func(p *linuxpackages.PackageRow) { p.SourceMapping = "trusted" },
		"name":           func(p *linuxpackages.PackageRow) { p.Name = "a" },
		"source name":    func(p *linuxpackages.PackageRow) { p.SourcePackage = "A!" },
		"version":        func(p *linuxpackages.PackageRow) { p.Version = strings.Repeat("1", 513) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			p := sourceFixture(1).Rows[0]
			change(&p)
			if ValidateRow(p) == nil {
				t.Fatal("new grammar diverged")
			}
		})
	}
}
func TestValidatorRejectsCrossChunkTamperingAndPoison(t *testing.T) {
	m, chunks := buildFixture(t, 300)
	changes := map[string]func(*Chunk){
		"duplicate at boundary": func(c *Chunk) { c.Items[0] = chunks[0].Items[len(chunks[0].Items)-1] },
		"order at boundary":     func(c *Chunk) { c.Items[0] = chunks[0].Items[0] },
		"ordinal":               func(c *Chunk) { c.Ordinal++ },
		"offset":                func(c *Chunk) { c.RowOffset++ },
		"count":                 func(c *Chunk) { c.ChunkCount++ },
		"previous":              func(c *Chunk) { c.PreviousSHA256 = strings.Repeat("0", 64) },
		"manifest":              func(c *Chunk) { c.ManifestSHA256 = strings.Repeat("0", 64) },
		"generation":            func(c *Chunk) { c.GenerationID = "sample_ffffffffffffffffffffffffffffffff" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			v, _ := NewValidator(context.Background(), m)
			if err := v.Add(chunks[0]); err != nil {
				t.Fatal(err)
			}
			bad := cloneChunk(chunks[1])
			change(&bad)
			rehash(&bad)
			if v.Add(bad) == nil {
				t.Fatal("accepted bad boundary")
			}
			if v.Add(chunks[1]) == nil {
				t.Fatal("error was not terminal")
			}
			if got, err := v.Finish(); err == nil || got.Valid() {
				t.Fatal("partial completion")
			}
		})
	}
}
func TestMissingExtraFinalAndDigestMismatch(t *testing.T) {
	m, c := buildFixture(t, 300)
	for _, n := range []int{0, 1, 2} {
		v, _ := NewValidator(context.Background(), m)
		for i := 0; i < n; i++ {
			if err := v.Add(c[i]); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := v.Finish(); err != ErrIncomplete || got.Valid() {
			t.Fatal("missing chunks completed")
		}
	}
	v, _ := NewValidator(context.Background(), m)
	for _, chunk := range c {
		if err := v.Add(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if v.Add(c[len(c)-1]) == nil {
		t.Fatal("accepted extra final chunk")
	}
	if got, err := v.Finish(); err == nil || got.Valid() {
		t.Fatal("extra completed")
	}
	wrong := m
	wrong.RowsSHA256 = strings.Repeat("0", 64)
	md, _ := ManifestDigest(wrong)
	previous := ""
	v, _ = NewValidator(context.Background(), wrong)
	for _, chunk := range c {
		chunk.ManifestSHA256 = md
		chunk.PreviousSHA256 = previous
		rehash(&chunk)
		previous = chunk.SHA256
		if err := v.Add(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := v.Finish(); err != ErrIncomplete || got.Valid() {
		t.Fatal("wrong full hash completed")
	}
}
func TestMetadataBindingCancellationAndMutation(t *testing.T) {
	m, c := buildFixture(t, 300)
	changed := cloneManifest(m)
	changed.CollectedAt = changed.CollectedAt.Add(time.Second)
	v, _ := NewValidator(context.Background(), changed)
	if v.Add(c[0]) == nil {
		t.Fatal("metadata not bound")
	}
	ctx, cancel := context.WithCancel(context.Background())
	v, _ = NewValidator(ctx, m)
	if err := v.Add(c[0]); err != nil {
		t.Fatal(err)
	}
	cancel()
	if v.Add(c[1]) != ErrCanceled {
		t.Fatal("cancellation ignored")
	}
	if got, err := v.Finish(); err != ErrCanceled || got.Valid() {
		t.Fatal("canceled completed")
	}
	v, _ = NewValidator(context.Background(), m)
	*m.Release.Fields.ID = "changed"
	for _, chunk := range c {
		local := cloneChunk(chunk)
		if err := v.Add(local); err != nil {
			t.Fatal(err)
		}
		local.Items[0].Name = "mutated"
	}
	got, err := v.Finish()
	if err != nil || *got.Manifest().Release.Fields.ID != "debian" {
		t.Fatal("input aliased validator")
	}
	if _, err := v.Finish(); err != ErrClosed {
		t.Fatal("completion reused")
	}
}

func TestCopiedValidatorHandlesShareWholeState(t *testing.T) {
	m, chunks := buildFixture(t, 300)
	original, err := NewValidator(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	copied := *original
	if err := original.Add(chunks[0]); err != nil {
		t.Fatal(err)
	}
	p1, _ := original.Progress()
	p2, _ := copied.Progress()
	if p1 != p2 || p2.AcceptedChunks != 1 {
		t.Fatal("copy split counters from hash state")
	}
	if err := copied.Add(chunks[1]); err != nil {
		t.Fatal(err)
	}
	if err := original.Add(chunks[2]); err != nil {
		t.Fatal(err)
	}
	receipt, err := copied.Finish()
	if err != nil || !receipt.Valid() || receipt.Manifest().ObservedCount != 300 {
		t.Fatal("copy corrupted consistent completion", err)
	}
	if got, err := original.Finish(); err != ErrClosed || got.Valid() {
		t.Fatal("copy did not share completion terminal state")
	}
	original, _ = NewValidator(context.Background(), m)
	copied = *original
	if err := copied.Add(chunks[0]); err != nil {
		t.Fatal(err)
	}
	if err := original.Add(chunks[0]); err == nil {
		t.Fatal("copy allowed repeated chunk")
	}
	if err := copied.Add(chunks[1]); err == nil {
		t.Fatal("copy did not share failure terminal state")
	}
	if got, err := copied.Finish(); err == nil || got.Valid() {
		t.Fatal("failed copy completed")
	}
	// Distinct constructors still create independent generations.
	independent, _ := NewValidator(context.Background(), m)
	for _, chunk := range chunks {
		if err := independent.Add(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := independent.Finish(); err != nil || !got.Valid() {
		t.Fatal("independent validator contaminated")
	}
}
