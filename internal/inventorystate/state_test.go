package inventorystate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/fullinventory"
	"localrmm/internal/inventorywire"
	"localrmm/internal/linuxpackages"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const fixtureAgent = "agent_0123456789abcdef0123456789abcdef"

var fixtureBinding = strings.Repeat("3", 64)
var fixtureAt = time.Date(2026, 10, 4, 9, 0, 0, 123, time.UTC)

func newFixture(t *testing.T) (*State, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux private state tests")
	}
	dir := filepath.Join(t.TempDir(), "inventory")
	s, e := InitializeNew(dir, fixtureBinding, fixtureAgent)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}
func reserve(t *testing.T, s *State) Allocation {
	t.Helper()
	a, e := s.Allocate(context.Background(), fixtureAt)
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func ptr(s string) *string { return &s }
func payloads(t *testing.T, a Allocation, n int) ([]byte, [][]byte) {
	t.Helper()
	source := fullinventory.SourceInventory{GenerationID: a.GenerationID, CollectedAt: a.AttemptedAt, DurationMS: 45, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone, Fields: linuxpackages.ReleaseFields{ID: ptr("debian"), VersionID: ptr("13"), VersionCodename: ptr("trixie")}}, Rows: make([]linuxpackages.PackageRow, n)}
	for i := range source.Rows {
		name := fmt.Sprintf("invented-pkg-%06d", i)
		source.Rows[i] = linuxpackages.PackageRow{Name: name, Version: "1:2.0~rc1-1+b1", Architecture: "amd64", SourcePackage: name, SourceVersion: "1:2.0~rc1-1+b1", SourceMapping: "binary-default", InstallState: "installed"}
	}
	m, chunks, e := fullinventory.Build(context.Background(), source, nil)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(m)
	out := make([][]byte, len(chunks))
	for i, c := range chunks {
		out[i], _ = json.Marshal(c)
	}
	return raw, out
}
func receipt(t *testing.T, w Work) []byte {
	t.Helper()
	m, e := inventorywire.DecodeMessage(w.Operation, w.Body())
	if e != nil {
		t.Fatal(e)
	}
	var result any
	switch w.Operation {
	case "begin":
		result = map[string]any{"startedAt": fixtureAt.Add(time.Minute), "expiresAt": fixtureAt.Add(16 * time.Minute)}
	case "append":
		result = map[string]any{"ordinal": m.Chunk.Ordinal, "rows": len(m.Chunk.Items), "receivedAt": fixtureAt.Add(2 * time.Minute)}
	case "finalize":
		result = map[string]any{"collectedAt": fixtureAt, "completedAt": fixtureAt.Add(3 * time.Minute)}
	case "failure":
		result = map[string]any{"attemptedAt": m.FailureAt, "reason": m.FailureReason, "receivedAt": fixtureAt.Add(time.Minute)}
	case "abort":
		result = map[string]any{"aborted": true}
	}
	raw, e := json.Marshal(map[string]any{"schemaVersion": "tracebolt.inventory-response.v1", "operation": w.Operation, "sequence": fmt.Sprint(w.Sequence), "generationId": w.GenerationID, "manifestHash": w.ManifestHash, "requestSha256": w.Digest, "result": result})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func stageFixture(t *testing.T, s *State, n int) Allocation {
	t.Helper()
	a := reserve(t, s)
	m, c := payloads(t, a, n)
	if e := s.Stage(context.Background(), a, m, c); e != nil {
		t.Fatal(e)
	}
	return a
}
func next(t *testing.T, s *State) Work {
	t.Helper()
	w, ok, e := s.NextWork()
	if e != nil || !ok {
		t.Fatalf("next missing: %v", e)
	}
	return w
}
func reopen(t *testing.T, s *State, dir string) *State {
	t.Helper()
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	out, e := OpenExisting(dir, fixtureBinding, fixtureAgent)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { out.Close() })
	return out
}

func TestRestartResumesAllRowsAndExactReceipts(t *testing.T) {
	s, dir := newFixture(t)
	a := reserve(t, s)
	m, c := payloads(t, a, 513)
	// Preserve noncanonical whitespace in the supplied payloads, without changing
	// fullinventory's canonical digest or collection age.
	m = append([]byte(" \n"), m...)
	c[0] = append(c[0], []byte(" \n")...)
	if e := s.Stage(context.Background(), a, m, c); e != nil {
		t.Fatal(e)
	}
	expected := append([][]byte{bytes.Clone(m)}, c...)
	seen := 0
	operations := 0
	for {
		w := next(t, s)
		before := w.Body()
		decoded, e := inventorywire.DecodeMessage(w.Operation, before)
		if e != nil {
			t.Fatal(e)
		}
		if w.Sequence != 1 || w.GenerationID != a.GenerationID {
			t.Fatal("identity changed")
		}
		if w.Operation == "begin" && (!decoded.Manifest.CollectedAt.Equal(fixtureAt) || decoded.Manifest.ObservedCount != 513) {
			t.Fatal("wrong manifest")
		}
		if w.Operation == "append" {
			seen += len(decoded.Chunk.Items)
		}
		if operations < len(expected) && !bytes.Contains(before, expected[operations]) {
			t.Fatal("payload bytes were rewritten")
		}
		s = reopen(t, s, dir)
		retry := next(t, s)
		if !sameWork(w, retry) || !bytes.Equal(before, retry.Body()) {
			t.Fatal("restart changed work")
		}
		ack := receipt(t, w)
		if e = s.Acknowledge(w, ack); e != nil {
			t.Fatal(e)
		}
		s = reopen(t, s, dir)
		if e = s.Acknowledge(w, ack); e != nil {
			t.Fatal("receipt retry rejected", e)
		}
		other := append(bytes.Clone(ack), ' ')
		if e = s.Acknowledge(w, other); !errors.Is(e, ErrAcknowledgment) {
			t.Fatal("changed exact receipt accepted")
		}
		operations++
		if w.Operation == "finalize" {
			break
		}
	}
	if seen != 513 || operations != 7 {
		t.Fatalf("lost rows/ops: %d/%d", seen, operations)
	}
	if _, ok, e := s.NextWork(); e != nil || ok {
		t.Fatal("completed transfer remains")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatal("generation data not cleaned")
	}
	floor, e := s.SequenceFloor()
	if e != nil || floor != 1 {
		t.Fatal("floor lost")
	}
	a2 := reserve(t, s)
	if a2.Sequence != 2 {
		t.Fatal("sequence reused")
	}
}
func TestAllocatedRestartUsesOriginalFixedFailure(t *testing.T) {
	s, dir := newFixture(t)
	a := reserve(t, s)
	s = reopen(t, s, dir)
	w := next(t, s)
	if w.Operation != "failure" || w.Sequence != a.Sequence {
		t.Fatal("interrupted capture was reused")
	}
	m, e := inventorywire.DecodeMessage("failure", w.Body())
	if e != nil || m.FailureReason != "collection_failed" || !m.FailureAt.Equal(a.AttemptedAt) {
		t.Fatal("fallback changed")
	}
	body := w.Body()
	s = reopen(t, s, dir)
	if !bytes.Equal(body, next(t, s).Body()) {
		t.Fatal("fallback bytes changed")
	}
	manifest, chunks := payloads(t, a, 10)
	if e = s.Stage(context.Background(), a, manifest, chunks); !errors.Is(e, ErrPending) {
		t.Fatal("old allocation used after restart")
	}
	if e = s.Acknowledge(w, receipt(t, w)); e != nil {
		t.Fatal(e)
	}
	if reserve(t, s).Sequence != 2 {
		t.Fatal("lost failed floor")
	}
}
func TestFailureZeroRowsAndInvalidStage(t *testing.T) {
	s, _ := newFixture(t)
	a := reserve(t, s)
	m, c := payloads(t, a, 513)
	if e := s.Stage(context.Background(), a, m, c[:len(c)-1]); !errors.Is(e, ErrBody) {
		t.Fatal("prefix staged")
	}
	duplicate := append([][]byte{}, c...)
	duplicate[1] = c[0]
	if e := s.Stage(context.Background(), a, m, duplicate); !errors.Is(e, ErrBody) {
		t.Fatal("duplicate staged")
	}
	if e := s.StageFailure(context.Background(), a, "raw invented metadata"); !errors.Is(e, ErrBody) {
		t.Fatal("arbitrary failure accepted")
	}
	if e := s.StageFailure(context.Background(), a, "source_changed"); e != nil {
		t.Fatal(e)
	}
	w := next(t, s)
	if e := s.Acknowledge(w, receipt(t, w)); e != nil {
		t.Fatal(e)
	}
	a = reserve(t, s)
	m, c = payloads(t, a, 0)
	if e := s.Stage(context.Background(), a, m, c); e != nil {
		t.Fatal(e)
	}
	for _, op := range []string{"begin", "finalize"} {
		w = next(t, s)
		if w.Operation != op {
			t.Fatal("zero-row transfer wrong")
		}
		if e := s.Acknowledge(w, receipt(t, w)); e != nil {
			t.Fatal(e)
		}
	}
}
func TestSnapshotAliasingCopyStateAndInvalidAcknowledgment(t *testing.T) {
	s, _ := newFixture(t)
	stageFixture(t, s, 513)
	copyState := *s
	w := next(t, &copyState)
	original := w.Body()
	mutated := w.Body()
	mutated[0] = 'x'
	if !bytes.Equal(original, next(t, s).Body()) {
		t.Fatal("body alias")
	}
	changed := w
	changed.Digest = strings.Repeat("0", 64)
	if e := s.Acknowledge(changed, receipt(t, w)); !errors.Is(e, ErrAcknowledgment) {
		t.Fatal("wrong digest accepted")
	}
	changed = w
	changed.Operation = "finalize"
	if e := s.Acknowledge(changed, receipt(t, w)); !errors.Is(e, ErrAcknowledgment) {
		t.Fatal("wrong operation accepted")
	}
	if e := s.Acknowledge(Work{}, []byte(`{}`)); !errors.Is(e, ErrAcknowledgment) {
		t.Fatal("zero work accepted")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				if _, ok, e := copyState.NextWork(); e != nil || !ok {
					t.Error("copy read", e)
				}
			}
		}()
	}
	wg.Wait()
	if e := copyState.Acknowledge(w, receipt(t, w)); e != nil {
		t.Fatal(e)
	}
	if next(t, s).Operation != "append" {
		t.Fatal("copy state diverged")
	}
	copyState.Close()
	if _, _, e := s.NextWork(); !errors.Is(e, ErrClosed) {
		t.Fatal("copy close did not close shared state")
	}
}
func TestRedactionAllFormattingVerbsAndJSON(t *testing.T) {
	s, _ := newFixture(t)
	a := stageFixture(t, s, 513)
	w := next(t, s)
	values := []any{s, *s, a, &a, w, &w}
	for _, v := range values {
		for _, verb := range []string{"%s", "%q", "%v", "%+v", "%#v", "%x", "%X", "%d", "%p", "%f"} {
			text := fmt.Sprintf(verb, v)
			for _, secret := range []string{fixtureBinding, fixtureAgent, "invented-pkg", "binary-default", "trixie"} {
				if strings.Contains(text, secret) {
					t.Fatalf("format leaked %s", verb)
				}
			}
		}
		raw, e := json.Marshal(v)
		if e != nil || !bytes.Equal(raw, []byte(`{"contentsRedacted":true}`)) {
			t.Fatal("JSON leaked")
		}
	}
}
func TestCancellationAndPublicLimits(t *testing.T) {
	s, _ := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := s.Allocate(ctx, fixtureAt); !errors.Is(e, ErrCanceled) {
		t.Fatal("canceled allocate")
	}
	floor, _ := s.SequenceFloor()
	if floor != 0 {
		t.Fatal("canceled allocation used floor")
	}
	a := reserve(t, s)
	m, c := payloads(t, a, 513)
	if e := s.Stage(ctx, a, m, c); !errors.Is(e, ErrCanceled) {
		t.Fatal("canceled stage")
	}
	if e := s.StageFailure(ctx, a, "collection_failed"); !errors.Is(e, ErrCanceled) {
		t.Fatal("canceled failure")
	}
	if e := s.Stage(context.Background(), a, bytes.Repeat([]byte(" "), fullinventory.MaxManifestBytes+1), nil); !errors.Is(e, ErrBody) {
		t.Fatal("large manifest accepted")
	}
	oversized := [][]byte{bytes.Repeat([]byte(" "), fullinventory.MaxChunkBytes+1)}
	if e := s.Stage(context.Background(), a, m, oversized); !errors.Is(e, ErrBody) {
		t.Fatal("large chunk accepted")
	}
	if e := s.Stage(context.Background(), a, m, make([][]byte, fullinventory.MaxGenerationChunks+1)); !errors.Is(e, ErrBody) {
		t.Fatal("extra chunks accepted")
	}
	if e := s.Stage(context.Background(), a, m, c); e != nil {
		t.Fatal("canceled/invalid validation blocked safe stage", e)
	}
}
func TestAbortRetainsGenerationUntilAcknowledged(t *testing.T) {
	s, dir := newFixture(t)
	stageFixture(t, s, 513)
	first := next(t, s)
	status, e := s.StatusWork()
	if e != nil || status.Operation != "status" || status.GenerationID != first.GenerationID || status.ManifestHash != first.ManifestHash {
		t.Fatal("status binding")
	}
	if e = s.RequestAbort(); e != nil {
		t.Fatal(e)
	}
	s = reopen(t, s, dir)
	w := next(t, s)
	if w.Operation != "abort" || w.Sequence != first.Sequence || w.GenerationID != first.GenerationID || w.ManifestHash != first.ManifestHash {
		t.Fatal("abort rebinding")
	}
	if _, e = os.Stat(filepath.Join(dir, "generation.pack")); e != nil {
		t.Fatal("abort dropped pending bytes")
	}
	if e = s.Acknowledge(w, receipt(t, w)); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(dir, "generation.pack")); !os.IsNotExist(e) {
		t.Fatal("acknowledged abort retained generation")
	}
	s = reopen(t, s, dir)
	if e = s.Acknowledge(w, receipt(t, w)); e != nil {
		t.Fatal("abort receipt retry", e)
	}
	if reserve(t, s).Sequence != 2 {
		t.Fatal("abort floor reused")
	}
}

func TestCollectionTimestampCannotBeRefreshed(t *testing.T) {
	s, _ := newFixture(t)
	a := reserve(t, s)
	changed := a
	changed.AttemptedAt = changed.AttemptedAt.Add(time.Second)
	m, c := payloads(t, changed, 513)
	if e := s.Stage(context.Background(), a, m, c); !errors.Is(e, ErrBody) {
		t.Fatal("manifest collection age replaced", e)
	}
	if e := s.Stage(context.Background(), changed, m, c); !errors.Is(e, ErrPending) {
		t.Fatal("allocation timestamp replaced", e)
	}
	if _, e := s.Allocate(context.Background(), fixtureAt); !errors.Is(e, ErrPending) {
		t.Fatal("pending generation discarded")
	}
	if e := s.StageFailure(context.Background(), a, "resource_limit"); e != nil {
		t.Fatal(e)
	}
}

func TestStrictOwnLedgerSchema(t *testing.T) {
	base := diskRecord{Version: stateVersion, Binding: fixtureBinding, AgentID: fixtureAgent, Phase: "idle"}
	raw, _ := encodeRecord(base)
	bad := [][]byte{append(bytes.Clone(raw), ' '), append(bytes.Clone(raw), []byte(`{}`)...), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"Version":1`), 1), bytes.Replace(raw, []byte(`"floor":0`), []byte(`"floor":null`), 1), bytes.Replace(raw, []byte(`"phase":"idle"`), []byte(`"phase":"idle","unknown":false`), 1)}
	for i, b := range bad {
		if _, e := decodeRecord(b); e == nil {
			t.Fatalf("bad own schema accepted: %d", i)
		}
	}
}

func TestFullContract1024ChunksAnd64KiBRawChunk(t *testing.T) {
	s, dir := newFixture(t)
	a := reserve(t, s)
	manifest, original := payloads(t, a, fullinventory.MaxGenerationChunks)
	m, e := fullinventory.DecodeManifest(manifest)
	if e != nil {
		t.Fatal(e)
	}
	m.ChunkCount = fullinventory.MaxGenerationChunks
	hash, e := fullinventory.ManifestDigest(m)
	if e != nil {
		t.Fatal(e)
	}
	manifest, _ = json.Marshal(m)
	var rows []linuxpackages.PackageRow
	for _, raw := range original {
		c, e := fullinventory.DecodeChunk(raw)
		if e != nil {
			t.Fatal(e)
		}
		rows = append(rows, c.Items...)
	}
	chunks := make([][]byte, len(rows))
	previous := ""
	for i, row := range rows {
		c := fullinventory.Chunk{SchemaVersion: fullinventory.SchemaVersion, GenerationID: a.GenerationID, ManifestSHA256: hash, Ordinal: uint32(i), ChunkCount: uint32(len(rows)), RowOffset: uint64(i), PreviousSHA256: previous, Items: []linuxpackages.PackageRow{row}}
		// Published contract fixture hashing, not a production alternate validator.
		raw, _ := json.Marshal(c)
		cut := bytes.LastIndex(raw, []byte(`,"sha256":`))
		payload := append(bytes.Clone(raw[:cut]), '}')
		c.SHA256 = digest(append([]byte("tracebolt.complete-linux-packages.chunk.v1\x00"), payload...))
		previous = c.SHA256
		chunks[i], _ = json.Marshal(c)
	}
	chunks[0] = append(chunks[0], bytes.Repeat([]byte(" "), fullinventory.MaxChunkBytes-len(chunks[0]))...)
	if len(chunks[0]) != 64<<10 || len(chunks) != 1024 {
		t.Fatal("bad boundary fixture")
	}
	if e = s.Stage(context.Background(), a, manifest, chunks); e != nil {
		t.Fatal("full contract rejected", e)
	}
	s = reopen(t, s, dir)
	w := next(t, s)
	if e = s.Acknowledge(w, receipt(t, w)); e != nil {
		t.Fatal(e)
	}
	w = next(t, s)
	if w.Operation != "append" || !bytes.Contains(w.Body(), chunks[0]) {
		t.Fatal("64 KiB chunk changed")
	}
	if e = s.RequestAbort(); e != nil {
		t.Fatal(e)
	}
	w = next(t, s)
	if e = s.Acknowledge(w, receipt(t, w)); e != nil {
		t.Fatal(e)
	}
}

func changeReceipt(t *testing.T, raw []byte, change func(map[string]any)) []byte {
	t.Helper()
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("receipt fixture")
	}
	change(fields)
	out, e := json.Marshal(fields)
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func TestStrictReceiptBindingAndOriginalTimes(t *testing.T) {
	s, dir := newFixture(t)
	stageFixture(t, s, 1)
	w := next(t, s)
	good := receipt(t, w)
	before := directoryBytes(t, dir)
	for _, field := range []string{"schemaVersion", "operation", "sequence", "generationId", "manifestHash", "requestSha256"} {
		bad := changeReceipt(t, good, func(v map[string]any) { v[field] = "wrong" })
		if e := s.Acknowledge(w, bad); !errors.Is(e, ErrAcknowledgment) {
			t.Fatal("incorrect receipt binding accepted", field, e)
		}
		unchanged(t, dir, before)
	}
	if e := s.Acknowledge(w, []byte(`{}`)); !errors.Is(e, ErrAcknowledgment) {
		t.Fatal("empty receipt accepted")
	}
	if e := s.Acknowledge(w, good); e != nil {
		t.Fatal(e)
	}
	w = next(t, s)
	good = receipt(t, w)
	before = directoryBytes(t, dir)
	for _, change := range []func(map[string]any){func(v map[string]any) { v["result"].(map[string]any)["rows"] = 2 }, func(v map[string]any) { v["result"].(map[string]any)["ordinal"] = 1 }, func(v map[string]any) { v["result"].(map[string]any)["receivedAt"] = fixtureAt }, func(v map[string]any) { v["result"].(map[string]any)["receivedAt"] = fixtureAt.Add(time.Hour) }} {
		if e := s.Acknowledge(w, changeReceipt(t, good, change)); !errors.Is(e, ErrAcknowledgment) {
			t.Fatal("invalid append receipt accepted", e)
		}
		unchanged(t, dir, before)
	}
	if e := s.Acknowledge(w, good); e != nil {
		t.Fatal(e)
	}
	w = next(t, s)
	good = receipt(t, w)
	bad := changeReceipt(t, good, func(v map[string]any) { v["result"].(map[string]any)["collectedAt"] = fixtureAt.Add(time.Second) })
	if e := s.Acknowledge(w, bad); !errors.Is(e, ErrAcknowledgment) {
		t.Fatal("refreshed source timestamp accepted")
	}
	if e := s.Acknowledge(w, good); e != nil {
		t.Fatal(e)
	}
}
func statusReceipt(t *testing.T, w Work, state string, chunks uint32, rows uint64) []byte {
	t.Helper()
	raw, e := json.Marshal(map[string]any{"schemaVersion": inventorywire.ReceiptVersion, "operation": "status", "sequence": fmt.Sprint(w.Sequence), "generationId": w.GenerationID, "manifestHash": w.ManifestHash, "requestSha256": w.Digest, "result": map[string]any{"state": state, "acceptedChunks": chunks, "expectedChunks": uint32(5), "acceptedRows": rows, "startedAt": fixtureAt.Add(time.Minute), "expiresAt": fixtureAt.Add(16 * time.Minute), "completedAt": ""}})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestStatusCountsExpiryAndCompletedReceiptAreBound(t *testing.T) {
	s, _ := newFixture(t)
	stageFixture(t, s, 513)
	w, e := s.StatusWork()
	if e != nil {
		t.Fatal(e)
	}
	good := statusReceipt(t, w, "pending", 2, 256)
	r, e := s.ValidateStatus(w, good)
	if e != nil || r.AcceptedRows != 256 {
		t.Fatal("valid status refused", e)
	}
	for _, change := range []func(map[string]any){func(v map[string]any) { v["result"].(map[string]any)["acceptedRows"] = 255 }, func(v map[string]any) { v["result"].(map[string]any)["expectedChunks"] = 4 }, func(v map[string]any) { v["result"].(map[string]any)["expiresAt"] = fixtureAt.Add(time.Hour) }} {
		if _, e := s.ValidateStatus(w, changeReceipt(t, good, change)); !errors.Is(e, ErrAcknowledgment) {
			t.Fatal("incorrect status accepted", e)
		}
	}
	expired := statusReceipt(t, w, "expired", 0, 0)
	if _, e = s.ValidateStatus(w, expired); e != nil {
		t.Fatal("coherent pruned expiry rejected", e)
	}
	complete := statusReceipt(t, w, "complete", 5, 513)
	complete = changeReceipt(t, complete, func(v map[string]any) {
		v["result"].(map[string]any)["completedAt"] = fixtureAt.Add(3 * time.Minute)
		v["result"].(map[string]any)["expiresAt"] = fixtureAt.Add(24 * time.Hour)
	})
	if _, e = s.ValidateStatus(w, complete); e != nil {
		t.Fatal("completed status rejected", e)
	}
	complete = changeReceipt(t, complete, func(v map[string]any) { v["result"].(map[string]any)["state"] = "expired" })
	if r, e = s.ValidateStatus(w, complete); e != nil || r.CompletedAt.IsZero() {
		t.Fatal("expired-complete ambiguity lost", e)
	}
}

func directoryBytes(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	out := map[string][]byte{}
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			raw, e := os.ReadFile(filepath.Join(dir, entry.Name()))
			if e != nil {
				t.Fatal(e)
			}
			out[entry.Name()] = raw
		}
	}
	return out
}
func unchanged(t *testing.T, dir string, before map[string][]byte) {
	t.Helper()
	after := directoryBytes(t, dir)
	if len(after) != len(before) {
		t.Fatal("refusal changed entries")
	}
	for name, raw := range before {
		if !bytes.Equal(raw, after[name]) {
			t.Fatal("refusal changed private fixture bytes")
		}
	}
}

func TestDurableAttemptCooldownAndAtomicStatusAbort(t *testing.T) {
	s, dir := newFixture(t)
	at, e := s.LastAttemptedAt()
	if e != nil || !at.IsZero() {
		t.Fatal("fresh attempt time", e)
	}
	stageFixture(t, s, 513)
	w, e := s.StatusWork()
	if e != nil {
		t.Fatal(e)
	}
	pending := statusReceipt(t, w, "pending", 0, 0)
	if e = s.RequestAbortAfterStatus(w, pending); !errors.Is(e, ErrAcknowledgment) {
		t.Fatal("live transfer aborted", e)
	}
	stale := w
	stale.GenerationID = "sample_ffffffffffffffffffffffffffffffff"
	expired := statusReceipt(t, w, "expired", 0, 0)
	if e = s.RequestAbortAfterStatus(stale, expired); !errors.Is(e, ErrAcknowledgment) {
		t.Fatal("wrong binding aborted", e)
	}
	completed := statusReceipt(t, w, "expired", 5, 513)
	completed = changeReceipt(t, completed, func(v map[string]any) {
		v["result"].(map[string]any)["completedAt"] = fixtureAt.Add(3 * time.Minute)
		v["result"].(map[string]any)["expiresAt"] = fixtureAt.Add(24 * time.Hour)
	})
	if e = s.RequestAbortAfterStatus(w, completed); !errors.Is(e, ErrAcknowledgment) {
		t.Fatal("completed transfer aborted", e)
	}
	if e = s.RequestAbortAfterStatus(w, expired); e != nil {
		t.Fatal(e)
	}
	w = next(t, s)
	if e = s.Acknowledge(w, receipt(t, w)); e != nil {
		t.Fatal(e)
	}
	s = reopen(t, s, dir)
	at, e = s.LastAttemptedAt()
	if e != nil || !at.Equal(fixtureAt) {
		t.Fatal("retirement forgot cooldown", e)
	}
	a := reserve(t, s)
	if a.Sequence != 2 || !a.AttemptedAt.Equal(fixtureAt) {
		t.Fatal("same timestamp reused floor")
	}
	if e = s.StageFailure(context.Background(), a, "source_missing"); e != nil {
		t.Fatal(e)
	}
	w = next(t, s)
	if e = s.Acknowledge(w, receipt(t, w)); e != nil {
		t.Fatal(e)
	}
	s = reopen(t, s, dir)
	at, e = s.LastAttemptedAt()
	if e != nil || !at.Equal(fixtureAt) {
		t.Fatal("failure forgot cooldown", e)
	}
}
