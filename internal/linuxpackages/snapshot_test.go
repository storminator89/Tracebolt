package linuxpackages

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func ptr[T any](v T) *T { return &v }

func fixtureSnapshot(n int) Snapshot {
	s := Snapshot{
		SchemaVersion: SchemaVersion, Scope: SnapshotScope,
		GenerationID: "sample_0123456789abcdef0123456789abcdef",
		CollectedAt:  time.Date(2026, 10, 4, 1, 0, 0, 0, time.UTC), DurationMS: 42,
		Release:   ReleaseObservation{Quality: Healthy, Reason: ReasonNone, Fields: ReleaseFields{ID: ptr("debian"), VersionID: ptr("13"), VersionCodename: ptr("trixie")}},
		Inventory: Inventory{Quality: Healthy, Reason: ReasonNone, Complete: true, CountExact: true, ObservedCount: ptr(uint64(n)), InstalledCount: ptr(uint64(n)), Items: make([]PackageRow, n)},
	}
	for i := range s.Inventory.Items {
		name := fmt.Sprintf("tracebolt-fixture-%06d", i)
		s.Inventory.Items[i] = PackageRow{Name: name, Version: "1:2.0~rc1-1+b1", Architecture: "amd64", SourcePackage: name, SourceVersion: "1:2.0~rc1-1+b1", SourceMapping: "binary-default", InstallState: "installed"}
	}
	return s
}

func TestSnapshotRoundTripAndUnavailable(t *testing.T) {
	complete := fixtureSnapshot(2)
	complete.Inventory.Items[1].InstallState = "incomplete"
	complete.Inventory.InstalledCount = ptr(uint64(1))
	missingRelease := cloneSnapshot(complete)
	missingRelease.Release = ReleaseObservation{Quality: Unknown, Reason: ReasonSourceMissing}
	emptyFields := cloneSnapshot(complete)
	emptyFields.Release.Fields = ReleaseFields{ID: ptr("")}
	unknown := fixtureSnapshot(0)
	unknown.Inventory = Inventory{Quality: Unknown, Reason: ReasonReadFailed, Items: []PackageRow{}}
	denied := cloneSnapshot(unknown)
	denied.Release = ReleaseObservation{Quality: Denied, Reason: ReasonPermissionDenied}
	denied.Inventory.Quality, denied.Inventory.Reason = Denied, ReasonPermissionDenied
	busy := cloneSnapshot(unknown)
	busy.Release = ReleaseObservation{Quality: Unknown, Reason: ReasonCollectorBusy}
	busy.Inventory.Reason = ReasonCollectorBusy
	for _, s := range []Snapshot{complete, missingRelease, emptyFields, unknown, denied, busy, fixtureSnapshot(0)} {
		if err := Validate(s); err != nil {
			t.Fatalf("valid state rejected: %v", err)
		}
		b, _ := json.Marshal(s)
		got, err := Decode(b)
		if err != nil || !reflect.DeepEqual(s, got) {
			t.Fatalf("round trip failed: %v", err)
		}
	}
	if missingRelease.Release.Fields.Target() != Incomplete || emptyFields.Release.Fields.Target() != Incomplete {
		t.Fatal("availability became supported target")
	}
}

func TestSnapshotTypedCrossFieldRejections(t *testing.T) {
	tests := map[string]func(*Snapshot){
		"schema":                         func(s *Snapshot) { s.SchemaVersion = "future" },
		"scope":                          func(s *Snapshot) { s.Scope = "host" },
		"generation":                     func(s *Snapshot) { s.GenerationID = "sample_bad" },
		"utc":                            func(s *Snapshot) { s.CollectedAt = s.CollectedAt.In(time.FixedZone("elsewhere", 3600)) },
		"zero time":                      func(s *Snapshot) { s.CollectedAt = time.Time{} },
		"negative duration":              func(s *Snapshot) { s.DurationMS = -1 },
		"oversize duration":              func(s *Snapshot) { s.DurationMS = MaxSafeInteger + 1 },
		"release unknown with fields":    func(s *Snapshot) { s.Release.Quality, s.Release.Reason = Unknown, ReasonSourceMissing },
		"release unrecognized quality":   func(s *Snapshot) { s.Release.Quality = "verified" },
		"release healthy failure reason": func(s *Snapshot) { s.Release.Reason = ReasonByteLimit },
		"release invalid identifier":     func(s *Snapshot) { s.Release.Fields.ID = ptr("Debian") },
		"release overlong identifier":    func(s *Snapshot) { s.Release.Fields.ID = ptr(strings.Repeat("a", MaxReleaseValue+1)) },
		"unknown reason":                 func(s *Snapshot) { s.Inventory.Reason = "a private diagnostic" },
		"nil rows":                       func(s *Snapshot) { s.Inventory.Items = nil },
		"unknown with prefix":            func(s *Snapshot) { s.Inventory.Quality, s.Inventory.Reason = Unknown, ReasonReadFailed },
		"denied wrong reason":            func(s *Snapshot) { s.Inventory.Quality = Denied },
		"healthy approximate count":      func(s *Snapshot) { s.Inventory.CountExact = false },
		"healthy null count":             func(s *Snapshot) { s.Inventory.ObservedCount = nil },
		"healthy null installed":         func(s *Snapshot) { s.Inventory.InstalledCount = nil },
		"over source bound":              func(s *Snapshot) { s.Inventory.ObservedCount = ptr(uint64(MaxDpkgRecords + 1)) },
		"installed exceeds observed":     func(s *Snapshot) { s.Inventory.InstalledCount = ptr(uint64(3)) },
		"observed below export":          func(s *Snapshot) { s.Inventory.ObservedCount = ptr(uint64(1)) },
		"complete omitted rows":          func(s *Snapshot) { s.Inventory.ObservedCount = ptr(uint64(3)) },
		"complete wrong installed":       func(s *Snapshot) { s.Inventory.InstalledCount = ptr(uint64(1)) },
		"complete truncation":            func(s *Snapshot) { s.Inventory.Truncated = true },
		"complete limit reason":          func(s *Snapshot) { s.Inventory.Reason = ReasonItemLimit },
		"partial not truncated":          func(s *Snapshot) { s.Inventory.Complete = false },
		"truncated no omitted": func(s *Snapshot) {
			s.Inventory.Complete, s.Inventory.Truncated, s.Inventory.Reason = false, true, ReasonItemLimit
		},
		"duplicate identity": func(s *Snapshot) { s.Inventory.Items[1] = s.Inventory.Items[0] },
		"unsorted": func(s *Snapshot) {
			s.Inventory.Items[0], s.Inventory.Items[1] = s.Inventory.Items[1], s.Inventory.Items[0]
		},
		"wrong default source name":    func(s *Snapshot) { s.Inventory.Items[0].SourcePackage = "other" },
		"wrong default source version": func(s *Snapshot) { s.Inventory.Items[0].SourceVersion = "3.0" },
		"unknown mapping":              func(s *Snapshot) { s.Inventory.Items[0].SourceMapping = "inferred" },
		"invalid package name":         func(s *Snapshot) { s.Inventory.Items[0].Name = "x;command" },
		"one character source":         func(s *Snapshot) { s.Inventory.Items[0].SourcePackage = "x" },
		"wildcard architecture":        func(s *Snapshot) { s.Inventory.Items[0].Architecture = "linux-any" },
		"invalid version":              func(s *Snapshot) { s.Inventory.Items[0].Version = "semver?" },
		"unknown install state":        func(s *Snapshot) { s.Inventory.Items[0].InstallState = "active" },
	}
	for name, modify := range tests {
		t.Run(name, func(t *testing.T) {
			s := fixtureSnapshot(2)
			modify(&s)
			if Validate(s) == nil {
				t.Fatal("invalid typed snapshot accepted")
			}
			b, _ := json.Marshal(s)
			if got, err := Decode(b); err == nil || !reflect.DeepEqual(got, Snapshot{}) {
				t.Fatal("invalid decoded snapshot returned facts")
			}
		})
	}
}

func TestTruncatedCountFeasibility(t *testing.T) {
	s := fixtureSnapshot(2)
	s.Inventory.Complete, s.Inventory.Truncated, s.Inventory.Reason = false, true, ReasonItemLimit
	s.Inventory.ObservedCount = ptr(uint64(4))
	s.Inventory.Items[1].InstallState = "incomplete"
	for _, count := range []uint64{1, 2, 3} {
		s.Inventory.InstalledCount = ptr(count)
		if err := Validate(s); err != nil {
			t.Fatalf("feasible full-source count rejected: %v", err)
		}
	}
	for _, count := range []uint64{0, 4} {
		s.Inventory.InstalledCount = ptr(count)
		if Validate(s) == nil {
			t.Fatal("impossible omitted-row installed total accepted")
		}
	}
}

func TestTrimDeterministicCloneAndCounts(t *testing.T) {
	s := fixtureSnapshot(300)
	for i, j := 0, len(s.Inventory.Items)-1; i < j; i, j = i+1, j-1 {
		s.Inventory.Items[i], s.Inventory.Items[j] = s.Inventory.Items[j], s.Inventory.Items[i]
	}
	before := cloneSnapshot(s)
	got, err := Trim(s)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s, before) || got.GenerationID != s.GenerationID || got.CollectedAt != s.CollectedAt || got.DurationMS != s.DurationMS || *got.Inventory.ObservedCount != 300 || *got.Inventory.InstalledCount != 300 {
		t.Fatal("trim mutated input or capture/full-source facts")
	}
	if got.Inventory.Complete || !got.Inventory.Truncated || !got.Inventory.CountExact || got.Inventory.Reason != ReasonByteLimit || len(got.Inventory.Items) >= MaxExportRows || cap(got.Inventory.Items) != len(got.Inventory.Items) {
		t.Fatal("trim lost byte-limit priority or retained hidden rows")
	}
	if got.Inventory.Items[0].Name != "tracebolt-fixture-000000" {
		t.Fatal("trim selected a noncanonical prefix")
	}
	b, _ := json.Marshal(got)
	if len(b) > MaxSnapshotBytes || Validate(got) != nil {
		t.Fatal("trim returned invalid export")
	}
	second, err := Trim(got)
	if err != nil || !reflect.DeepEqual(second, got) {
		t.Fatal("repeated trim was not idempotent")
	}
	*got.Release.Fields.ID = "changed"
	*got.Inventory.ObservedCount = 7
	got.Inventory.Items[0].Name = "changed"
	if !reflect.DeepEqual(s, before) {
		t.Fatal("returned snapshot aliases input mutable members")
	}
}

func TestTrimItemLimitAndBytePriority(t *testing.T) {
	// Minimal valid rows ensure the item cap itself can be exercised independently
	// of the byte cap by invoking the internal shape/mark invariant directly.
	x := fixtureSnapshot(130).Inventory
	x.Items = x.Items[:128]
	markTruncated(&x, ReasonItemLimit)
	if x.Reason != ReasonItemLimit || *x.ObservedCount != 130 || !x.Truncated {
		t.Fatal("item-limit metadata wrong")
	}
	markTruncated(&x, ReasonByteLimit)
	markTruncated(&x, ReasonItemLimit)
	if x.Reason != ReasonByteLimit || *x.InstalledCount != 130 {
		t.Fatal("byte-limit priority or source count changed")
	}
	s := fixtureSnapshot(4)
	s.Inventory.Items[3] = s.Inventory.Items[0]
	if got, err := Trim(s); err == nil || !reflect.DeepEqual(got, Snapshot{}) {
		t.Fatal("trimming erased malformed suffix evidence")
	}
	oversize := fixtureSnapshot(MaxDpkgRecords + 1)
	if _, err := Trim(oversize); err == nil {
		t.Fatal("unbounded local input accepted")
	}
}

func TestTrimExactByteEdgesAndMetadataFailure(t *testing.T) {
	s := fixtureSnapshot(2)
	b, _ := json.Marshal(s)
	exact, err := trimToBudget(s, len(b))
	if err != nil || !exact.Inventory.Complete || len(exact.Inventory.Items) != 2 {
		t.Fatal("exact canonical byte bound rejected")
	}
	smaller, err := trimToBudget(s, len(b)-1)
	if err != nil || smaller.Inventory.Complete || smaller.Inventory.Reason != ReasonByteLimit || *smaller.Inventory.ObservedCount != 2 || len(smaller.Inventory.Items) != 1 {
		t.Fatal("one-byte overflow not honestly trimmed")
	}
	for _, budget := range []int{0, 1, MaxSnapshotBytes + 1} {
		if got, err := trimToBudget(s, budget); err == nil || !reflect.DeepEqual(got, Snapshot{}) {
			t.Fatal("metadata/budget failure returned a snapshot")
		}
	}
}

func TestDecodeStrictShapeAndRawLimits(t *testing.T) {
	b, _ := json.Marshal(fixtureSnapshot(1))
	base := string(b)
	for name, input := range map[string]string{
		"top duplicate":          strings.Replace(base, `"scope":`, `"scope":"agent-visible-dpkg","scope":`, 1),
		"nested duplicate":       strings.Replace(base, `"quality":`, `"quality":"healthy","quality":`, 1),
		"escaped duplicate":      strings.Replace(base, `"scope":`, `"sc\u006fpe":"agent-visible-dpkg","scope":`, 1),
		"unknown trust":          strings.Replace(base, `"release":{`, `"verified":true,"release":{`, 1),
		"unknown row origin":     strings.Replace(base, `"name":`, `"origin":"official","name":`, 1),
		"case variant":           strings.Replace(base, `"scope":`, `"Scope":`, 1),
		"missing duration":       strings.Replace(base, `"durationMs":42,`, "", 1),
		"null duration":          strings.Replace(base, `"durationMs":42`, `"durationMs":null`, 1),
		"negative zero duration": strings.Replace(base, `"durationMs":42`, `"durationMs":-0`, 1),
		"exponent duration":      strings.Replace(base, `"durationMs":42`, `"durationMs":4.2e1`, 1),
		"decimal count":          strings.Replace(base, `"observedCount":1`, `"observedCount":1.0`, 1),
		"string count":           strings.Replace(base, `"observedCount":1`, `"observedCount":"1"`, 1),
		"null boolean":           strings.Replace(base, `"complete":true`, `"complete":null`, 1),
		"null release":           strings.Replace(base, `"release":{"quality":"healthy","reason":"none","fields":{"id":"debian","versionId":"13","versionCodename":"trixie"}}`, `"release":null`, 1),
		"number selected field":  strings.Replace(base, `"id":"debian"`, `"id":13`, 1),
		"null string":            strings.Replace(base, `"sourceMapping":"binary-default"`, `"sourceMapping":null`, 1),
		"numeric timezone":       strings.Replace(base, `01:00:00Z`, `01:00:00+00:00`, 1),
		"trailing object":        base + `{}`, "array root": `[]`, "null root": `null`,
		"invalid utf8":         strings.Replace(base, "debian", "\xff", 1),
		"surrogate identifier": strings.Replace(base, `"debian"`, `"\ud800"`, 1),
		"depth":                strings.Repeat("[", 9) + strings.Repeat("]", 9),
	} {
		t.Run(name, func(t *testing.T) {
			if input == base {
				t.Fatal("negative fixture did not change input")
			}
			got, err := Decode([]byte(input))
			if err == nil || !reflect.DeepEqual(got, Snapshot{}) {
				t.Fatal("malformed JSON returned facts")
			}
		})
	}
	padding := strings.Repeat(" ", MaxSnapshotBytes-len(b))
	if _, err := Decode([]byte(base + padding)); err != nil {
		t.Fatal("exact raw byte bound rejected")
	}
	if _, err := Decode([]byte(base + padding + " ")); err != ErrSnapshotLimit {
		t.Fatal("raw limit not enforced")
	}
	if _, err := Decode([]byte(strings.Replace(base, `"items":[`, `"items":null,"bad":[`, 1))); err == nil {
		t.Fatal("null item list accepted")
	}
}

func TestSnapshotCanonicalByteCap(t *testing.T) {
	s := fixtureSnapshot(MaxExportRows)
	b, err := json.Marshal(s)
	if err != nil || len(b) <= MaxSnapshotBytes {
		t.Fatal("fixture does not exercise canonical overflow")
	}
	if Validate(s) != ErrSnapshotLimit {
		t.Fatal("canonical byte cap not enforced independently of row cap")
	}
	got, err := Trim(s)
	if err != nil || got.Inventory.Reason != ReasonByteLimit || *got.Inventory.ObservedCount != MaxExportRows {
		t.Fatal("canonical overflow did not preserve source counts")
	}
}

func FuzzDecodeNoFactsOnError(f *testing.F) {
	b, _ := json.Marshal(fixtureSnapshot(1))
	f.Add(b)
	f.Add([]byte(`{"schemaVersion":null}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		s, err := Decode(raw)
		if err != nil && !reflect.DeepEqual(s, Snapshot{}) {
			t.Fatal("error returned partial snapshot")
		}
		if err == nil && Validate(s) != nil {
			t.Fatal("decoder returned invalid snapshot")
		}
	})
}
