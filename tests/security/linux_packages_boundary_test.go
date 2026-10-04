package security_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"localrmm/internal/linuxpackages"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These independent checks use only public pure parser/DTO functions and inert
// strings, plus repository-source AST inspection. They do not call a collector, open host inventory, start subprocesses,
// construct credentials, contact a service, or change a frozen candidate.
func packageReviewPointer[T any](v T) *T { return &v }

func packageReviewSnapshot(n int) linuxpackages.Snapshot {
	s := linuxpackages.Snapshot{
		SchemaVersion: linuxpackages.SchemaVersion, Scope: linuxpackages.SnapshotScope,
		GenerationID: "sample_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CollectedAt:  time.Date(2026, 10, 4, 2, 0, 0, 0, time.UTC), DurationMS: 17,
		Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone,
			Fields: linuxpackages.ReleaseFields{ID: packageReviewPointer("ubuntu"), VersionID: packageReviewPointer("24.04"), VersionCodename: packageReviewPointer("noble")}},
		Inventory: linuxpackages.Inventory{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone,
			Complete: true, CountExact: true, ObservedCount: packageReviewPointer(uint64(n)),
			InstalledCount: packageReviewPointer(uint64(n)), Items: make([]linuxpackages.PackageRow, n)},
	}
	for i := range s.Inventory.Items {
		name := fmt.Sprintf("review-%05d", i)
		s.Inventory.Items[i] = linuxpackages.PackageRow{Name: name, Version: "1.0-1", Architecture: "amd64",
			SourcePackage: name, SourceVersion: "1.0-1", SourceMapping: "source-field", InstallState: "installed"}
	}
	return s
}

func packageReviewJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal("synthetic serialization failed")
	}
	return raw
}

func packageReviewZeroOnError(t *testing.T, raw []byte) {
	t.Helper()
	s, err := linuxpackages.Decode(raw)
	if err == nil || !reflect.DeepEqual(s, linuxpackages.Snapshot{}) {
		t.Fatal("invalid raw component returned facts")
	}
	if !errors.Is(err, linuxpackages.ErrInvalidSnapshot) && !errors.Is(err, linuxpackages.ErrSnapshotLimit) {
		t.Fatal("raw decoder exposed an unexpected diagnostic")
	}
}

func TestIndependentLinuxPackagesRawContract(t *testing.T) {
	base := packageReviewJSON(t, packageReviewSnapshot(1))
	var original map[string]json.RawMessage
	if json.Unmarshal(base, &original) != nil {
		t.Fatal("fixture decode failed")
	}
	// Every required root member, including nullable-containing objects, must be
	// present and correctly typed. Go's zero values must not supply missing data.
	for key := range original {
		t.Run("missing_"+key, func(t *testing.T) {
			copy := make(map[string]json.RawMessage, len(original))
			for name, value := range original {
				if name != key {
					copy[name] = value
				}
			}
			packageReviewZeroOnError(t, packageReviewJSON(t, copy))
		})
		t.Run("null_"+key, func(t *testing.T) {
			copy := make(map[string]json.RawMessage, len(original))
			for name, value := range original {
				copy[name] = value
			}
			copy[key] = []byte("null")
			packageReviewZeroOnError(t, packageReviewJSON(t, copy))
		})
	}
	text := string(base)
	for name, raw := range map[string]string{
		"escaped nested duplicate": strings.Replace(text, `"installedCount":1`, `"installedCount":1,"installed\u0043ount":1`, 1),
		"row duplicate":            strings.Replace(text, `"version":"1.0-1"`, `"version":"1.0-1","version":"1.0-1"`, 1),
		"case alias":               strings.Replace(text, `"countExact":true`, `"CountExact":true`, 1),
		"release extra provenance": strings.Replace(text, `"fields":{`, `"trusted":true,"fields":{`, 1),
		"row extra source hash":    strings.Replace(text, `"sourcePackage":`, `"sourceDigest":"private-canary","sourcePackage":`, 1),
		"future candidate section": strings.Replace(text, `"inventory":{`, `"cachedCandidates":{},"inventory":{`, 1),
		"omitted nullable field":   strings.Replace(text, `"id":"ubuntu",`, "", 1),
		"null items":               strings.Replace(text, `"items":[`, `"items":null,"extra":[`, 1),
		"negative-zero integer":    strings.Replace(text, `"durationMs":17`, `"durationMs":-0`, 1),
		"exponent integer":         strings.Replace(text, `"observedCount":1`, `"observedCount":1e0`, 1),
		"decimal integer":          strings.Replace(text, `"installedCount":1`, `"installedCount":1.0`, 1),
		"integer overflow":         strings.Replace(text, `"durationMs":17`, `"durationMs":999999999999999999999999`, 1),
		"encoded control":          strings.Replace(text, `"ubuntu"`, `"ubu\u0000ntu"`, 1),
		"lone surrogate":           strings.Replace(text, `"ubuntu"`, `"\udfff"`, 1),
		"invalid utf8":             strings.Replace(text, "ubuntu", "\xff", 1),
		"extra document":           text + "{}",
		"BOM":                      "\xef\xbb\xbf" + text,
	} {
		t.Run(name, func(t *testing.T) {
			if raw == text {
				t.Fatal("negative fixture did not change bytes")
			}
			packageReviewZeroOnError(t, []byte(raw))
		})
	}
	for _, fields := range []linuxpackages.ReleaseFields{{}, {ID: packageReviewPointer("")}} {
		s := packageReviewSnapshot(0)
		s.Release.Fields = fields
		got, err := linuxpackages.Decode(packageReviewJSON(t, s))
		if err != nil || !reflect.DeepEqual(got.Release.Fields, fields) || got.Release.Fields.Target() != linuxpackages.Incomplete {
			t.Fatal("missing and empty release facts were conflated or promoted")
		}
	}
}

func TestIndependentLinuxPackagesCountFeasibility(t *testing.T) {
	// Two installed and one incomplete exported rows imply tight source-total
	// bounds. Sweep both complete and truncated count claims through public APIs.
	for observed := uint64(0); observed <= 6; observed++ {
		for installed := uint64(0); installed <= 7; installed++ {
			s := packageReviewSnapshot(3)
			s.Inventory.Items[1].InstallState = "incomplete"
			s.Inventory.ObservedCount, s.Inventory.InstalledCount = packageReviewPointer(observed), packageReviewPointer(installed)
			if observed > 3 {
				s.Inventory.Complete, s.Inventory.Truncated, s.Inventory.Reason = false, true, linuxpackages.ReasonByteLimit
			}
			want := observed >= 3 && installed >= 2 && installed <= observed-1
			if observed == 3 {
				want = installed == 2
			}
			if (linuxpackages.Validate(s) == nil) != want {
				t.Fatal("typed source-count feasibility mismatch")
			}
			got, err := linuxpackages.Decode(packageReviewJSON(t, s))
			if (err == nil) != want || err != nil && !reflect.DeepEqual(got, linuxpackages.Snapshot{}) {
				t.Fatal("decoded source-count feasibility mismatch")
			}
		}
	}
	for _, quality := range []linuxpackages.Quality{linuxpackages.Unknown, linuxpackages.Denied} {
		s := packageReviewSnapshot(0)
		reason := linuxpackages.ReasonReadFailed
		if quality == linuxpackages.Denied {
			reason = linuxpackages.ReasonPermissionDenied
		}
		s.Inventory = linuxpackages.Inventory{Quality: quality, Reason: reason, Items: []linuxpackages.PackageRow{}}
		if linuxpackages.Validate(s) != nil {
			t.Fatal("unavailable inventory rejected")
		}
		s.Inventory.ObservedCount = packageReviewPointer(uint64(0))
		if linuxpackages.Validate(s) == nil {
			t.Fatal("unavailable source acquired a fabricated exact zero")
		}
	}
}

func packageReviewExactSize(t *testing.T, size int) linuxpackages.Snapshot {
	t.Helper()
	s := packageReviewSnapshot(20)
	remaining := size - len(packageReviewJSON(t, s))
	if remaining < 0 {
		t.Fatal("fixture starts above byte target")
	}
	for i := range s.Inventory.Items {
		for _, field := range []*string{&s.Inventory.Items[i].Version, &s.Inventory.Items[i].SourceVersion} {
			n := min(remaining, linuxpackages.MaxVersion-len(*field))
			*field += strings.Repeat("0", n)
			remaining -= n
		}
	}
	if remaining != 0 || len(packageReviewJSON(t, s)) != size {
		t.Fatal("ordinary typed values did not reach exact byte target")
	}
	return s
}

func TestIndependentLinuxPackagesByteEdgesAndTrimOwnership(t *testing.T) {
	exact := packageReviewExactSize(t, linuxpackages.MaxSnapshotBytes)
	if linuxpackages.Validate(exact) != nil {
		t.Fatal("exact canonical size rejected")
	}
	raw := packageReviewJSON(t, exact)
	if _, err := linuxpackages.Decode(raw); err != nil {
		t.Fatal("exact raw and canonical size rejected")
	}
	packageReviewZeroOnError(t, append(bytes.Clone(raw), ' '))
	over := packageReviewExactSize(t, linuxpackages.MaxSnapshotBytes+1)
	if !errors.Is(linuxpackages.Validate(over), linuxpackages.ErrSnapshotLimit) {
		t.Fatal("canonical overflow accepted")
	}
	before := packageReviewJSON(t, over)
	trimmed, err := linuxpackages.Trim(over)
	if err != nil || trimmed.Inventory.Complete || !trimmed.Inventory.Truncated || trimmed.Inventory.Reason != linuxpackages.ReasonByteLimit ||
		*trimmed.Inventory.ObservedCount != 20 || *trimmed.Inventory.InstalledCount != 20 || len(trimmed.Inventory.Items) >= 20 ||
		trimmed.GenerationID != over.GenerationID || trimmed.CollectedAt != over.CollectedAt || trimmed.DurationMS != over.DurationMS ||
		cap(trimmed.Inventory.Items) != len(trimmed.Inventory.Items) || linuxpackages.Validate(trimmed) != nil {
		t.Fatal("byte trimming changed source facts or retained hidden rows")
	}
	again, err := linuxpackages.Trim(trimmed)
	if err != nil || !reflect.DeepEqual(again, trimmed) {
		t.Fatal("trimming is not idempotent")
	}
	*trimmed.Release.Fields.ID, *trimmed.Release.Fields.VersionID, *trimmed.Release.Fields.VersionCodename = "changed", "0", "changed"
	*trimmed.Inventory.ObservedCount, *trimmed.Inventory.InstalledCount = 0, 0
	trimmed.Inventory.Items[0].Name = "changed"
	if !bytes.Equal(before, packageReviewJSON(t, over)) {
		t.Fatal("trim output aliases caller-owned rows or pointers")
	}

	// A malformed suffix cannot disappear behind either row or byte trimming.
	for _, malformed := range []func(*linuxpackages.PackageRow){
		func(p *linuxpackages.PackageRow) { p.SourceVersion = "invalid" },
		func(p *linuxpackages.PackageRow) { p.Architecture = "musl-any-any" },
		func(p *linuxpackages.PackageRow) { p.SourceMapping = "trusted" },
	} {
		s := packageReviewSnapshot(200)
		malformed(&s.Inventory.Items[199])
		if got, err := linuxpackages.Trim(s); err == nil || !reflect.DeepEqual(got, linuxpackages.Snapshot{}) {
			t.Fatal("trimmer hid an invalid source suffix")
		}
	}
}

func TestIndependentLinuxPackagesPrivacyAndReleaseIsolation(t *testing.T) {
	ctx := context.Background()
	const source = "Package: review-binary\nStatus: hold ok installed\nVersion: 1:2.0~rc1-1+b7\nArchitecture: all\nSource: review-source (1:2.0~rc1-1)\nDescription: private-canary\nMaintainer: private-canary@example.invalid\n"
	rows, err := linuxpackages.ParseDpkgStatus(ctx, strings.NewReader(source))
	if err != nil || len(rows) != 1 || rows[0].Architecture != "all" || rows[0].SourceVersion != "1:2.0~rc1-1" || rows[0].Version != "1:2.0~rc1-1+b7" {
		t.Fatal("selected source mapping or binary architecture lost")
	}
	s := packageReviewSnapshot(1)
	s.Inventory.Items = rows
	s.Release = linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}
	raw := packageReviewJSON(t, s)
	got, err := linuxpackages.Decode(raw)
	if err != nil || got.Release.Fields.Target() != linuxpackages.Incomplete || len(got.Inventory.Items) != 1 {
		t.Fatal("release failure erased independent inventory or invented release applicability")
	}
	for _, forbidden := range []string{"private-canary", "example.invalid", "hold", "sha256", "origin", "verified", "candidate", "affected"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("unselected source data or authority escaped selected DTO")
		}
	}
	for _, tuple := range []linuxpackages.ReleaseFields{
		{ID: packageReviewPointer("linuxmint"), VersionID: packageReviewPointer("24.04"), VersionCodename: packageReviewPointer("noble")},
		{ID: packageReviewPointer("ubuntu"), VersionID: packageReviewPointer("24.04"), VersionCodename: packageReviewPointer("trixie")},
	} {
		if tuple.Target() == linuxpackages.Debian13 || tuple.Target() == linuxpackages.Ubuntu2404 {
			t.Fatal("derivative or contradictory release acquired vendor routing")
		}
	}
}

func TestIndependentLinuxPackagesPureDependencyBoundary(t *testing.T) {
	// A narrow source-regression tripwire, not a complete effect-system proof.
	// Reuse only the foundation's supplied-reader parser/grammar, never its native
	// filesystem collector, comparator, advisory matcher, or provenance DTO.
	allowedImports := map[string]bool{
		"bytes": true, "context": true, "encoding/json": true, "errors": true,
		"io": true, "regexp": true, "sort": true, "strings": true, "time": true,
		"unicode": true, "unicode/utf8": true, "localrmm/internal/assessment": true,
	}
	allowedAssessment := map[string]bool{
		"MaxInventoryBytes": true, "MaxInventoryLine": true, "MaxInventoryPackages": true,
		"MaxInventoryFields": true, "ParseDpkgStatus": true, "ErrInventoryLimit": true,
		"ErrInventoryEmpty": true, "ErrInventoryInvalid": true, "ValidDebianVersion": true,
	}
	dir := filepath.Join("..", "..", "internal", "linuxpackages")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal("cannot inspect package source")
	}
	parserUses := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatal("cannot parse package source")
		}
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || !allowedImports[path] || imp.Name != nil {
				t.Fatalf("review new or aliased production dependency in %s", name)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok || pkg.Name != "assessment" {
				return true
			}
			if !allowedAssessment[selector.Sel.Name] {
				t.Fatalf("unreviewed assessment capability in %s", name)
			}
			if selector.Sel.Name == "ParseDpkgStatus" {
				parserUses++
			}
			return true
		})
	}
	if parserUses != 1 {
		t.Fatal("selected adapter no longer reuses its one supplied-reader parser")
	}
}
