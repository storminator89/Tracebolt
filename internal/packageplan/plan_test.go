package packageplan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"testing"

	"localrmm/internal/actionpermit"
)

const fixtureNow int64 = 1700000000

func fixture(t *testing.T) Plan {
	t.Helper()
	raw, err := os.ReadFile("testdata/plan.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func hash(s string) string { return actionpermit.Digest([]byte(s)) }
func archive(p Plan) []ObservedArchive {
	return []ObservedArchive{{Path: "/var/cache/apt/archives/sample-bin_1.0-2_amd64.deb", SHA256: p.Packages[0].Archive.SHA256, Size: p.Packages[0].Archive.Size}}
}

func TestCanonicalPlanFixture(t *testing.T) {
	ctx := context.Background()
	p := fixture(t)
	raw, err := Encode(ctx, p)
	if err != nil || !bytes.Equal(raw, fixtureBytes(t, "plan.json")) {
		t.Fatal("canonical fixture mismatch", err)
	}
	digest, err := Digest(ctx, p)
	if err != nil || digest != strings.TrimSpace(string(fixtureBytes(t, "plan.digest"))) {
		t.Fatal("digest mismatch", digest, err)
	}
	if err := CheckFresh(ctx, p, fixtureNow); err != nil {
		t.Fatal(err)
	}
}
func TestStrictPlanWire(t *testing.T) {
	raw := fixtureBytes(t, "plan.json")
	changes := map[string][]byte{
		"empty": nil, "space": append([]byte(" "), raw...), "trailing": append(bytes.Clone(raw), '\n'),
		"unknown":      bytes.Replace(raw, []byte(`"version":`), []byte(`"extra":0,"version":`), 1),
		"duplicate":    bytes.Replace(raw, []byte(`"version":`), []byte(`"version":"ignored","version":`), 1),
		"case":         bytes.Replace(raw, []byte(`"version":`), []byte(`"Version":`), 1),
		"missing":      bytes.Replace(raw, []byte(`"holdState":"unheld",`), nil, 1),
		"null":         bytes.Replace(raw, []byte(`"holdState":"unheld"`), []byte(`"holdState":null`), 1),
		"nullPackages": bytes.Replace(raw, []byte(`"packages":[`), []byte(`"packages":null,"packages":[`), 1),
		"escape":       bytes.Replace(raw, []byte(`agent_`), []byte(`\u0061gent_`), 1),
		"futureSchema": bytes.Replace(raw, []byte(Version), []byte("tracebolt.selected-apt-plan.v2"), 1),
		"oversized":    bytes.Repeat([]byte(" "), MaxPlanBytes+1),
		"wrongType":    bytes.Replace(raw, []byte(`"size":23`), []byte(`"size":"23"`), 1),
		"float":        bytes.Replace(raw, []byte(`"size":23`), []byte(`"size":23.0`), 1),
	}
	for name, b := range changes {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(context.Background(), b); err == nil {
				t.Fatal("accepted noncanonical wire")
			}
		})
	}
}
func TestRejectedPlans(t *testing.T) {
	cases := map[string]func(*Plan){
		"empty": func(p *Plan) { p.Packages = nil },
		"tooMany": func(p *Plan) {
			for len(p.Packages) <= MaxPackages {
				p.Packages = append(p.Packages, p.Packages[0])
			}
		},
		"duplicate":               func(p *Plan) { p.Packages = append(p.Packages, p.Packages[0]) },
		"unsorted":                func(p *Plan) { u := p.Packages[0]; u.Name = "aa"; p.Packages = append(p.Packages, u) },
		"unsupportedRelease":      func(p *Plan) { p.Release = "debian-14-forky" },
		"releaseUpgrade":          func(p *Plan) { p.Packages[0].Archive.Release = "ubuntu-24.04-noble" },
		"unknownInventory":        func(p *Plan) { p.Evidence.InventoryCoverage = "unknown" },
		"partialInventory":        func(p *Plan) { p.Evidence.InventoryCoverage = "partial" },
		"staleInventory":          func(p *Plan) { p.Evidence.InventoryAt = fixtureNow - MaxInventoryAgeSeconds - 1 },
		"futureInventory":         func(p *Plan) { p.Evidence.InventoryAt = fixtureNow + 1 },
		"zeroInventory":           func(p *Plan) { p.Evidence.InventoryAt = 0 },
		"staleMetadata":           func(p *Plan) { p.Evidence.MetadataRefreshedAt = fixtureNow - MaxMetadataAgeSeconds - 1 },
		"unknownMetadata":         func(p *Plan) { p.Evidence.MetadataState = "unknown" },
		"cachedMetadata":          func(p *Plan) { p.Evidence.MetadataState = "not_attempted" },
		"partialRefresh":          func(p *Plan) { p.Evidence.MetadataState = "partial-refresh" },
		"futureMetadata":          func(p *Plan) { p.Evidence.MetadataRefreshedAt = fixtureNow + 1 },
		"dirtyDpkg":               func(p *Plan) { p.Evidence.DpkgState = "pending-triggers" },
		"unknownHolds":            func(p *Plan) { p.Evidence.HoldsState = "unknown" },
		"held":                    func(p *Plan) { p.Packages[0].HoldState = "held" },
		"newDependency":           func(p *Plan) { p.Packages[0].InstallState = "not-installed" },
		"unknownOld":              func(p *Plan) { p.Packages[0].From.Version = "-" },
		"unknownNew":              func(p *Plan) { p.Packages[0].To.Version = "unknown" },
		"unknownSourceVersion":    func(p *Plan) { p.Packages[0].To.SourceVersion = "" },
		"unknownOldSource":        func(p *Plan) { p.Packages[0].From.SourcePackage = "" },
		"unsupportedEpoch":        func(p *Plan) { p.Packages[0].To.Version = "2147483648:1" },
		"unsupportedVersion":      func(p *Plan) { p.Packages[0].To.Version = "1:2:3" },
		"downgrade":               func(p *Plan) { p.Packages[0].To.Version = "0.1" },
		"equal":                   func(p *Plan) { p.Packages[0].To.Version = p.Packages[0].From.Version },
		"sameOrderDifferentBytes": func(p *Plan) { p.Packages[0].To.Version = "0:1.0-01" },
		"defaultSourceMismatch": func(p *Plan) {
			p.Packages[0].From.SourceMapping = "binary-default"
			p.Packages[0].From.SourcePackage = "another"
		},
		"sourceMapping":     func(p *Plan) { p.Packages[0].From.SourceMapping = "unknown" },
		"archWildcard":      func(p *Plan) { p.Packages[0].Architecture = "linux-any" },
		"archSource":        func(p *Plan) { p.Packages[0].Architecture = "source" },
		"archEmptyPart":     func(p *Plan) { p.Packages[0].Architecture = "-amd64" },
		"multiarch":         func(p *Plan) { p.Packages[0].To.MultiArch = "unknown" },
		"noncanonicalNone":  func(p *Plan) { p.Packages[0].To.MultiArch = "none" },
		"unsignedArchive":   func(p *Plan) { p.Packages[0].Archive.Authentication = "unknown" },
		"missingHash":       func(p *Plan) { p.Packages[0].Archive.SHA256 = "" },
		"uppercaseHash":     func(p *Plan) { p.Packages[0].Archive.IndexDigest = strings.ToUpper(p.Packages[0].Archive.IndexDigest) },
		"zeroArchive":       func(p *Plan) { p.Packages[0].Archive.Size = 0 },
		"hugeArchive":       func(p *Plan) { p.Packages[0].Archive.Size = MaxArchiveBytes + 1 },
		"absoluteArchive":   func(p *Plan) { p.Packages[0].Archive.Filename = "/tmp/file.deb" },
		"traversal":         func(p *Plan) { p.Packages[0].Archive.Filename = "pool/../file.deb" },
		"escapedPath":       func(p *Plan) { p.Packages[0].Archive.Filename = "pool/file%20.deb" },
		"indexTraversal":    func(p *Plan) { p.Packages[0].Archive.IndexPath = "../Packages" },
		"expiredAtCreation": func(p *Plan) { p.ExpiresAt = p.CreatedAt },
		"tooLong":           func(p *Plan) { p.ExpiresAt = p.CreatedAt + MaxLifetimeSeconds + 1 },
		"zeroTime":          func(p *Plan) { p.CreatedAt = 0 },
		"overflowTime":      func(p *Plan) { p.CreatedAt = math.MaxInt64 },
		"overflowExpiry":    func(p *Plan) { p.ExpiresAt = math.MaxInt64 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p := fixture(t)
			change(&p)
			if _, err := Encode(context.Background(), p); err == nil {
				t.Fatal("accepted unsupported plan")
			}
		})
	}
}
func TestFreshnessBoundaries(t *testing.T) {
	ctx := context.Background()
	p := fixture(t)
	for _, now := range []int64{0, fixtureNow - 1, p.ExpiresAt, math.MaxInt64} {
		if err := CheckFresh(ctx, p, now); !errors.Is(err, ErrStale) {
			t.Fatalf("time %d: %v", now, err)
		}
	}
	p.Evidence.InventoryAt = fixtureNow - MaxInventoryAgeSeconds
	p.Evidence.MetadataRefreshedAt = fixtureNow - MaxMetadataAgeSeconds
	if err := CheckFresh(ctx, p, fixtureNow); err != nil {
		t.Fatal("inclusive age boundary", err)
	}
	if err := CheckFresh(ctx, p, fixtureNow+1); !errors.Is(err, ErrStale) {
		t.Fatal("original ages refreshed", err)
	}
}
func TestBinaryRebuildAndDefaultMapping(t *testing.T) {
	p := fixture(t)
	p.Packages[0].From.Version = "1.0-1+b1"
	p.Packages[0].To.Version = "1.0-1+b2"
	p.Packages[0].To.SourceVersion = p.Packages[0].From.SourceVersion
	if _, err := Encode(context.Background(), p); err != nil {
		t.Fatal("source version equality is allowed", err)
	}
	p = fixture(t)
	p.Packages[0].From.SourceMapping = "binary-default"
	p.Packages[0].To.SourceMapping = "binary-default"
	if _, err := Encode(context.Background(), p); err != nil {
		t.Fatal(err)
	}
}

func TestEveryBindingChangesDigest(t *testing.T) {
	changes := map[string]func(*Plan){
		"endpoint":    func(p *Plan) { p.EndpointID = "agent_" + strings.Repeat("b", 32) },
		"incarnation": func(p *Plan) { p.IncarnationDigest = hash("other") },
		"policy":      func(p *Plan) { p.RootPolicyDigest = hash("other") },
		"release":     func(p *Plan) { p.Release = "ubuntu-24.04-noble"; p.Packages[0].Archive.Release = p.Release },
		"created":     func(p *Plan) { p.CreatedAt++ }, "expiry": func(p *Plan) { p.ExpiresAt++ },
		"inventory":         func(p *Plan) { p.Evidence.InventoryDigest = hash("other") },
		"inventoryAt":       func(p *Plan) { p.Evidence.InventoryAt++ },
		"dpkg":              func(p *Plan) { p.Evidence.DpkgStateDigest = hash("other") },
		"holds":             func(p *Plan) { p.Evidence.HoldsDigest = hash("other") },
		"refreshAt":         func(p *Plan) { p.Evidence.MetadataRefreshedAt++ },
		"hooks":             func(p *Plan) { p.Evidence.HookPolicyDigest = hash("other") },
		"config":            func(p *Plan) { p.Evidence.ConfigDigest = hash("other") },
		"binary":            func(p *Plan) { p.Packages[0].Name = "other-bin" },
		"arch":              func(p *Plan) { p.Packages[0].Architecture = "i386" },
		"fromVersion":       func(p *Plan) { p.Packages[0].From.Version = "1.0-0" },
		"fromSource":        func(p *Plan) { p.Packages[0].From.SourcePackage = "other-source" },
		"fromSourceVersion": func(p *Plan) { p.Packages[0].From.SourceVersion = "1.0-0" },
		"fromMapping":       func(p *Plan) { p.Packages[0].From.SourceMapping = "binary-default" },
		"fromMultiarch":     func(p *Plan) { p.Packages[0].From.MultiArch = "foreign" },
		"toVersion":         func(p *Plan) { p.Packages[0].To.Version = "1.0-3" },
		"toSource":          func(p *Plan) { p.Packages[0].To.SourcePackage = "other-source" },
		"toSourceVersion":   func(p *Plan) { p.Packages[0].To.SourceVersion = "1.0-3" },
		"toMapping":         func(p *Plan) { p.Packages[0].To.SourceMapping = "binary-default" },
		"toMultiarch":       func(p *Plan) { p.Packages[0].To.MultiArch = "foreign" },
		"archiveHash":       func(p *Plan) { p.Packages[0].Archive.SHA256 = hash("other") },
		"archiveSize":       func(p *Plan) { p.Packages[0].Archive.Size++ },
		"archiveFilename":   func(p *Plan) { p.Packages[0].Archive.Filename = "pool/other.deb" },
		"sourceIdentity":    func(p *Plan) { p.Packages[0].Archive.SourceIdentityDigest = hash("other") },
		"releaseDigest":     func(p *Plan) { p.Packages[0].Archive.ReleaseDigest = hash("other") },
		"indexDigest":       func(p *Plan) { p.Packages[0].Archive.IndexDigest = hash("other") },
		"indexPath":         func(p *Plan) { p.Packages[0].Archive.IndexPath = "main/binary-i386/Packages" },
	}
	original, err := Digest(context.Background(), fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			p := fixture(t)
			change(&p)
			got, err := Digest(context.Background(), p)
			if err != nil || got == original {
				t.Fatal("binding was lost", err)
			}
		})
	}
}
func TestCancellationAndNilContext(t *testing.T) {
	p := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	raw := fixtureBytes(t, "single.hook")
	for _, err := range []error{CheckFresh(ctx, p, fixtureNow), Match(ctx, p, fixtureNow, raw, archive(p))} {
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	if _, err := Encode(ctx, p); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := Decode(ctx, fixtureBytes(t, "plan.json")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := ParseHook(ctx, raw); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := Encode(nil, p); err == nil {
		t.Fatal("nil context")
	}
	if _, err := ParseHook(nil, raw); err == nil {
		t.Fatal("nil context")
	}
}
func FuzzDecode(f *testing.F) {
	raw, err := os.ReadFile("testdata/plan.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := Decode(context.Background(), raw)
		if err == nil {
			got, err := Encode(context.Background(), p)
			if err != nil || !bytes.Equal(raw, got) {
				t.Fatal("noncanonical success")
			}
		}
	})
}
func TestNoCachedObservationCoercion(t *testing.T) {
	// Mimic the cached wire shape without depending on or invoking its collector.
	raw, _ := json.Marshal(map[string]any{"schemaVersion": "tracebolt.complete-cached-apt-updates.v1", "metadata": map[string]string{"freshness": "unknown", "refresh": "not_attempted"}, "items": []any{}})
	if _, err := Decode(context.Background(), raw); err == nil {
		t.Fatal("cached candidates are not plans")
	}
}

func TestCanonicalTupleOrderForPrefixNames(t *testing.T) {
	p := fixture(t)
	first := p.Packages[0]
	first.Name = "aa"
	p.Packages = []Upgrade{first}
	for _, name := range []string{"aa+extension", "aa-tools", "aa.extra"} {
		u := first
		u.Name = name
		p.Packages = append(p.Packages, u)
	}
	if _, err := Encode(context.Background(), p); err != nil {
		t.Fatal("binary names sort before architecture", err)
	}
	p.Packages[0], p.Packages[1] = p.Packages[1], p.Packages[0]
	if _, err := Encode(context.Background(), p); err == nil {
		t.Fatal("noncanonical tuple order accepted")
	}
}
