package packageplan

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestHookFixturesAndMultiarch(t *testing.T) {
	p := fixture(t)
	ctx := context.Background()
	raw := fixtureBytes(t, "single.hook")
	h, err := ParseHook(ctx, raw)
	if err != nil || len(h.Operations) != 2 || h.ConfigDigest != p.Evidence.ConfigDigest {
		t.Fatal(h, err)
	}
	if err := Match(ctx, p, fixtureNow, raw, archive(p)); err != nil {
		t.Fatal(err)
	}
	// These two architecture-distinct binaries share a name, not archive identity.
	second := p.Packages[0]
	second.Architecture = "i386"
	second.Archive.SHA256 = hash("synthetic archive i386")
	second.Archive.Filename = "pool/main/s/sample-bin/sample-bin_1.0-2_i386.deb"
	second.Archive.IndexPath = "main/binary-i386/Packages"
	p.Packages = append(p.Packages, second)
	observations := append(archive(p), ObservedArchive{Path: "/var/cache/apt/archives/sample-bin_1.0-2_i386.deb", SHA256: second.Archive.SHA256, Size: second.Archive.Size})
	raw = fixtureBytes(t, "multiarch.hook")
	if err := Match(ctx, p, fixtureNow, raw, observations); err != nil {
		t.Fatal(err)
	}
	// Cross-package interleaving is valid; per-package configure must follow unpack.
	lines := strings.Split(string(raw), "\n")
	lines[len(lines)-4], lines[len(lines)-3] = lines[len(lines)-3], lines[len(lines)-4]
	if err := Match(ctx, p, fixtureNow, []byte(strings.Join(lines, "\n")), observations); err != nil {
		t.Fatal("interleaving", err)
	}
	observations[1].SHA256 = observations[0].SHA256
	if err := Match(ctx, p, fixtureNow, raw, observations); !errors.Is(err, ErrMismatch) {
		t.Fatal("arch hash mismatch", err)
	}
}
func TestProtocolNoneAlias(t *testing.T) {
	p := fixture(t)
	p.Packages[0].From.MultiArch = "no"
	p.Packages[0].To.MultiArch = "no"
	for _, ma := range []string{"none", "no"} {
		raw := bytes.ReplaceAll(fixtureBytes(t, "single.hook"), []byte(" same "), []byte(" "+ma+" "))
		if err := Match(context.Background(), p, fixtureNow, raw, archive(p)); err != nil {
			t.Fatal(ma, err)
		}
	}
}
func TestConfigurationIsAnExactOrderedBlock(t *testing.T) {
	p := fixture(t)
	raw := fixtureBytes(t, "single.hook")
	ctx := context.Background()
	marker := []byte("\n\nsample-bin")
	start := len("VERSION 3\n")
	end := bytes.Index(raw, marker) + 1
	if hash(string(raw[start:end])) != p.Evidence.ConfigDigest {
		t.Fatal("wrong newline boundary")
	}
	mutations := map[string][]byte{
		"addDuplicateList": bytes.Replace(raw, []byte("APT::Architectures::=i386\n"), []byte("APT::Architectures::=i386\nAPT::Architectures::=i386\n"), 1),
		"listOrder":        bytes.Replace(raw, []byte("APT::Architectures::=amd64\nAPT::Architectures::=i386\n"), []byte("APT::Architectures::=i386\nAPT::Architectures::=amd64\n"), 1),
		"escaping":         bytes.Replace(raw, []byte("a=b+c%20d"), []byte("a=b%2Bc%20d"), 1),
		"caseEscaping":     bytes.Replace(raw, []byte("a=b+c%20d"), []byte("a=b%2bc%20d"), 1),
		"extraEquals":      bytes.Replace(raw, []byte("a=b+c%20d"), []byte("a=b=c+d"), 1),
	}
	for name, b := range mutations {
		t.Run(name, func(t *testing.T) {
			h, err := ParseHook(ctx, b)
			if err != nil {
				t.Fatal("valid config syntax", err)
			}
			if h.ConfigDigest == p.Evidence.ConfigDigest {
				t.Fatal("config was normalized")
			}
			if err := Match(ctx, p, fixtureNow, b, archive(p)); !errors.Is(err, ErrMismatch) {
				t.Fatal(err)
			}
		})
	}
	// APT preserves repeated list keys. They are not duplicate object keys.
	p.Evidence.ConfigDigest = hash(string(mutations["addDuplicateList"][start : bytes.Index(mutations["addDuplicateList"], marker)+1]))
	if err := Match(ctx, p, fixtureNow, mutations["addDuplicateList"], archive(p)); err != nil {
		t.Fatal(err)
	}
}
func TestMalformedProtocol(t *testing.T) {
	raw := fixtureBytes(t, "single.hook")
	replace := func(a, b string) []byte { return bytes.Replace(raw, []byte(a), []byte(b), 1) }
	configEnd := bytes.Index(raw, []byte("\n\n")) + 2
	cases := map[string][]byte{
		"nil": nil, "v1": []byte("/var/cache/apt/archives/file.deb\n"), "v2": replace("VERSION 3", "VERSION 2"), "v4": replace("VERSION 3", "VERSION 4"),
		"missingFinalLF": raw[:len(raw)-1], "CRLF": bytes.ReplaceAll(raw, []byte("\n"), []byte("\r\n")), "NUL": append(bytes.Clone(raw), 0),
		"trailingBlank": append(bytes.Clone(raw), '\n'), "trailingGarbage": append(bytes.Clone(raw), []byte("garbage\n")...),
		"noSeparator": bytes.Replace(raw, []byte("\n\n"), []byte("\n"), 1), "missingSeparator": []byte("VERSION 3\n"), "noWork": raw[:configEnd],
		"badConfigEscape": replace("%20", "%Q0"), "shortEscape": replace("%20d", "%"), "configControl": replace("a=b+c%20d", "a=\td"),
		"configSpace": replace("a=b+c%20d", "a b"), "configNoKey": replace("Fixture::Value=", "="), "configEmpty": replace("a=b+c%20d", ""),
		"configQuoteKey": replace("Fixture::Value", "Fixture::\"Value"), "configNoEquals": replace("Fixture::Value=a=b+c%20d", "Fixture::Value"),
		"missingField": replace("amd64 same <", "amd64 <"), "extraField": replace("amd64 same <", "amd64 same extra <"), "repeatedSpace": replace("same <", "same  <"),
		"tabSeparated": replace("sample-bin 1.0-1", "sample-bin\t1.0-1"), "qualifiedName": replace("sample-bin 1.0-1", "sample-bin:amd64 1.0-1"),
		"unknownVersion": replace("1.0-1", "unknown"), "newPackage": replace("1.0-1 amd64 same", "- - none"), "downgrade": replace(" < ", " > "), "equal": replace(" < ", " = "),
		"lyingOrder": bytes.ReplaceAll(raw, []byte("1.0-2"), []byte("0.9-1")), "unknownEpoch": replace("1.0-2", "2147483648:1"),
		"unknownOldMultiarch": replace("amd64 same <", "amd64 mystery <"), "unknownNewMultiarch": replace("1.0-2 amd64 same", "1.0-2 amd64 mystery"),
		"crossgrade": replace("1.0-2 amd64 same", "1.0-2 i386 same"), "sourceArchitecture": bytes.ReplaceAll(raw, []byte("amd64 same"), []byte("source same")),
		"remove": replace("**CONFIGURE**", "**REMOVE**"), "errorMarker": replace("**CONFIGURE**", "**ERROR**"), "unknownAction": replace("**CONFIGURE**", "**TRIGGERS**"),
		"relative": replace("/var/cache/apt/archives/", "var/cache/apt/archives/"), "traversal": replace("/var/cache/apt/archives/", "/var/../archives/"),
		"duplicateSeparator": replace("/var/cache/apt/archives/", "/var//cache/apt/archives/"), "encodedPath": replace("/var/cache/apt/archives/", "/var/cache/%2e%2e/"),
		"nonDeb": replace("amd64.deb", "amd64.tar"), "pathControl": replace("amd64.deb", "amd64\t.deb"),
		"oversized": bytes.Repeat([]byte("x"), MaxHookBytes+1), "longLine": []byte("VERSION 3\nK=" + strings.Repeat("x", MaxHookLineBytes) + "\n\n"),
		"tooManyConfigLines": []byte("VERSION 3\n" + strings.Repeat("K=x\n", MaxConfigLines+1) + "\n"),
		"configByteLimit":    []byte("VERSION 3\n" + strings.Repeat("K="+strings.Repeat("x", 4093)+"\n", 33) + "\n"),
		"operationLimit":     append(bytes.Clone(raw[:configEnd]), bytes.Repeat([]byte("sample-bin 1.0-1 amd64 same < 1.0-2 amd64 same **CONFIGURE**\n"), MaxOperations+1)...),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseHook(context.Background(), b); !errors.Is(err, ErrProtocol) {
				t.Fatal("malformed protocol admitted", err)
			}
		})
	}
}
func TestExactOperationAndArchiveBijection(t *testing.T) {
	raw := fixtureBytes(t, "single.hook")
	offset := bytes.Index(raw, []byte("\n\n")) + 2
	rows := strings.Split(strings.TrimSuffix(string(raw[offset:]), "\n"), "\n")
	reassemble := func(r ...string) []byte {
		return append(bytes.Clone(raw[:offset]), []byte(strings.Join(r, "\n")+"\n")...)
	}
	cases := map[string][]byte{
		"duplicateUnpack": reassemble(rows[0], rows[0]), "duplicateConfigure": reassemble(rows[1], rows[1]), "configureFirst": reassemble(rows[1], rows[0]),
		"missingConfigure": reassemble(rows[0]), "missingUnpack": reassemble(rows[1]), "extraOperation": reassemble(rows[0], rows[1], rows[1]),
		"unexpectedPackage": bytes.ReplaceAll(raw, []byte("sample-bin 1.0"), []byte("other-bin 1.0")),
		"unapprovedOld":     bytes.ReplaceAll(raw, []byte("1.0-1"), []byte("1.0-0")), "unapprovedNew": bytes.ReplaceAll(raw, []byte("1.0-2"), []byte("1.0-3")),
		"unapprovedMultiarch": bytes.ReplaceAll(raw, []byte(" same "), []byte(" foreign ")),
		"wrongArch":           bytes.ReplaceAll(raw, []byte("amd64 same"), []byte("i386 same")),
		"differentPath":       bytes.ReplaceAll(raw, []byte("/var/cache/apt/archives/"), []byte("/tmp/")),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			p := fixture(t)
			if err := Match(context.Background(), p, fixtureNow, b, archive(p)); !errors.Is(err, ErrMismatch) {
				t.Fatal("unexpected match", err)
			}
		})
	}
	archiveCases := map[string]func([]ObservedArchive) []ObservedArchive{
		"missing": func(a []ObservedArchive) []ObservedArchive { return nil }, "extra": func(a []ObservedArchive) []ObservedArchive { return append(a, a[0]) },
		"hash": func(a []ObservedArchive) []ObservedArchive { a[0].SHA256 = hash("replaced bytes"); return a }, "size": func(a []ObservedArchive) []ObservedArchive { a[0].Size++; return a },
		"invalidHash": func(a []ObservedArchive) []ObservedArchive { a[0].SHA256 = ""; return a }, "relative": func(a []ObservedArchive) []ObservedArchive { a[0].Path = "file.deb"; return a },
		"traversal": func(a []ObservedArchive) []ObservedArchive { a[0].Path = "/var/../file.deb"; return a }, "zeroSize": func(a []ObservedArchive) []ObservedArchive { a[0].Size = 0; return a },
	}
	for name, change := range archiveCases {
		t.Run(name, func(t *testing.T) {
			p := fixture(t)
			if err := Match(context.Background(), p, fixtureNow, raw, change(archive(p))); !errors.Is(err, ErrMismatch) {
				t.Fatal(err)
			}
		})
	}
	p := fixture(t)
	if err := Match(context.Background(), p, fixtureNow+51, raw, archive(p)); !errors.Is(err, ErrStale) {
		t.Fatal("stale original inventory", err)
	}
}
func TestDuplicateAndReusedArchivePaths(t *testing.T) {
	p := fixture(t)
	second := p.Packages[0]
	second.Architecture = "i386"
	p.Packages = append(p.Packages, second)
	observations := append(archive(p), archive(p)[0])
	raw := fixtureBytes(t, "multiarch.hook")
	if err := Match(context.Background(), p, fixtureNow, raw, observations); !errors.Is(err, ErrMismatch) {
		t.Fatal("duplicate path", err)
	}
	observations[1].Path = "/var/cache/apt/archives/sample-bin_1.0-2_i386.deb"
	raw = bytes.ReplaceAll(raw, []byte("sample-bin_1.0-2_i386.deb"), []byte("sample-bin_1.0-2_amd64.deb"))
	if err := Match(context.Background(), p, fixtureNow, raw, observations); !errors.Is(err, ErrMismatch) {
		t.Fatal("reused path", err)
	}
}
func TestRepeatedPureCallsDoNotPretendToConsume(t *testing.T) {
	p := fixture(t)
	for i := 0; i < 2; i++ {
		if err := Match(context.Background(), p, fixtureNow, fixtureBytes(t, "single.hook"), archive(p)); err != nil {
			t.Fatal(err)
		}
	}
	// This deliberately documents stateless equality, not durable job admission.
}
func FuzzParseHook(f *testing.F) {
	f.Add([]byte("VERSION 3\n\nsample-bin 1.0-1 amd64 none < 1.0-2 amd64 no **CONFIGURE**\n"))
	f.Add([]byte("VERSION 3\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		h, err := ParseHook(context.Background(), raw)
		if err == nil && (len(h.Operations) == 0 || len(h.Operations) > MaxOperations || h.ConfigDigest == "") {
			t.Fatal("unbounded/empty result")
		}
	})
}
