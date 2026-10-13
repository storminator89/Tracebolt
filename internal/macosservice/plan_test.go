package macosservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"
)

func fixtureRequest() Request {
	return Request{ServiceIdentity: "510:510", AgentSHA256: strings.Repeat("a", 64), SourceArchive: "/Library/TraceboltReview/source.tar", SourceSHA256: strings.Repeat("b", 64)}
}

type fixtureBackend struct {
	calls  int
	checks []Check
	err    error
}

func (b *fixtureBackend) Inspect(context.Context, Request) ([]Check, error) {
	b.calls++
	return b.checks, b.err
}
func allChecks() []Check {
	out := []Check{}
	for _, code := range checkOrder {
		out = append(out, Check{Code: code, Passed: true})
	}
	return out
}

func TestPlanDeterministicInertPlist(t *testing.T) {
	request := fixtureRequest()
	a, err := Plan(request)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Plan(request)
	if err != nil || a.Plist != b.Plist || a.PlistSHA256 != b.PlistSHA256 {
		t.Fatal("nondeterministic")
	}
	sum := sha256.Sum256([]byte(a.Plist))
	if a.PlistSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("wrong plist hash")
	}
	if !a.ReadOnly || a.LocalChecksPerformed || a.LocalPreflightPassed || a.InstallationAvailable || a.ReadyForInstallation {
		t.Fatal("plan claimed native readiness")
	}
	decoder := xml.NewDecoder(strings.NewReader(a.Plist))
	for {
		_, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, required := range []string{"<key>UserName</key><string>" + Account + "</string>", "<key>GroupName</key><string>" + Account + "</string>", "<key>InitGroups</key><false/>", "<key>Umask</key><integer>63</integer>", "<key>ExitTimeOut</key><integer>30</integer>", "<string>--service-identity</string><string>510:510</string>", "<string>--foreground</string>", "<string>--interval</string><string>30s</string>", "<string>" + ConfigPath + "</string>", "<string>" + AgentPath + "</string>"} {
		if !strings.Contains(a.Plist, required) {
			t.Fatalf("missing %q", required)
		}
	}
	for _, forbidden := range []string{"/bin/sh", "launchctl", "--pending", "--insecure", "--enrollment", "--validate", "StandardOutPath", "StandardErrorPath", "EnvironmentVariables", "SERVICE_IDENTITY"} {
		if strings.Contains(a.Plist, forbidden) {
			t.Fatalf("unexpected %q", forbidden)
		}
	}
}
func TestRequestStrict(t *testing.T) {
	for _, raw := range []string{"", "0:510", "510:0", "-1:510", "+510:510", "0510:510", "510:0510", "510:510:510", "510:4294967295", "4294967296:510", "510:510\n", "510:510</string>"} {
		r := fixtureRequest()
		r.ServiceIdentity = raw
		if _, err := Plan(r); !errors.Is(err, ErrRequest) {
			t.Fatalf("accepted identity %q", raw)
		}
	}
	for _, raw := range []string{"", "relative.tar", "/a/../b", "/a/./b", "/", "//a", "/a/", "/a\nfile", AgentPath, ConfigPath, PlistPath, InstallDirectory, StateDirectory + "/foo"} {
		r := fixtureRequest()
		r.SourceArchive = raw
		if _, err := Plan(r); !errors.Is(err, ErrRequest) {
			t.Fatalf("accepted source %q", raw)
		}
	}
	for _, raw := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("z", 64)} {
		r := fixtureRequest()
		r.AgentSHA256 = raw
		if _, err := Plan(r); !errors.Is(err, ErrRequest) {
			t.Fatal("bad binary digest")
		}
		r = fixtureRequest()
		r.SourceSHA256 = raw
		if _, err := Plan(r); !errors.Is(err, ErrRequest) {
			t.Fatal("bad source digest")
		}
	}
}
func TestRenderNeverInspects(t *testing.T) {
	r := fixtureRequest()
	r.RenderOnly = true
	b := &fixtureBackend{err: errors.New("must not inspect")}
	p, err := Execute(context.Background(), r, b)
	if err != nil || b.calls != 0 || p.LocalChecksPerformed || p.LocalPreflightPassed {
		t.Fatal("render inspected host")
	}
}
func TestPreflightRequiresCompleteOrderedEvidence(t *testing.T) {
	tests := []struct {
		name   string
		checks []Check
		err    error
	}{{"missing", nil, nil}, {"partial", allChecks()[:3], nil}, {"failed", allChecks(), nil}, {"reordered", allChecks(), nil}, {"error", allChecks(), errors.New("blocked")}, {"extra", append(allChecks(), Check{Code: "extra", Passed: true}), nil}}
	tests[2].checks[3].Passed = false
	tests[3].checks[1], tests[3].checks[2] = tests[3].checks[2], tests[3].checks[1]
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := &fixtureBackend{checks: test.checks, err: test.err}
			p, err := Execute(context.Background(), fixtureRequest(), b)
			if !errors.Is(err, ErrPreflight) || !p.LocalChecksPerformed || p.LocalPreflightPassed || p.ReadyForInstallation || p.InstallationAvailable || b.calls != 1 {
				t.Fatal("incomplete preflight accepted")
			}
		})
	}
	b := &fixtureBackend{checks: allChecks()}
	p, err := Execute(context.Background(), fixtureRequest(), b)
	if err != nil || !p.LocalChecksPerformed || !p.LocalPreflightPassed || p.InstallationAvailable || p.ReadyForInstallation {
		t.Fatal("bad successful local-only result")
	}
}
func TestCancellationAndInvalidRequestAvoidInspection(t *testing.T) {
	b := &fixtureBackend{checks: allChecks()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Execute(ctx, fixtureRequest(), b); err == nil || b.calls != 0 {
		t.Fatal("canceled inspection")
	}
	r := fixtureRequest()
	r.ServiceIdentity = "0:0"
	if _, err := Execute(context.Background(), r, b); err == nil || b.calls != 0 {
		t.Fatal("invalid inspection")
	}
	if _, err := Execute(nil, fixtureRequest(), b); err == nil || b.calls != 0 {
		t.Fatal("nil context")
	}
	if _, err := Execute(context.Background(), fixtureRequest(), nil); err == nil {
		t.Fatal("nil backend")
	}
}
func TestSourceHashIsBoundedExactAndCancelable(t *testing.T) {
	raw := []byte("inert source fixture")
	sum := sha256.Sum256(raw)
	want := hex.EncodeToString(sum[:])
	ctx := context.Background()
	if hashArtifact(ctx, bytes.NewReader(raw), int64(len(raw)), want) != nil {
		t.Fatal("valid source")
	}
	for _, size := range []int64{0, int64(len(raw) - 1), int64(len(raw) + 1), MaxSourceBytes + 1} {
		if hashArtifact(ctx, bytes.NewReader(raw), size, want) == nil {
			t.Fatal("bad size accepted")
		}
	}
	if hashArtifact(ctx, bytes.NewReader(raw), int64(len(raw)), strings.Repeat("0", 64)) == nil {
		t.Fatal("wrong hash")
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if hashArtifact(ctx, bytes.NewReader(raw), int64(len(raw)), want) == nil {
		t.Fatal("canceled hash")
	}
}
