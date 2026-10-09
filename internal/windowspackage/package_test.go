package windowspackage

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"localrmm/internal/windowsservice"
)

type fakeSession struct {
	events          []string
	fail            string
	cancel          context.CancelFunc
	cancelAfter     string
	writes          map[objectRole][]byte
	payloadMutation []byte
}

func (s *fakeSession) step(name string) error {
	s.events = append(s.events, name)
	if s.cancelAfter == name {
		s.cancel()
	}
	if s.fail == name {
		return failure("fixture-failure")
	}
	return nil
}
func (s *fakeSession) open(ctx context.Context) (session, error) {
	if err := s.step("open"); err != nil {
		return nil, err
	}
	if s.payloadMutation != nil {
		s.payloadMutation[700]++
	}
	return s, nil
}
func (*fakeSession) Layout() windowsservice.Layout {
	return windowsservice.Layout{Executable: `C:\Program Files\Tracebolt\tracebolt-windows-service.exe`}
}
func (*fakeSession) BootstrapPath() string {
	return `C:\ProgramData\Tracebolt\windows-setup\bootstrap.json`
}
func (s *fakeSession) CheckFresh(context.Context) error { return s.step("fresh") }
func (s *fakeSession) CreateDirectory(_ context.Context, r objectRole) error {
	return s.step(roleName(r))
}
func (s *fakeSession) WriteFile(_ context.Context, r objectRole, raw []byte) error {
	if s.writes == nil {
		s.writes = map[objectRole][]byte{}
	}
	s.writes[r] = append([]byte(nil), raw...)
	return s.step(roleName(r))
}
func (s *fakeSession) Verify(context.Context) error { return s.step("verify") }
func (s *fakeSession) Close() error                 { return s.step("close") }
func roleName(r objectRole) string {
	return []string{"program-files", "program-data", "setup-directory", "service-file", "bootstrap-file", "manifest-file"}[r]
}
func TestProvisionOrderingAndPinLifetime(t *testing.T) {
	payload := fixturePE("amd64")
	m := fixtureManifest(payload, "amd64")
	bootstrap := []byte("public-bootstrap")
	fake := &fakeSession{payloadMutation: payload}
	result, err := provisionWith(context.Background(), payload, m, bootstrap, "amd64", fake.open)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"open", "fresh", "program-files", "program-data", "setup-directory", "service-file", "bootstrap-file", "manifest-file", "verify"}
	if !reflect.DeepEqual(fake.events, want) {
		t.Fatal(fake.events)
	}
	if !result.Retained || result.BootstrapPath == "" || result.Layout.Executable == "" {
		t.Fatal("incomplete result")
	}
	if err := m.Validate(fake.writes[serviceFile]); err != nil {
		t.Fatal("caller mutation changed pinned snapshot", err)
	}
	parsed, err := ParseManifest(fake.writes[manifestFile])
	if err != nil || parsed != m {
		t.Fatal("retained provenance differs")
	}
	if string(fake.writes[bootstrapFile]) != string(bootstrap) {
		t.Fatal("bootstrap changed")
	}
	if err := result.Close(); err != nil {
		t.Fatal(err)
	}
	copyResult := result
	if err := copyResult.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fake.events, append(want, "close")) {
		t.Fatal("pins closed early or twice", fake.events)
	}
}
func TestProvisionEveryFailureRetainsAndNeverContinues(t *testing.T) {
	steps := []string{"open", "fresh", "program-files", "program-data", "setup-directory", "service-file", "bootstrap-file", "manifest-file", "verify"}
	for index, step := range steps {
		t.Run(step, func(t *testing.T) {
			p := fixturePE("amd64")
			m := fixtureManifest(p, "amd64")
			fake := &fakeSession{fail: step}
			result, err := provisionWith(context.Background(), p, m, []byte("public"), "amd64", fake.open)
			if err == nil {
				t.Fatal("failure swallowed")
			}
			want := append([]string(nil), steps[:index+1]...)
			if index > 0 {
				want = append(want, "close")
			}
			if !reflect.DeepEqual(fake.events, want) {
				t.Fatal(fake.events, want)
			}
			if result.Retained != (index >= 2) || result.BootstrapPath != "" {
				t.Fatal("incorrect partial result")
			}
			_ = result.Close()
			if !reflect.DeepEqual(fake.events, want) {
				t.Fatal("failure result retained leaked handles")
			}
		})
	}
}
func TestProvisionRejectsInputsWithoutNativeCalls(t *testing.T) {
	for _, tc := range []string{"nil-context", "cancelled", "manifest", "digest", "architecture", "empty-bootstrap", "oversize-bootstrap"} {
		t.Run(tc, func(t *testing.T) {
			ctx := context.Background()
			p := fixturePE("amd64")
			m := fixtureManifest(p, "amd64")
			bootstrap := []byte("public")
			arch := "amd64"
			switch tc {
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "manifest":
				m.SourceCommit = "no"
			case "digest":
				p[700]++
			case "architecture":
				arch = "arm64"
			case "empty-bootstrap":
				bootstrap = nil
			case "oversize-bootstrap":
				bootstrap = make([]byte, MaxBootstrapBytes+1)
			}
			fake := &fakeSession{}
			result, err := provisionWith(ctx, p, m, bootstrap, arch, fake.open)
			if err == nil || len(fake.events) != 0 || result.Retained {
				t.Fatal("invalid input performed native work")
			}
		})
	}
}
func TestProvisionCancellationAtEveryBoundary(t *testing.T) {
	steps := []string{"fresh", "program-files", "program-data", "setup-directory", "service-file", "bootstrap-file", "manifest-file", "verify"}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fake := &fakeSession{cancel: cancel, cancelAfter: step}
			p := fixturePE("amd64")
			_, err := provisionWith(ctx, p, fixtureManifest(p, "amd64"), []byte("public"), "amd64", fake.open)
			if Code(err) != "cancelled" {
				t.Fatal(err)
			}
			if fake.events[len(fake.events)-2] != step || fake.events[len(fake.events)-1] != "close" {
				t.Fatal("continued after cancellation", fake.events)
			}
		})
	}
}
func TestPreflightReadOnlyAndCloses(t *testing.T) {
	for _, fail := range []string{"", "open", "fresh", "close"} {
		fake := &fakeSession{fail: fail}
		err := preflightWith(context.Background(), fake.open)
		if (err == nil) != (fail == "") {
			t.Fatal("preflight swallowed failure", fail, err)
		}
		want := []string{"open", "fresh", "close"}
		if fail == "open" {
			want = want[:1]
		}
		if !reflect.DeepEqual(fake.events, want) {
			t.Fatal(fake.events)
		}
	}
}
func TestCloseFailureFiniteAndIdempotent(t *testing.T) {
	fake := &fakeSession{fail: "close"}
	r := Result{lease: &lease{session: fake}}
	if r.Close() == nil || r.Close() == nil || len(fake.events) != 1 {
		t.Fatal("close failure lost or retried")
	}
	var zero Result
	if zero.Close() != nil {
		t.Fatal("zero close failed")
	}
	var nilResult *Result
	if nilResult.Close() != nil {
		t.Fatal("nil close failed")
	}
	if Code(errors.New(`secret C:\private`)) != "package-failed" {
		t.Fatal("untrusted error inspected")
	}
	if !errors.Is(failure("file-create"), ErrPackage) || strings.Contains(failure("file-create").Error(), `C:\`) {
		t.Fatal("unsafe diagnostic")
	}
}
func TestAncestorExceptionKeepsDestructiveRights(t *testing.T) {
	strict, shared := ancestorWriteMask(false), ancestorWriteMask(true)
	if strict&^shared != 0x112 {
		t.Fatal("exception expanded")
	}
	for _, bit := range []uint32{0x10000000, 0x40000000, 0x80000, 0x40000, 0x10000, 0x40} {
		if shared&bit == 0 {
			t.Fatal("destructive right admitted")
		}
	}
}
