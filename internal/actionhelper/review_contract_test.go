//go:build linux

package actionhelper

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
)

func uncheckedImpactDigestForReview(list []string) string {
	raw, _ := json.Marshal(struct {
		Version  string   `json:"version"`
		Services []string `json:"services"`
	}{"tracebolt.service-action-affected-services.v2", list})
	return actionpermit.Digest(raw)
}
func signedReviewImpactRequest(t *testing.T, f *runtimeFixture, b *fullAdminRuntimeBackend, digest string) (Request, error) {
	t.Helper()
	r := requestV2(t, f, b, 1)
	p, e := actionpermit.Decode(r.Envelope)
	if e != nil {
		t.Fatal(e)
	}
	p.Plan.AffectedServicesDigest = digest
	p.PlanDigest, e = actionpermit.PlanDigest(p.Plan)
	if e != nil {
		return Request{}, e
	}
	msg, e := actionpermit.SigningMessage(p)
	if e != nil {
		return Request{}, e
	}
	r.Envelope, e = actionpermit.Encode(p, ed25519.Sign(f.key, msg))
	return r, e
}
func countReviewStarts(graph *fullAdminFixture) int {
	starts := 0
	for _, args := range graph.commands {
		if len(args) > 2 && args[len(args)-3] == "try-restart" {
			starts++
		}
	}
	return starts
}

// The original reviewer fixture's two-service real backend is preserved. Only
// injected command/file fixtures run; there is no real systemctl invocation.
func TestReviewRootHelperRejectsMisstatedApprovedAffectedProjection(t *testing.T) {
	cases := map[string][]string{"missing": nil, "shortened": {"sshd.service"}, "added": {"dependent.service", "extra.service", "sshd.service"}, "reordered": {"sshd.service", "dependent.service"}, "duplicate": {"dependent.service", "dependent.service", "sshd.service"}, "exact": {"dependent.service", "sshd.service"}}
	for name, list := range cases {
		t.Run(name, func(t *testing.T) {
			f, b := newRuntimeV2(t)
			graph := fixtureV2(t, "sshd.service")
			graph.add("dependent.service")
			graph.properties["sshd.service"]["RequiredBy"] = "dependent.service"
			actual := &fullAdminSystemdBackend{source: graph.source(t)}
			inspected, e := actual.InspectService(context.Background(), "sshd.service")
			if e != nil || len(inspected.AffectedServices) != 2 {
				t.Fatal(inspected, e)
			}
			b.inspection = inspected
			f.s.inner.deps.Backend = actual
			digest := uncheckedImpactDigestForReview(list)
			if name == "missing" {
				digest = ""
			}
			request, e := signedReviewImpactRequest(t, f, b, digest)
			if name == "missing" {
				if e == nil {
					t.Fatal("missing projection signed")
				}
				if countReviewStarts(graph) != 0 {
					t.Fatal("effect before rejected signing")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			permit, _ := actionpermit.Decode(request.Envelope)
			result, e := f.s.Handle(context.Background(), f.peer, request)
			if name == "exact" {
				if e != nil || result.Phase != actionstate.OperationCompleted || countReviewStarts(graph) != 1 {
					t.Fatal(result, e, countReviewStarts(graph))
				}
				return
			}
			if e == nil || countReviewStarts(graph) != 0 {
				t.Fatal("misstated affected services executed", result, e)
			}
			if _, e = f.state.Status(context.Background(), permit.JobID); !errors.Is(e, actionstate.ErrNotFound) {
				t.Fatal("mismatched projection consumed before rejection", e)
			}
		})
	}
}

type reviewImpactCheckingBackend struct {
	*fullAdminSystemdBackend
	want  string
	calls int
	t     *testing.T
}

func (b *reviewImpactCheckingBackend) Check(ctx context.Context, target Target) (Observation, error) {
	b.calls++
	if target.AffectedServicesDigest != b.want {
		b.t.Fatal("signed projection lost before check", b.calls, target.AffectedServicesDigest)
	}
	return b.fullAdminSystemdBackend.Check(ctx, target)
}
func TestReviewTrustedImpactRecheckedBeforeAdmissionAndFinalDispatch(t *testing.T) {
	for _, driftAt := range []int{0, 1, 2, 3} {
		t.Run(fmt.Sprint(driftAt), func(t *testing.T) {
			f, b := newRuntimeV2(t)
			graph := fixtureV2(t, "sshd.service")
			graph.add("dependent.service")
			graph.properties["sshd.service"]["RequiredBy"] = "dependent.service"
			actual := &fullAdminSystemdBackend{source: graph.source(t)}
			initial, e := actual.InspectService(context.Background(), "sshd.service")
			if e != nil {
				t.Fatal(e)
			}
			b.inspection = initial
			request := requestV2(t, f, b, 1)
			permit, _ := actionpermit.Decode(request.Envelope)
			checking := &reviewImpactCheckingBackend{fullAdminSystemdBackend: actual, want: permit.Plan.AffectedServicesDigest, t: t}
			f.s.inner.deps.Backend = checking
			graph.calls = map[string]int{}
			graph.hook = func(unit string, n int) {
				if driftAt > 0 && unit == "sshd.service" && n == (driftAt-1)*2+1 {
					graph.add("extra.service")
					graph.properties[unit]["RequiredBy"] = "dependent.service extra.service"
				}
			}
			result, e := f.s.Handle(context.Background(), f.peer, request)
			if driftAt == 0 {
				if e != nil || checking.calls != 3 || countReviewStarts(graph) != 1 {
					t.Fatal(result, e, checking.calls)
				}
				return
			}
			if checking.calls != driftAt || countReviewStarts(graph) != 0 {
				t.Fatal("graph drift reached effects", checking.calls, countReviewStarts(graph))
			}
			if driftAt == 1 {
				if e == nil {
					t.Fatal("admitted drift")
				}
				if _, e = f.state.Status(context.Background(), permit.JobID); !errors.Is(e, actionstate.ErrNotFound) {
					t.Fatal(e)
				}
			} else if e != nil || result.Phase != actionstate.NotStarted {
				t.Fatal(result, e)
			}
		})
	}
}
