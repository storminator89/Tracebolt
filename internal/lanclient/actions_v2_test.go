package lanclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"testing"

	"localrmm/internal/actionhelper"
	"localrmm/internal/actionpermit"
	"localrmm/internal/actionwire"
)

func (h *actionHelperFixture) FullAdminCapabilities(ctx context.Context) (actionhelper.Capabilities, error) {
	return h.Capabilities(ctx)
}
func serviceActionFixtureV2(t *testing.T) *serviceActionFixture {
	t.Helper()
	f := serviceActionTestFixture(t)
	f.local.policy.Version = ActionClientPolicyVersionV2
	f.local.policy.Scope = actionhelper.FullAdminServiceScope
	c := &f.helper.caps
	c.Version = actionhelper.CapabilitiesVersionV2
	c.Scope = actionhelper.FullAdminServiceScope
	c.ReviewNotice = actionhelper.FullAdminReviewNotice
	c.Services[0].Unit = "sshd.service"
	c.Services[0].AffectedServices = []string{"sshd.service"}
	p, e := actionpermit.Decode(f.grant.Envelope)
	if e != nil {
		t.Fatal(e)
	}
	p.Version = actionpermit.VersionV2
	p.Plan.Version = actionpermit.PlanVersionV2
	p.Plan.Unit = "sshd.service"
	p.Plan.AffectedServicesDigest, _ = actionpermit.AffectedServicesDigest(c.Services[0].AffectedServices)
	p.PlanDigest, _ = actionpermit.PlanDigest(p.Plan)
	msg, _ := actionpermit.SigningMessage(p)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{37}, 32))
	f.grant.Envelope, e = actionpermit.Encode(p, ed25519.Sign(key, msg))
	if e != nil {
		t.Fatal(e)
	}
	f.grant.Identity.EnvelopeDigest = actionpermit.Digest(f.grant.Envelope)
	f.delivery.Identity = f.grant.Identity
	f.helper.result.EnvelopeDigest = f.grant.Identity.EnvelopeDigest
	exchange := f.s.exchange
	f.s.exchange = func(ctx context.Context, path string, seq uint64, raw []byte) ([]byte, int, error) {
		if path == actionwire.CapabilitiesPathV2 {
			if _, e := actionwire.DecodeCapabilitiesV2(raw); e != nil || seq != 1 {
				t.Fatal("wrong v2 report", e)
			}
			f.network++
			return []byte("{}"), http.StatusOK, nil
		}
		return exchange(ctx, path, seq, raw)
	}
	return f
}
func TestFullAdminSenderRequiresExplicitV2GrantAndFreshInspection(t *testing.T) {
	f := serviceActionFixtureV2(t)
	if e := validateActionLocal(f.local.policy, f.s.material, 1234, 1234); e != nil {
		t.Fatal(e)
	}
	if got := f.s.Run(context.Background()); got != "reported" || f.helper.submits != 1 || f.claims != 1 {
		t.Fatal(got, f.helper.submits, f.claims)
	}
	for _, kind := range []string{"v1_local", "scope_missing", "digest_drift", "missing_service"} {
		t.Run(kind, func(t *testing.T) {
			f := serviceActionFixtureV2(t)
			switch kind {
			case "v1_local":
				f.local.policy.Version = ActionClientPolicyVersion
				f.local.policy.Scope = ""
			case "scope_missing":
				f.local.policy.Scope = ""
			case "digest_drift":
				f.helper.capHook = func(n int) {
					if n == 2 {
						f.helper.caps.Services[0].UnitPolicyDigest = actionpermit.Digest([]byte("changed"))
					}
				}
			case "missing_service":
				f.helper.capHook = func(n int) {
					if n == 2 {
						f.helper.caps.Services = nil
					}
				}
			}
			f.s.Run(context.Background())
			if f.helper.submits != 0 {
				t.Fatal("scope or current inspection bypassed")
			}
		})
	}
}
