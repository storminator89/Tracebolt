//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"localrmm/internal/journalhelper"
	"localrmm/internal/journalpolicy"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalstate"
	"localrmm/internal/journalview"
	"localrmm/internal/journalwire"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This extends the existing real loopback TLS/HTTP fixture with the native
// consume/helper flow. The helper is synthetic; no native journal is opened.
func TestJournalNativeTLSAndSignedHTTPExactResultFlow(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			native := newJournalFixture(t)
			original := native.s.exchange
			var verifier *journalwire.Verifier
			f := integrationFixture(t, profile, func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var raw []byte
					var e error
					var sequence uint64
					if profile == "http-test" {
						verified, err := verifier.Verify(r)
						e = err
						raw = verified.Body
						sequence = verified.Sequence
					} else {
						if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
							t.Error("client-auth TLS absent")
							w.WriteHeader(403)
							return
						}
						raw, e = io.ReadAll(io.LimitReader(r.Body, journalwire.MaxBodyBytes+1))
						sequence = native.record.Description.Identity.Sequence
						if r.URL.Path == journalwire.PeekPath {
							sequence = 1
						}
					}
					if e != nil {
						t.Error("journal request authentication rejected")
						w.WriteHeader(403)
						return
					}
					body, code, e := original(r.Context(), r.URL.Path, sequence, raw)
					if e != nil {
						w.WriteHeader(500)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(code)
					w.Write(body)
				})
			})
			c := completeConfig(f.material.config)
			if InitializeGuidedState(c) != nil {
				t.Fatal("complete state fixture")
			}
			m, e := loadConfig(c)
			if e != nil {
				t.Fatal(e)
			}
			if profile == "http-test" {
				verifier, e = journalwire.New(journalwire.Config{Origin: m.config.ManagerOrigin, Registry: f.registry})
				if e != nil {
					t.Fatal(e)
				}
			}
			native.s.state.Close()
			native.s.material = m
			native.s.state, e = journalstate.Initialize(context.Background(), journalStateDirectory(m.config), m.binding)
			if e != nil {
				t.Fatal(e)
			}
			native.local.policy.SenderBinding = m.binding
			native.local.policy.ManagerOrigin = m.config.ManagerOrigin
			native.local.policy.TransportProfile = profile
			native.local.policy.PlaintextAcknowledged = profile == "http-test"
			native.record, e = journalrequest.New(m.config.AgentID, journalLeaf(m), 9, native.record.Description.Query, native.now)
			if e != nil {
				t.Fatal(e)
			}
			native.s.client = newHTTPClient(m.tlsConfig, profile == "http-test")
			native.s.exchange = native.s.request
			// Verify callback's original synthetic context is replaced too.
			native.s.helper = func(ctx context.Context, local journalLocal, request journalhelper.Request) (journalhelper.Response, error) {
				permit, e := journalpolicy.Authorize(local.policy, journalContext(m, local), request.Query, native.now)
				if e != nil {
					return journalhelper.Response{}, e
				}
				rev := "sha256:" + strings.Repeat("c", 64)
				if request.Operation == journalhelper.VerifyOperation {
					native.verifies++
					return journalResponse(t, journalhelper.StatusVerified, permit.PolicyDigest(), rev, nil), nil
				}
				native.captures++
				rawState, e := os.ReadFile(filepath.Join(journalStateDirectory(m.config), "journal-consumption.json"))
				if e != nil || !bytes.Contains(rawState, []byte(`"sequence":9`)) || !native.consumed {
					t.Fatal("capture preceded durable consumption")
				}
				snapshot, e := journalview.Parse(ctx, request.Query, native.now, bytes.NewReader(nil))
				if e != nil {
					return journalhelper.Response{}, e
				}
				raw, _ := journalview.Encode(snapshot)
				return journalResponse(t, journalhelper.StatusSnapshot, permit.PolicyDigest(), rev, raw), nil
			}
			if got := native.s.Run(context.Background()); got != "pending_retained" {
				t.Fatal(got)
			}
			native.failSend = false
			if got := native.s.Run(context.Background()); got != "acknowledged" {
				t.Fatal(got)
			}
			if native.captures != 1 || native.verifies != 2 || native.claims != 1 || len(native.bodies) != 2 || !bytes.Equal(native.bodies[0], native.bodies[1]) {
				t.Fatal("real transport flow recaptured or changed bytes")
			}
			// An accepted prior query is no longer mistaken for a lost capture.
			native.s.exchange = func(context.Context, string, uint64, []byte) ([]byte, int, error) {
				b, _ := json.Marshal(map[string]any{"error": map[string]string{"code": "journal_accepted", "message": "fixed"}})
				return b, 409, nil
			}
			if native.s.Run(context.Background()) != "idle" {
				t.Fatal("accepted request misreported")
			}
		})
	}
}
