//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/windowsnetworkcontext"
	"net/http"
	"testing"
	"time"
)

func networkContextReceipt(t *testing.T, body []byte, now time.Time) *http.Response {
	t.Helper()
	m, e := windowsnetworkcontext.DecodeMessage(body)
	if e != nil {
		t.Fatal(e)
	}
	status := "accepted"
	if m.Operation == "chunk" && m.Index == m.Manifest.ChunkCount-1 {
		status = "complete"
	}
	raw, e := json.Marshal(windowsnetworkcontext.Receipt{SchemaVersion: windowsnetworkcontext.ReceiptVersion, Operation: m.Operation, DeviceID: m.DeviceID, GrantID: m.Consent.GrantID, GrantRevision: m.Consent.Revision, Sequence: m.Sequence, RequestSHA256: windowsnetworkcontext.Hash(body), Index: m.Index, Status: status, ReceivedAt: now})
	if e != nil {
		t.Fatal(e)
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw))}
}

func TestWindowsNetworkContextLostResponseRestartRetriesExactBytesWithoutRecapture(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		t.Run(transport, func(t *testing.T) {
			m := windowsMaterialFixture(t, transport)
			st := networkContextLocal(t, m)
			now := time.Now().UTC()
			calls, sends := 0, 0
			var pending []byte
			collect := func(ctx context.Context) (windowsnetworkcontext.Capture, error) {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > windowsnetworkcontext.CaptureTimeout {
					t.Fatal("unbounded source")
				}
				return windowsnetworkcontext.Capture{StartedAt: now, FinishedAt: now, Complete: true, Rows: inventedNetworkContext(4096)}, nil
			}
			s, e := newNetworkContextFixtureSender(m, st, func() time.Time { return now }, collect)
			if e != nil {
				t.Fatal(e)
			}
			s.client = &http.Client{Transport: networkContextRoundTrip(func(r *http.Request) (*http.Response, error) {
				sends++
				b, _ := io.ReadAll(r.Body)
				msg, _ := windowsnetworkcontext.DecodeMessage(b)
				if msg.Operation == "chunk" {
					pending = bytes.Clone(b)
					return nil, errors.New("inert lost response")
				}
				return networkContextReceipt(t, b, now), nil
			})}
			first, e := s.Burst(context.Background())
			if e != windowsnetworkcontext.ErrTransport || calls != 1 || sends != 2 || first.Status != "pending_retained" || s.state.Floor() != 1 {
				t.Fatal(first, e, calls, sends)
			}
			frozen := bytes.Clone(st.files["pack.json"])
			s.Close()
			if transport == "tls" {
				now = now.Add(2 * time.Minute) // Pending outranks a newly due capture.
			} else {
				now = now.Add(10 * time.Second) // Stay inside the real signing-clock skew bound.
			}
			s, e = newNetworkContextFixtureSender(m, st, func() time.Time { return now }, func(context.Context) (windowsnetworkcontext.Capture, error) {
				t.Fatal("pending recaptured")
				return windowsnetworkcontext.Capture{}, nil
			})
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			retry := 0
			s.client = &http.Client{Transport: networkContextRoundTrip(func(r *http.Request) (*http.Response, error) {
				retry++
				b, _ := io.ReadAll(r.Body)
				if retry == 1 && !bytes.Equal(b, pending) {
					t.Fatal("retry bytes changed")
				}
				return networkContextReceipt(t, b, now), nil
			})}
			out, e := s.Burst(context.Background())
			if e != nil || out.Status != "complete" || !out.RetriedPending || out.Operations > 64 || calls != 1 || s.state.Floor() != 1 || !bytes.Equal(frozen, st.files["pack.json"]) {
				t.Fatal(out, e)
			}
		})
	}
}

func TestWindowsNetworkContextDisabledOnlySynchronizesScopeAndAuthorityLossStopsSender(t *testing.T) {
	m := windowsMaterialFixture(t, "tls")
	st := networkContextLocal(t, m)
	c, e := windowsnetworkcontext.DecodeConsent(st.files["consent.json"])
	if e != nil {
		t.Fatal(e)
	}
	c.Enabled = false
	c.Revision++
	st.files["consent.json"], _ = windowsnetworkcontext.EncodeConsent(c)
	now := time.Now().UTC()
	authorized := true
	s, e := newNetworkContextSenderWithAuthority(m, st, func() time.Time { return now }, func(context.Context) (windowsnetworkcontext.Capture, error) {
		t.Fatal("disabled source read")
		return windowsnetworkcontext.Capture{}, nil
	}, func() bool { return authorized })
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	sends := 0
	s.client = &http.Client{Transport: networkContextRoundTrip(func(r *http.Request) (*http.Response, error) {
		sends++
		b, _ := io.ReadAll(r.Body)
		msg, _ := windowsnetworkcontext.DecodeMessage(b)
		if msg.Operation != "scope" || msg.Consent.Enabled {
			t.Fatal("disabled data sent")
		}
		return networkContextReceipt(t, b, now), nil
	})}
	for i := 0; i < 2; i++ {
		out, e := s.Burst(context.Background())
		if e != nil || out.Status != "disabled" || s.state.Floor() != 0 {
			t.Fatal(out, e)
		}
	}
	authorized = false
	if _, e := s.Burst(context.Background()); e != ErrConfiguration || sends != 1 {
		t.Fatal("lost authority reached transport", e, sends)
	}
}

func TestWindowsNetworkContextCurrentAuthorityAndConsentRecheckedAtEveryBoundary(t *testing.T) {
	for _, phase := range []string{"before_scope", "during_reservation", "during_capture", "during_receipt", "consent_during_reservation", "consent_during_receipt"} {
		t.Run(phase, func(t *testing.T) {
			m := windowsMaterialFixture(t, "tls")
			st := networkContextLocal(t, m)
			now := time.Now().UTC()
			authorized := true
			calls, sends := 0, 0
			revoke := func() {
				c, e := windowsnetworkcontext.DecodeConsent(st.files["consent.json"])
				if e != nil {
					t.Fatal(e)
				}
				c.Enabled = false
				c.Revision++
				st.files["consent.json"], _ = windowsnetworkcontext.EncodeConsent(c)
			}
			storage := &networkContextExpiryStorage{Storage: st, afterWrite: func(name string, b []byte) {
				if name == "sender.json" && bytes.Contains(b, []byte(`"phase":"capturing"`)) {
					if phase == "during_reservation" {
						authorized = false
					}
					if phase == "consent_during_reservation" {
						revoke()
					}
				}
			}}
			s, e := newNetworkContextSenderWithAuthority(m, storage, func() time.Time { return now }, func(context.Context) (windowsnetworkcontext.Capture, error) {
				calls++
				if phase == "during_capture" {
					authorized = false
				}
				return windowsnetworkcontext.Capture{StartedAt: now, FinishedAt: now, Complete: true, Rows: inventedNetworkContext(1)}, nil
			}, func() bool { return authorized })
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			s.client = &http.Client{Transport: networkContextRoundTrip(func(r *http.Request) (*http.Response, error) {
				sends++
				b, _ := io.ReadAll(r.Body)
				msg, _ := windowsnetworkcontext.DecodeMessage(b)
				out := networkContextReceipt(t, b, now)
				if msg.Operation == "chunk" {
					if phase == "during_receipt" {
						authorized = false
					}
					if phase == "consent_during_receipt" {
						revoke()
					}
				}
				return out, nil
			})}
			if phase == "before_scope" {
				authorized = false
			}
			_, e = s.Burst(context.Background())
			if e == nil {
				t.Fatal("authority/consent loss accepted")
			}
			wantCalls, wantSends := 1, 1
			if phase == "before_scope" {
				wantCalls, wantSends = 0, 0
			}
			if phase == "during_reservation" || phase == "consent_during_reservation" {
				wantCalls = 0
			}
			if phase == "during_receipt" || phase == "consent_during_receipt" {
				wantSends = 2
			}
			if calls != wantCalls || sends != wantSends {
				t.Fatal("forbidden native read or send", calls, sends)
			}
			if phase != "before_scope" && (!s.state.Pending() || s.state.Floor() != 1) {
				t.Fatal("revocation erased claim or acknowledged old bytes")
			}
		})
	}
}
