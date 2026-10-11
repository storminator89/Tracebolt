//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowsfullservices"
)

func TestFullServicesLocalExpiryNeverCapturesOrAcknowledges(t *testing.T) {
	for _, phase := range []string{"before_scope", "after_scope_ack", "during_reservation", "during_capture", "during_receipt"} {
		t.Run(phase, func(t *testing.T) {
			f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "tls")
			st := fullServicesLocal(t, f.material)
			now := time.Now().UTC()
			leaf, e := x509.ParseCertificate(f.material.certificate.Certificate[0])
			if e != nil {
				t.Fatal(e)
			}
			calls, sends := 0, 0
			storage := &fullServicesExpiryStorage{Storage: st, afterWrite: func(name string, raw []byte) {
				if phase == "during_reservation" && name == "sender.json" && bytes.Contains(raw, []byte(`"phase":"capturing"`)) {
					now = leaf.NotAfter
				}
			}}
			sender, e := newFullServicesSender(f.material, storage, func() time.Time { return now }, func(context.Context) (windowsfullservices.Capture, error) {
				calls++
				at := now
				if phase == "during_capture" {
					now = leaf.NotAfter
				}
				return windowsfullservices.Capture{StartedAt: at, FinishedAt: at, Complete: true, Rows: inventedFullServices(1)}, nil
			})
			if e != nil {
				t.Fatal(e)
			}
			defer sender.Close()
			sender.client = &http.Client{Transport: fullServicesRoundTrip(func(req *http.Request) (*http.Response, error) {
				sends++
				raw, e := io.ReadAll(req.Body)
				if e != nil {
					t.Fatal(e)
				}
				m, e := windowsfullservices.DecodeMessage(raw)
				if e != nil {
					t.Fatal(e)
				}
				status := "accepted"
				if m.Operation == "chunk" {
					status = "complete"
				}
				receipt, e := json.Marshal(windowsfullservices.Receipt{SchemaVersion: windowsfullservices.ReceiptVersion, Operation: m.Operation, DeviceID: m.DeviceID, GrantID: m.Consent.GrantID, GrantRevision: m.Consent.Revision, Sequence: m.Sequence, RequestSHA256: windowsfullservices.Hash(raw), Index: m.Index, Status: status, ReceivedAt: now})
				if e != nil {
					t.Fatal(e)
				}
				if phase == "during_receipt" && m.Operation == "chunk" {
					now = leaf.NotAfter
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(receipt))}, nil
			})}
			if phase == "after_scope_ack" {
				c, e := sender.consent()
				if e != nil {
					t.Fatal(e)
				}
				raw, _, e := sender.state.Scope(c)
				if e != nil {
					t.Fatal(e)
				}
				receipt, e := sender.exchange(context.Background(), raw, c)
				if e != nil {
					t.Fatal(e)
				}
				if e = sender.state.AcknowledgeScope(raw, receipt, now); e != nil {
					t.Fatal(e)
				}
				sends = 0
			}
			if phase == "before_scope" || phase == "after_scope_ack" {
				now = leaf.NotAfter
			}
			before := map[string][]byte{}
			for k, v := range st.files {
				before[k] = append([]byte(nil), v...)
			}
			_, e = sender.Burst(context.Background())
			if !errors.Is(e, ErrConfiguration) {
				t.Fatal("expired local authority accepted", e)
			}
			if phase == "before_scope" || phase == "after_scope_ack" {
				if calls != 0 || sends != 0 || sender.state.Floor() != 0 {
					t.Fatal("expired identity reached source or network", calls, sends, sender.state.Floor())
				}
				for k, v := range before {
					if !bytes.Equal(v, st.files[k]) {
						t.Fatal("expired identity mutated state")
					}
				}
			} else {
				wantSends := 1
				if phase == "during_receipt" {
					wantSends = 2
				}
				wantCalls := 1
				if phase == "during_reservation" {
					wantCalls = 0
				}
				if calls != wantCalls || sends != wantSends || sender.state.Floor() != 1 || !sender.state.Pending() {
					t.Fatal("expiry reset or acknowledged pending generation", calls, sends, sender.state.Floor(), sender.state.Pending())
				}
				frozen := append([]byte(nil), st.files["pack.json"]...)
				_, e = sender.Burst(context.Background())
				if !errors.Is(e, ErrConfiguration) || calls != wantCalls || sends != wantSends || !bytes.Equal(frozen, st.files["pack.json"]) {
					t.Fatal("expired retry changed original pack", e)
				}
			}
		})
	}
}

// The storage hook models certificate expiry while the durable reservation fsync
// is blocked. It never touches a native path or changes production storage.
type fullServicesExpiryStorage struct {
	windowsfullservices.Storage
	afterWrite func(string, []byte)
}

func (s *fullServicesExpiryStorage) Write(name string, raw []byte) error {
	if e := s.Storage.Write(name, raw); e != nil {
		return e
	}
	s.afterWrite(name, raw)
	return nil
}
