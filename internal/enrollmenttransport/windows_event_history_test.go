package enrollmenttransport

import (
	"bytes"
	"context"
	"localrmm/internal/windowseventhistory"
	"localrmm/internal/windowseventwire"
	"localrmm/internal/windowshistorycache"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorywire"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestWindowsHistoryRealTransportSearchSelectedMessagesAndPurpose(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			x := newEventTransportFixture(t, profile, nil)
			ctx := context.Background()
			if err := x.f.store.InitializeWindowsHistory(ctx); err != nil {
				t.Fatal(err)
			}
			cache := windowshistorycache.New(x.f.store, x.now)
			t.Cleanup(cache.Close)
			if err := x.h.ConfigureWindowsHistory(cache); err != nil {
				t.Fatal(err)
			}
			request := func(path string, seq uint64, body []byte) *http.Request {
				if profile == "http-test" {
					r, e := windowshistorywire.NewSignedRequest(ctx, x.origin, path, x.f.pair, seq, time.Now().UTC(), body)
					if e != nil {
						t.Fatal(e)
					}
					return r
				}
				r, e := http.NewRequest(http.MethodPost, x.origin+path, bytes.NewReader(body))
				if e != nil {
					t.Fatal(e)
				}
				r.Header.Set("Content-Type", "application/json")
				return r
			}
			device, anchor := x.capability.DeviceID, x.capability.CertificateHash
			consent := windowshistoryrequest.Consent{SchemaVersion: windowshistoryrequest.ConsentVersion, Scope: windowshistoryrequest.Scope, SenderBinding: strings.Repeat("a", 64), GrantID: strings.Repeat("b", 32), Profile: profile, Enabled: true, HistoryAcknowledged: true, ContentAcknowledged: true, HTTPPlaintextAcknowledged: profile == "http-test"}
			cap, err := windowshistorywire.CapabilityFor(consent, windowshistoryrequest.LocalContext{SenderBinding: consent.SenderBinding, Profile: profile, DeviceID: device, CertificateHash: anchor}, 1, x.now())
			if err != nil {
				t.Fatal(err)
			}
			raw, err := windowshistorywire.EncodeCapability(cap)
			if err != nil {
				t.Fatal(err)
			}
			response(t, x.client, request(windowshistorywire.CapabilityPath, 1, raw), 200)
			bad := cap
			bad.CertificateHash = strings.Repeat("f", 64)
			badRaw, _ := windowshistorywire.EncodeCapability(bad)
			response(t, x.client, request(windowshistorywire.CapabilityPath, 1, badRaw), 400)
			owner := windowshistorycache.Owner{ID: x.owner.ID, ExpiresAt: x.owner.ExpiresAt, Lifetime: x.owner.Lifetime, Active: x.owner.Active}
			search := windowseventhistory.Search{Channel: "System", Start: x.now().Add(-time.Hour), End: x.now()}
			d, err := cache.CreateSearch(ctx, device, owner, 0, search, x.now())
			if err != nil {
				t.Fatal(err)
			}
			for phase := 0; phase < 2; phase++ {
				peek, err := windowshistorywire.DecodeDescription(response(t, x.client, request(windowshistorywire.PeekPath, 1, []byte("{}")), 200))
				if err != nil || peek.Identity != d.Identity {
					t.Fatal("peek", err)
				}
				claim, _ := windowshistorywire.ClaimFor(d, cap.PolicyDigest)
				claimBytes, _ := windowshistorywire.EncodeClaim(claim)
				if _, err := windowshistorywire.DecodeGrant(response(t, x.client, request(windowshistorywire.ClaimPath, d.Identity.Sequence, claimBytes), 200)); err != nil {
					t.Fatal(err)
				}
				response(t, x.client, request(windowshistorywire.ClaimPath, d.Identity.Sequence, claimBytes), 409)
				rows := []windowseventhistory.Result{{Event: windowseventhistory.Event{Channel: "System", RecordID: 12, EventID: 42, Level: 2, Provider: "Synthetic history transport", Timestamp: x.now().Add(-time.Minute)}, Quality: "observed", Complete: true}}
				if phase == 1 {
					rows[0].Event = d.Query.Events[0]
					rows[0].Message = "synthetic-private-history-transport"
				}
				result := windowshistorywire.Result{Claim: claim, Report: windowseventhistory.Report{Source: windowseventhistory.Source, Warning: windowseventhistory.PrivacyWarning, Quality: "observed", CollectedAt: x.now(), Complete: true, Search: windowseventhistory.CloneSearch(d.Query.Search), Events: rows}}
				raw, err = windowshistorywire.EncodeResult(result)
				if err != nil {
					t.Fatal(err)
				}
				accepted := response(t, x.client, request(windowshistorywire.ResultPath, d.Identity.Sequence, raw), 200)
				receipt, err := windowshistorywire.DecodeReceipt(accepted)
				if err != nil {
					t.Fatal(err)
				}
				if retry := response(t, x.client, request(windowshistorywire.ResultPath, d.Identity.Sequence, raw), 200); !bytes.Equal(accepted, retry) {
					t.Fatal("receipt refreshed")
				}
				page, err := cache.Query(ctx, device, owner, d.Identity, x.now())
				if err != nil || len(page.Report.Events) != 1 {
					t.Fatal("private page", err)
				}
				if phase == 0 {
					prior := d
					d, err = cache.CreateMessages(ctx, device, owner, 1, receipt, []windowshistoryrequest.Selection{{Channel: "System", RecordID: "12"}}, x.now())
					if err != nil || d.ExpiresAt != prior.ExpiresAt {
						t.Fatal("followup", err)
					}
				} else if page.Report.Events[0].Message != rows[0].Message {
					t.Fatal("message missing")
				}
			}
			if profile == "http-test" {
				old := x.request(t, windowseventwire.PeekPath, 1, []byte("{}"))
				for _, keys := range [][2]string{{windowseventwire.CertificateHeader, windowshistorywire.CertificateHeader}, {windowseventwire.SequenceHeader, windowshistorywire.SequenceHeader}, {windowseventwire.SignedAtHeader, windowshistorywire.SignedAtHeader}, {windowseventwire.SignatureHeader, windowshistorywire.SignatureHeader}} {
					old.Header.Set(keys[1], old.Header.Get(keys[0]))
					old.Header.Del(keys[0])
				}
				old.URL.Path = windowshistorywire.PeekPath
				response(t, x.client, old, 403)
			}
		})
	}
}
