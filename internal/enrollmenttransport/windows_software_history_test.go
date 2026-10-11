package enrollmenttransport

import (
	"bytes"
	"context"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowsfullsoftware"
	"localrmm/internal/windowsfullsoftwarewire"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSoftwareHistoryUsesExistingAuthenticatedTransferAndExactReceipts(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newCollectionFixture(t, profile, enrollmentcrypto.CollectionProfileWindowsInventory, true)
			if e := f.store.InitializeWindowsFullSoftware(context.Background()); e != nil {
				t.Fatal(e)
			}
			_, server, client := f.listen(t, nil)
			c := windowsfullsoftware.Consent{SchemaVersion: windowsfullsoftware.ConsentVersion, Scope: windowsfullsoftware.Scope, SenderBinding: windowsfullsoftware.SenderBinding(profile, server.URL, f.cert.CertificateHash(), f.snapshot.Approval.DeviceID), GrantID: strings.Repeat("d", 32), Revision: 1, Enabled: true, ChangedAt: f.now, HistoryScope: windowsfullsoftware.HistoryScope}
			send := func(m windowsfullsoftware.Message) []byte {
				raw, e := windowsfullsoftware.EncodeMessage(m)
				if e != nil {
					t.Fatal(e)
				}
				var r *http.Request
				if profile == "http-test" {
					r, e = windowsfullsoftwarewire.NewSignedRequest(context.Background(), server.URL, f.pair, m.Operation, m.WireSequence(), time.Now().UTC(), raw)
				} else {
					r, e = http.NewRequest(http.MethodPost, server.URL+windowsfullsoftwarewire.PathPrefix+m.Operation, bytes.NewReader(raw))
					if e == nil {
						r.Header.Set("Content-Type", "application/json")
					}
				}
				if e != nil {
					t.Fatal(e)
				}
				receipt := response(t, client, r, 200)
				if _, e = windowsfullsoftware.DecodeReceipt(receipt, raw); e != nil {
					t.Fatal("history not receipt-bound", e)
				}
				return receipt
			}
			scope := windowsfullsoftware.Message{SchemaVersion: windowsfullsoftware.MessageVersion, Operation: "scope", DeviceID: f.snapshot.Approval.DeviceID, Consent: c}
			first := send(scope)
			if !bytes.Equal(first, send(scope)) {
				t.Fatal("scope retry refreshed history grant")
			}
			for seq := uint64(1); seq <= 2; seq++ {
				rows := []windowsfullsoftware.Row{}
				if seq == 2 {
					rows = append(rows, windowsfullsoftware.Row{RegistrationID: strings.Repeat("1", 64), RegistryView: "64", NameQuality: "unavailable", VersionQuality: "unavailable", PublisherQuality: "unavailable"})
				}
				messages, e := windowsfullsoftware.Build(f.snapshot.Approval.DeviceID, c, seq, windowsfullsoftware.Capture{StartedAt: f.now, FinishedAt: f.now, Rows: rows, Complete: true})
				if e != nil {
					t.Fatal(e)
				}
				for _, m := range messages {
					receipt := send(m)
					if !bytes.Equal(receipt, send(m)) {
						t.Fatal("chunk retry changed history receipt")
					}
				}
			}
			page, e := f.store.WindowsSoftwareHistoryPage(context.Background(), f.snapshot.Approval.DeviceID, windowsfullsoftware.Query{Sort: "observed-desc", Limit: 100}, time.Now().UTC())
			if e != nil || page.RetainedCount != 1 || len(page.Rows) != 1 || page.Rows[0].Kind != "registration_added" {
				t.Fatal("authenticated transfer did not produce history", e)
			}
		})
	}
}
