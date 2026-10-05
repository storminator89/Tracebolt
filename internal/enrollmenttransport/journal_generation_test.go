package enrollmenttransport

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/journalcache"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalwire"
)

func TestJournalGenerationRealTransportAndOperatorCAS(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f, h, origin, client, old := prepareJournalTransportFixture(t, profile)
			report := journalgeneration.Report{SchemaVersion: journalgeneration.ReportSchemaVersion, Tuple: journalgeneration.Tuple{Revision: 1, Generation: strings.Repeat("a", 64), PolicyDigest: "sha256:" + strings.Repeat("a", 64)}, Sequence: 1, ObservedAt: time.Now().UTC()}
			raw, err := journalwire.EncodeGenerationReport(report)
			if err != nil {
				t.Fatal(err)
			}
			got := response(t, client, f.journalRequestFixture(t, origin, journalwire.GenerationPath, report.Sequence, raw), 200)
			echo, err := journalwire.DecodeGenerationReport(got)
			if err != nil || echo != report || !bytes.Equal(raw, got) {
				t.Fatal("report response", err)
			}
			retry := response(t, client, f.journalRequestFixture(t, origin, journalwire.GenerationPath, report.Sequence, raw), 200)
			if !bytes.Equal(got, retry) {
				t.Fatal("retry changed echo")
			}
			bad := bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":"2","sequence":"1"`), 1)
			response(t, client, f.journalRequestFixture(t, origin, journalwire.GenerationPath, report.Sequence, bad), 400)
			if profile == "http-test" {
				response(t, client, f.journalRequestFixture(t, origin, journalwire.GenerationPath, 2, raw), 400)
				switched := f.journalRequestFixture(t, origin, journalwire.GenerationPath, 1, raw)
				switched.URL.Path = journalwire.ResultPath
				response(t, client, switched, 403)
			}
			oldClaim := journalrequest.Claim{Identity: old.Identity, PolicyDigest: report.Tuple.PolicyDigest}
			claimRaw, _ := journalwire.EncodeClaim(oldClaim)
			response(t, client, f.journalRequestFixture(t, origin, journalwire.ClaimPath, old.Identity.Sequence, claimRaw), 409)
			o := journalOperatorFixtureNew(t, f, h)
			path := "/api/devices/" + old.DeviceID + "/journal"
			input := map[string]any{"expectedFloor": "1", "query": old.Query, "acknowledgeLogContent": true, "acknowledgePlaintext": profile == "http-test"}
			if out := o.call(t, path+"/create", input, nil); out.Code != 409 {
				t.Fatal("legacy create after floor", out.Code)
			}
			input["expectedPolicyGeneration"] = report.Tuple
			created := o.call(t, path+"/create", input, nil)
			if created.Code != 200 {
				t.Fatal("v2 create", created.Code, created.Body.String())
			}
			var view struct {
				SchemaVersion string                                 `json:"schemaVersion"`
				Generation    *enrollmentstore.JournalGenerationView `json:"generation"`
				Request       *journalrequest.Status                 `json:"request"`
			}
			if json.Unmarshal(created.Body.Bytes(), &view) != nil || view.SchemaVersion != "tracebolt.journal-view.v2" || view.Generation == nil || view.Generation.PolicyGeneration != report.Tuple || view.Request == nil || view.Request.Description.PolicyGeneration != report.Tuple || view.Request.Description.Identity.Sequence != 2 {
				t.Fatal("v2 view binding")
			}
			d := view.Request.Description
			claim := journalrequest.Claim{Identity: d.Identity, PolicyDigest: report.Tuple.PolicyDigest}
			claimRaw, _ = journalwire.EncodeClaim(claim)
			granted := response(t, client, f.journalRequestFixture(t, origin, journalwire.ClaimPath, d.Identity.Sequence, claimRaw), 200)
			grant, err := journalwire.DecodeGrant(granted)
			if err != nil || grant.Description != d {
				t.Fatal("v2 grant", err)
			}
			result := journalResultFixture(d, claim, 1)
			resultRaw, _ := journalwire.EncodeResult(result)
			receiptRaw := response(t, client, f.journalRequestFixture(t, origin, journalwire.ResultPath, d.Identity.Sequence, resultRaw), 200)
			receipt, err := journalwire.DecodeReceipt(receiptRaw)
			if err != nil {
				t.Fatal(err)
			}
			newer := report
			newer.Sequence = 2
			newer.Tuple.Revision = 2
			newer.Tuple.Generation = strings.Repeat("b", 64)
			newer.Tuple.PolicyDigest = "sha256:" + strings.Repeat("b", 64)
			newer.ObservedAt = time.Now().UTC()
			newerRaw, _ := journalwire.EncodeGenerationReport(newer)
			response(t, client, f.journalRequestFixture(t, origin, journalwire.GenerationPath, 2, newerRaw), 200)
			response(t, client, f.journalRequestFixture(t, origin, journalwire.ResultPath, d.Identity.Sequence, resultRaw), 409)
			page, err := h.journal.Page(context.Background(), d.DeviceID, journalcache.PageRequest{Identity: d.Identity, SnapshotDigest: receipt.ResultDigest, Limit: 100}, time.Now().UTC())
			if err != nil || len(page.Rows) != 1 || !page.ExpiresAt.Equal(d.ExpiresAt) {
				t.Fatal("accepted cache lost or refreshed", err)
			}
			o.clock.Store(time.Now().UTC().UnixNano())
			input["expectedFloor"] = "2"
			if out := o.call(t, path+"/create", input, nil); out.Code != 409 {
				t.Fatal("old expected generation silently rebound", out.Code)
			}
			// A fresh report is required for each explicit create, but its expiry does
			// not delete the generation floor or permit a v1 fallback.
			o.clock.Store(newer.ObservedAt.Add(enrollmentstore.JournalGenerationMaxAge).UnixNano())
			input["expectedPolicyGeneration"] = newer.Tuple
			if out := o.call(t, path+"/create", input, nil); out.Code != 409 || !strings.Contains(out.Body.String(), "journal_generation_stale") {
				t.Fatal("stale generation create", out.Code, out.Body.String())
			}
			// The operator has durably observed expiry at the advanced trusted
			// time. Revoke at that same time, never backdate history through
			// the generic fixture helper's real-time clock.
			other, err := enrollmentstore.Open(f.path, f.config, f.issuer.IssuerDER())
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			control := f.control(30)
			control.Now = time.Unix(0, o.clock.Load()).UTC().Unix()
			f.snapshot, err = other.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: control, State: enrollmentstate.Revoked})
			if err != nil {
				t.Fatal(err)
			}
			response(t, client, f.journalRequestFixture(t, origin, journalwire.GenerationPath, 2, newerRaw), 403)
		})
	}
}
