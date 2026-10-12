package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"localrmm/internal/actionpermit"
	"localrmm/internal/operatorauth"
	fence "localrmm/internal/windowsmutationfence"
	job "localrmm/internal/windowsupdatejob"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestReusableWUAAPIExactReviewAndReadOnlyReconciliation(t *testing.T) {
	f := newUpdateAPIFixture(t, []operatorauth.Capability{operatorauth.Read, operatorauth.WindowsUpdateInstall}, false, true)
	m := f.handler.windowsUpdateJobs
	ctx := context.Background()
	ek := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, 32))
	if code, v := f.call(t, "POST", "/request", map[string]any{"requestId": f.id, "updateId": f.selection.UpdateID, "revision": f.selection.Revision}, nil); code != 200 {
		t.Fatal(code, v)
	}
	r, e := job.DecodeRecord(f.store["jobs.json"])
	if e != nil {
		t.Fatal(e)
	}
	j := r.Jobs[0]
	ch, _ := job.VerifyChallenge(j.Challenge, r.PublicKey)
	now := time.Now().UTC().Unix()
	shared := fence.Status{Active: true, Phase: "idle", Revision: 1, Retained: 1}
	proof, _ := job.SignStatement(job.Statement{Version: job.RelayVersion, Kind: "mutation", Binding: r.Consent.Binding, JobID: j.ID, ReferenceDigest: actionpermit.Digest(j.Challenge), Deadline: ch.Deadline, IssuedAt: now, ExpiresAt: now + 60, Mutation: &shared}, ek)
	if e = m.Report(ctx, proof); e != nil {
		t.Fatal(e)
	}
	if code, v := f.call(t, "POST", "/approve", map[string]any{"previewId": j.ID, "previewDigest": j.Preview.Digest, "acknowledged": true}, nil); code != 200 {
		t.Fatal(code, v)
	}
	envelope, e := m.Claim(ctx, j.ID)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := job.Verify(envelope, r.PublicKey)
	result := job.Result{JobID: j.ID, EnvelopeDigest: actionpermit.Digest(envelope), Attempted: true, Outcome: "succeeded", OperationResult: 2, RebootRequired: job.Yes, CompletedAt: now}
	proof, _ = job.SignStatement(job.Statement{Version: job.RelayVersion, Kind: "result", Binding: r.Consent.Binding, JobID: j.ID, ReferenceDigest: result.EnvelopeDigest, Deadline: p.Preview.ExpiresAt, IssuedAt: now, ExpiresAt: now + 300, Result: &result}, ek)
	if e = m.Report(ctx, proof); e != nil {
		t.Fatal(e)
	}
	body := map[string]any{"jobId": j.ID, "occurrence": "1", "envelopeDigest": result.EnvelopeDigest, "resultDigest": actionpermit.Digest(proof), "acknowledged": false}
	if code, _ := f.call(t, "POST", "/retire", body, nil); code != 400 {
		t.Fatal("unchecked", code)
	}
	body["acknowledged"] = true
	body["occurrence"] = "2"
	if code, _ := f.call(t, "POST", "/retire", body, nil); code != 409 {
		t.Fatal("stale occurrence", code)
	}
	body["occurrence"] = "1"
	if code, _ := f.call(t, "POST", "/retire", body, func(r *http.Request) { r.Header.Del("X-CSRF-Token") }); code != 403 {
		t.Fatal("CSRF", code)
	}
	code, v := f.call(t, "POST", "/retire", body, nil)
	if code != 200 || v["reusableJobs"] != true || v["available"] != false {
		t.Fatal(code, v)
	}
	current := v["job"].(map[string]any)
	if current["retirement"].(map[string]any)["state"] != "pending" || current["result"].(map[string]any)["rebootRequired"] != "yes" {
		t.Fatal(v)
	}
	before, _ := job.DecodeRecord(f.store["jobs.json"])
	for i := 0; i < 2; i++ {
		if code, v = f.call(t, "GET", "?jobId="+j.ID, nil, nil); code != 200 || v["job"].(map[string]any)["retirement"].(map[string]any)["state"] != "pending" {
			t.Fatal("lost-response GET", code, v)
		}
	}
	after, _ := job.DecodeRecord(f.store["jobs.json"])
	if !bytes.Equal(before.Jobs[0].RetirePermit, after.Jobs[0].RetirePermit) || after.Jobs[0].RetireClaimedAt != 0 {
		t.Fatal("GET claimed or refreshed retirement")
	}
	if strings.Contains(string(f.store["jobs.json"]), "not_attempted") {
		t.Fatal("unexpected fixture")
	}
}
