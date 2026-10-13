package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"localrmm/internal/operatorauth"
	job "localrmm/internal/windowsupdatejob"
)

// Pure recorder/source fixtures: no listener, native provider or delivery call.
func newDownloadAPIFixture(t *testing.T, caps ...operatorauth.Capability) updateAPIFixture {
	t.Helper()
	return newDownloadAPIFixtureMode(t, false, caps...)
}
func newDownloadAPIFixtureMode(t *testing.T, coexistence bool, caps ...operatorauth.Capability) updateAPIFixture {
	t.Helper()
	f := newUpdateAPIFixture(t, append([]operatorauth.Capability{operatorauth.Read}, caps...), false, true)
	old, err := job.DecodeRecord(f.store["jobs.json"])
	if err != nil {
		t.Fatal(err)
	}
	consent := old.Consent
	consent.Version = job.DownloadConsentVersion
	if coexistence {
		consent.Version = job.DownloadCoexistenceConsentVersion
		consent.ScheduleScope = job.ScheduleScope
		consent.ScheduleAcknowledged = true
	}
	consent.DownloadScope = job.DownloadScope
	consent.DownloadAcknowledged = true
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{62}, 32))
	ek := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, 32))
	at := time.Now().UTC().Unix()
	record, err := job.NewRecordWithExecutor(consent, key.Public().(ed25519.PublicKey), ek.Public().(ed25519.PublicKey), at)
	if err != nil {
		t.Fatal(err)
	}
	f.store["jobs.json"], err = job.EncodeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(consent)
	f.store["started.json"] = raw
	f.store["receipt.json"] = raw
	r := job.Readiness{Purpose: job.DownloadPurpose, Selection: f.selection, CapturedAt: at, Software: job.Yes, Installed: job.No, Hidden: job.No, Downloaded: job.No, EULAAccepted: job.Yes, CanRequestUserInput: job.Unknown, CanRequireSource: job.Unknown, RequiresNetwork: job.Unknown, BundledCount: 0, InstallerBusy: job.Unknown, RebootRequiredBefore: job.Unknown, RebootBehavior: "unknown", OfflineVerified: job.Yes, DownloadMetadataKnown: true, DownloadOrigins: "https://updates.invalid", DownloadMinBytes: 1024, DownloadMaxBytes: 2048, DownloadSource: "default"}
	m, err := job.Open(f.store, f.authority, updateAPIReadiness{r}, key, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.ConfigureOperatorPolicy(func(actor string) bool {
		return f.handler.auth.ActorHasCapability(actor, operatorauth.WindowsUpdateInstall)
	}); err != nil {
		t.Fatal(err)
	}
	if err = m.ConfigureDownloadPolicy(func(actor string) bool {
		return f.handler.auth.ActorHasCapability(actor, operatorauth.WindowsUpdateDownload)
	}); err != nil {
		t.Fatal(err)
	}
	if coexistence {
		if err = m.ConfigureSchedulePolicy(context.Background(), func(actor string) bool {
			return f.handler.auth.ActorHasCapability(actor, operatorauth.WindowsUpdateSchedule)
		}); err != nil {
			t.Fatal(err)
		}
	}
	f.handler.windowsUpdateJobs = m
	return f
}
func downloadRequestBody(f updateAPIFixture) map[string]any {
	return map[string]any{"requestId": f.id, "updateId": f.selection.UpdateID, "revision": f.selection.Revision}
}
func TestWindowsUpdateDownloadAPIIndependentCapabilityAndPurpose(t *testing.T) {
	f := newDownloadAPIFixture(t, operatorauth.WindowsUpdateDownload)
	code, v := f.call(t, "GET", "", nil, nil)
	if code != 200 || v["available"] != false || v["downloadAvailable"] != true || v["downloadEnabled"] != true {
		t.Fatal(code, v)
	}
	for _, op := range []string{"request", "preview", "approve", "retire", "schedule", "cancel-schedule", "revoke-scheduling"} {
		if code, _ = f.call(t, "POST", "/"+op, map[string]any{}, nil); code != 403 {
			t.Fatal("download implies install", op, code)
		}
	}
	code, v = f.call(t, "POST", "/request-download", downloadRequestBody(f), nil)
	if code != 200 {
		t.Fatal(code, v)
	}
	j := v["job"].(map[string]any)
	if j["purpose"] != "download" || j["preview"] == nil {
		t.Fatal("download-only review stripped", v)
	}
	for _, op := range []string{"GET", "POST"} {
		suffix := "?jobId=" + f.id
		var body any
		if op == "POST" {
			suffix = "/preview-download"
			body = map[string]any{"requestId": f.id}
		}
		code, v = f.call(t, op, suffix, body, nil)
		if code != 200 || v["job"].(map[string]any)["preview"] == nil {
			t.Fatal("download review unavailable", code, v)
		}
	}
	preview := j["preview"].(map[string]any)
	code, _ = f.call(t, "POST", "/approve-download", map[string]any{"previewId": f.id, "previewDigest": preview["digest"], "acknowledged": false}, nil)
	if code != 400 {
		t.Fatal("unchecked approval accepted", code)
	}
	// The other purpose still fails even when the target ID/digest are known.
	if err := f.handler.windowsUpdateJobs.Review(context.Background(), f.device, namedActorID, f.id); err == nil {
		t.Fatal("install review accepted download")
	}
}
func TestWindowsUpdateDownloadAPINoPromotionAndRequestGuards(t *testing.T) {
	for _, caps := range [][]operatorauth.Capability{nil, {operatorauth.WindowsUpdateInstall}, {operatorauth.WindowsUpdateSchedule}} {
		f := newDownloadAPIFixture(t, caps...)
		for _, op := range []string{"request-download", "preview-download", "approve-download", "retire-download"} {
			if code, _ := f.call(t, "POST", "/"+op, map[string]any{}, nil); code != 403 {
				t.Fatal("missing download accepted", caps, op, code)
			}
		}
	}
	for _, change := range []func(*http.Request){func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, func(r *http.Request) { r.Header.Set("Origin", "https://elsewhere.invalid") }} {
		f := newDownloadAPIFixture(t, operatorauth.WindowsUpdateDownload)
		before := bytes.Clone(f.store["jobs.json"])
		if code, _ := f.call(t, "POST", "/request-download", downloadRequestBody(f), change); code != 403 {
			t.Fatal("request guard missing", code)
		}
		if !bytes.Equal(before, f.store["jobs.json"]) {
			t.Fatal("denied request changed durable state")
		}
	}
	f := newDownloadAPIFixture(t, operatorauth.WindowsUpdateDownload)
	f.handler.insecureHTTPTest = true
	if code, _ := f.call(t, "POST", "/request-download", downloadRequestBody(f), nil); code == 200 {
		t.Fatal("download admitted under HTTP")
	}
}
func TestWindowsUpdateDownloadAPICommitGuardUsesExactCapability(t *testing.T) {
	for _, op := range []string{"request-download", "preview-download", "approve-download", "retire-download"} {
		if windowsUpdateCapability(op) != operatorauth.WindowsUpdateDownload || !windowsUpdateDownloadOperation(op) {
			t.Fatal("download commit capability", op)
		}
	}
	for _, op := range []string{"request", "preview", "approve", "retire", "schedule"} {
		if windowsUpdateCapability(op) != operatorauth.WindowsUpdateInstall || windowsUpdateDownloadOperation(op) {
			t.Fatal("install commit capability", op)
		}
	}
}

func TestWindowsUpdateDownloadAPIFinalLiveSessionGuard(t *testing.T) {
	f := newDownloadAPIFixture(t, operatorauth.WindowsUpdateDownload)
	live := true
	for _, op := range []string{"request-download", "preview-download", "approve-download", "retire-download"} {
		r := httptest.NewRequest("POST", "https://manager.invalid/api/devices/"+f.device+"/windows-update-jobs/"+op, nil)
		r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{session: f.session, active: func() bool { return live }}))
		ctx := f.handler.windowsUpdateJobContext(r, true)
		if err := job.CheckFinal(ctx); err != nil {
			t.Fatal("download final grant denied", op, err)
		}
		live = false
		if err := job.CheckFinal(ctx); err == nil {
			t.Fatal("final session guard absent", op)
		}
		live = true
	}
	r := httptest.NewRequest("POST", "https://manager.invalid/api/devices/"+f.device+"/windows-update-jobs/approve", nil)
	r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{session: f.session, active: func() bool { return live }}))
	if err := job.CheckFinal(f.handler.windowsUpdateJobContext(r, true)); err == nil {
		t.Fatal("download final guard authorized installation")
	}
	r.URL.Path += "-download"
	ctx := f.handler.windowsUpdateJobContext(r, true)
	f.handler.auth.Logout(f.session.Token)
	if err := job.CheckFinal(ctx); err == nil {
		t.Fatal("revoked session retained download authority")
	}
}
func TestWindowsUpdateDownloadOnlyActorCannotReadInstallPreview(t *testing.T) {
	install := newUpdateAPIFixture(t, []operatorauth.Capability{operatorauth.Read, operatorauth.WindowsUpdateInstall})
	if code, _ := install.call(t, "POST", "/request", downloadRequestBody(install), nil); code != 200 {
		t.Fatal(code)
	}
	download := newDownloadAPIFixture(t, operatorauth.WindowsUpdateDownload)
	download.handler.windowsUpdateJobs = install.handler.windowsUpdateJobs
	if code, v := download.call(t, "GET", "?jobId="+install.id, nil, nil); code != 200 || v["job"].(map[string]any)["preview"] != nil {
		t.Fatal("download-only actor received install review", code, v)
	}
}

func TestWindowsUpdateDownloadCoexistenceAPIIndependentCapabilities(t *testing.T) {
	for _, caps := range [][]operatorauth.Capability{
		{operatorauth.WindowsUpdateDownload},
		{operatorauth.WindowsUpdateInstall, operatorauth.WindowsUpdateSchedule},
		{operatorauth.WindowsUpdateDownload, operatorauth.WindowsUpdateSchedule},
		{operatorauth.WindowsUpdateDownload, operatorauth.WindowsUpdateInstall, operatorauth.WindowsUpdateSchedule},
	} {
		f := newDownloadAPIFixtureMode(t, true, caps...)
		has := func(want operatorauth.Capability) bool {
			for _, cap := range caps {
				if cap == want {
					return true
				}
			}
			return false
		}
		code, view := f.call(t, "GET", "", nil, nil)
		if code != 200 || view["downloadEnabled"] != true || view["backgroundScheduling"] != true || (view["downloadAvailable"] == true) != has(operatorauth.WindowsUpdateDownload) || (view["schedulingAvailable"] == true) != (has(operatorauth.WindowsUpdateInstall) && has(operatorauth.WindowsUpdateSchedule)) {
			t.Fatal("capability promotion or false coexistence view", caps, code, view)
		}
		code, view = f.call(t, "POST", "/request-download", downloadRequestBody(f), nil)
		if !has(operatorauth.WindowsUpdateDownload) {
			if code != 403 {
				t.Fatal("installation grants download", code)
			}
			continue
		}
		if code != 200 {
			t.Fatal(code, view)
		}
		j := view["job"].(map[string]any)
		p := j["preview"].(map[string]any)
		before := bytes.Clone(f.store["jobs.json"])
		code, _ = f.call(t, "POST", "/schedule", map[string]any{"previewId": f.id, "previewDigest": p["digest"], "startAt": int64(view["serverNow"].(float64)) + 120, "endAt": int64(view["serverNow"].(float64)) + 240, "acknowledged": true}, nil)
		if code == 200 || !bytes.Equal(before, f.store["jobs.json"]) {
			t.Fatal("download entered scheduler or consumed approval", caps, code)
		}
	}
}
