package api

import (
	"context"
	"encoding/json"
	"localrmm/internal/windowseventhistory"
	"localrmm/internal/windowshistorycache"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorywire"
	"net/http"
	"strings"
	"testing"
	"time"
)

func historyOperatorFixture(t *testing.T) (windowsEventOperatorFixture, windowshistorywire.Capability) {
	t.Helper()
	f := newWindowsEventOperatorFixture(t)
	ctx := context.Background()
	f.path = strings.Replace(f.path, "windows-event-content", "windows-event-history", 1)
	if e := f.service.InitializeWindowsHistory(ctx); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(f.service.CloseWindowsHistory)
	c := windowshistoryrequest.Consent{SchemaVersion: windowshistoryrequest.ConsentVersion, Scope: windowshistoryrequest.Scope, SenderBinding: strings.Repeat("a", 64), GrantID: strings.Repeat("b", 32), Profile: "tls", Enabled: true, HistoryAcknowledged: true, ContentAcknowledged: true}
	cap, e := windowshistorywire.CapabilityFor(c, windowshistoryrequest.LocalContext{SenderBinding: c.SenderBinding, Profile: "tls", DeviceID: f.snap.Approval.DeviceID, CertificateHash: f.snap.Issuance.CertificateHash}, 1, f.at)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.ReportWindowsHistoryCapability(ctx, cap.DeviceID, cap.CertificateHash, cap, f.at); e != nil {
		t.Fatal(e)
	}
	return f, cap
}
func historyOperatorCreate(t *testing.T, f windowsEventOperatorFixture) windowshistoryrequest.Description {
	t.Helper()
	body := map[string]any{"expectedFloor": "0", "search": windowseventhistory.Search{Channel: "Application", Start: f.at.Add(-24 * time.Hour), End: f.at}, "acknowledgeHistory": true, "acknowledgePlaintext": false}
	r, v := f.call(t, "POST", f.path+"/create", body, f.csrf, nil)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("history create status %d", r.StatusCode)
	}
	view := windowsEventOperatorDecode[windowsHistoryView](t, v)
	if view.Request == nil || view.Request.State != windowshistoryrequest.Pending {
		t.Fatal("no pending history")
	}
	d, e := view.Request.Description.Native()
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func historyOperatorAccept(t *testing.T, f windowsEventOperatorFixture, cap windowshistorywire.Capability, d windowshistoryrequest.Description) (windowshistoryrequest.Receipt, windowseventhistory.Report) {
	t.Helper()
	ctx := context.Background()
	claim, e := windowshistorywire.ClaimFor(d, cap.PolicyDigest)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.ClaimWindowsHistoryRequest(ctx, cap.DeviceID, cap.CertificateHash, claim, f.at); e != nil {
		t.Fatal(e)
	}
	rows := []windowseventhistory.Result{}
	if d.Query.Search != nil {
		rows = append(rows, windowseventhistory.Result{Event: windowseventhistory.Event{Channel: "Application", RecordID: 18446744073709551615, EventID: 42, Level: 2, Provider: "Synthetic history API", Timestamp: f.at.Add(-time.Minute)}, Quality: "observed", Complete: true})
	} else {
		for _, event := range d.Query.Events {
			rows = append(rows, windowseventhistory.Result{Event: event, Message: "synthetic-private-history-content", Quality: "observed", Complete: true})
		}
	}
	report := windowseventhistory.Report{Source: windowseventhistory.Source, Warning: windowseventhistory.PrivacyWarning, Quality: "observed", CollectedAt: f.at, Complete: true, Search: windowseventhistory.CloneSearch(d.Query.Search), Events: rows}
	receipt, e := f.service.AcceptWindowsHistoryResult(ctx, cap.DeviceID, cap.CertificateHash, windowshistorywire.Result{Claim: claim, Report: report}, f.at)
	if e != nil {
		t.Fatal(e)
	}
	return receipt, report
}
func TestWindowsHistoryOperatorSearchAndSelectedMessages(t *testing.T) {
	f, cap := historyOperatorFixture(t)
	d := historyOperatorCreate(t, f)
	receipt, _ := historyOperatorAccept(t, f, cap, d)
	response, value := f.call(t, "POST", f.path+"/query", map[string]any{"identity": d.Identity}, f.csrf, nil)
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("private query failed", response.StatusCode)
	}
	page := windowsEventOperatorDecode[windowshistorycache.Page](t, value)
	if len(page.Report.Events) != 1 || page.Report.Events[0].Event.RecordID != "18446744073709551615" || page.Receipt != receipt {
		t.Fatal("accepted headers changed")
	}
	body := map[string]any{"expectedFloor": "1", "receipt": receipt, "selections": []map[string]string{{"channel": "Application", "recordId": "18446744073709551615"}}, "acknowledgeContent": true, "acknowledgePlaintext": false}
	response, value = f.call(t, "POST", f.path+"/messages", body, f.csrf, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatal("selected history create", response.StatusCode)
	}
	view := windowsEventOperatorDecode[windowsHistoryView](t, value)
	messages, e := view.Request.Description.Native()
	if e != nil {
		t.Fatal(e)
	}
	if messages.ExpiresAt != d.ExpiresAt || messages.SearchReceipt == nil || *messages.SearchReceipt != receipt {
		t.Fatal("followup receipt/lifetime changed")
	}
	historyOperatorAccept(t, f, cap, messages)
	response, value = f.call(t, "POST", f.path+"/query", map[string]any{"identity": messages.Identity}, f.csrf, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatal("message query", response.StatusCode)
	}
	raw, _ := json.Marshal(value)
	if !strings.Contains(string(raw), "synthetic-private-history-content") {
		t.Fatal("selected message missing")
	}
	f.clock.set(d.ExpiresAt)
	response, value = f.call(t, "POST", f.path+"/query", map[string]any{"identity": messages.Identity}, f.csrf, nil)
	raw, _ = json.Marshal(value)
	if response.StatusCode == http.StatusOK || strings.Contains(string(raw), "synthetic-private-history-content") {
		t.Fatal("expired message released")
	}
}
func TestWindowsHistoryOperatorRequiresExplicitScopeCSRFAndKnownQuery(t *testing.T) {
	f, _ := historyOperatorFixture(t)
	body := map[string]any{"expectedFloor": "0", "search": map[string]any{"channel": "Security", "start": f.at.Add(-time.Hour), "end": f.at, "xpath": "*"}, "acknowledgeHistory": true, "acknowledgePlaintext": false}
	r, _ := f.call(t, "POST", f.path+"/create", body, f.csrf, nil)
	if r.StatusCode != 400 {
		t.Fatal("injected query accepted", r.StatusCode)
	}
	body["search"] = windowseventhistory.Search{Channel: "System", Start: f.at.Add(-time.Hour), End: f.at}
	body["acknowledgeHistory"] = false
	r, _ = f.call(t, "POST", f.path+"/create", body, f.csrf, nil)
	if r.StatusCode != 400 {
		t.Fatal("unacknowledged history", r.StatusCode)
	}
	body["acknowledgeHistory"] = true
	r, _ = f.call(t, "POST", f.path+"/create", body, "", nil)
	if r.StatusCode != 403 {
		t.Fatal("missing csrf", r.StatusCode)
	}
}
