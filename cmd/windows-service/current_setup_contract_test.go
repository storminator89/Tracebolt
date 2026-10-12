package main

import (
	"bytes"
	"context"
	"encoding/json"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsfullsoftware"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowsservice"
	"reflect"
	"strings"
	"testing"
)

func TestCurrentSetupPendingRejectsHistoricalReceiptAndConsent(t *testing.T) {
	c := freshReadAdminSetupConsent(false)
	r := installReceipt{Version: 12, Prepared: true, Service: windowsservice.Receipt{Version: 2, Complete: true}, ReadSetup: &readSetupProgress{Consent: c}}
	if !validCurrentSetupPendingReceipt(r) {
		t.Fatal("current pending rejected")
	}
	for _, version := range []int{2, 3, 11} {
		bad := r
		bad.Version = version
		if validCurrentSetupPendingReceipt(bad) {
			t.Fatal("old receipt accepted")
		}
	}
	bad := r
	copyProgress := *r.ReadSetup
	copyProgress.Consent = setupWizardConsent()
	bad.ReadSetup = &copyProgress
	if validCurrentSetupPendingReceipt(bad) {
		t.Fatal("old consent accepted")
	}
	if _, e := captureCurrentSetupPendingObservation(context.Background(), func() (installReceipt, error) { return bad, nil }, func(context.Context, windowsservice.Receipt) (windowsservice.Snapshot, error) {
		t.Fatal("invalid receipt reached SCM")
		return windowsservice.Snapshot{}, nil
	}); e == nil {
		t.Fatal("old receipt observed")
	}
}
func TestCurrentSetupCanonicalSenderRequiresAllUsedMarkersAndOriginalFloor(t *testing.T) {
	binding := strings.Repeat("a", 64)
	raw := []byte(`{"windowsNetworkContextUsed":true,"windowsFullProcessesUsed":true,"windowsFullSoftwareUsed":true,"windowsFullServicesUsed":true,"version":5,"binding":"` + binding + `","lastSequence":9,"pending":null}`)
	if !currentRetentionSender(raw, binding, 9) {
		t.Fatal("current sender rejected")
	}
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"version":5`), []byte(`"version":1`), 1), bytes.Replace(raw, []byte(`"windowsFullServicesUsed":true,`), nil, 1), bytes.Replace(raw, []byte(`"version":5`), []byte(`"windowsUserSoftwareUsed":true,"version":6`), 1)} {
		if currentRetentionSender(bad, binding, 9) {
			t.Fatal("missing/unapproved used scope admitted")
		}
	}
	if currentRetentionSender(raw, binding, 10) || currentRetentionSender(raw, strings.Repeat("b", 64), 1) {
		t.Fatal("sender floor/binding lost")
	}
}
func TestCurrentSetupGrantSpecsExactOrderedTwentyAndHistoryProof(t *testing.T) {
	r := installReceipt{Service: windowsservice.Receipt{ServiceSID: "inert", Layout: windowsservice.Layout{StateRoot: "inert"}}}
	specs := currentRetentionGrantSpecs(r)
	if len(specs) != 20 {
		t.Fatal("grant count")
	}
	if specs[6].path != specs[18].path || !reflect.DeepEqual(specs[6], specs[18]) {
		t.Fatal("history grant sharing lost")
	}
	for _, s := range specs {
		if s.options.Create || s.options.RuntimeSID != "inert" {
			t.Fatal("observer grants store creation")
		}
	}
	binding := strings.Repeat("a", 64)
	history := windowshistoryrequest.Consent{SchemaVersion: windowshistoryrequest.ConsentVersion, Scope: windowshistoryrequest.Scope, SenderBinding: binding, GrantID: strings.Repeat("b", 32), Profile: "tls", Enabled: true, HistoryAcknowledged: true, ContentAcknowledged: true}
	raw, _ := json.Marshal(history)
	if !currentRetentionGrant(raw, windowshistoryrequest.Scope, binding) {
		t.Fatal("history proof rejected")
	}
	history.ContentAcknowledged = false
	raw, _ = json.Marshal(history)
	if currentRetentionGrant(raw, windowshistoryrequest.Scope, binding) {
		t.Fatal("missing sensitive-content acknowledgement")
	}
	if currentRetentionGrant(raw, windowsfullsoftware.HistoryScope, binding) {
		t.Fatal("history domains interchangeable")
	}
	if len(lanclient.WindowsReadAdminScopesV14()) != 21 {
		t.Fatal("current profile drift requires versioned gate")
	}
}
