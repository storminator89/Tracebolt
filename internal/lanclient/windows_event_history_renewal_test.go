//go:build linux

package lanclient

import (
	"bytes"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowseventhistory"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorystate"
	"testing"
	"time"
)

func TestWindowsEventHistoryRenewalKeepsAnchorGrantFloorAndPendingBytes(t *testing.T) {
	f := newRenewalMaterialFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, false)
	before, after := f.material(t, f.initial), f.material(t, f.renewed)
	local := windowsEventHistoryContext(before)
	if local != windowsEventHistoryContext(after) || local.CertificateHash != f.initial.AnchorHash || bytes.Equal(before.certificate.Certificate[0], after.certificate.Certificate[0]) {
		t.Fatal("history identity changed or leaf failed to advance")
	}
	now := time.Now().UTC().Truncate(time.Second)
	c := windowshistoryrequest.Consent{SchemaVersion: windowshistoryrequest.ConsentVersion, Scope: windowshistoryrequest.Scope, SenderBinding: local.SenderBinding, GrantID: "11111111111111111111111111111111", Profile: local.Profile, Enabled: true, HistoryAcknowledged: true, ContentAcknowledged: true}
	r, _ := windowshistorystate.NewReports(local)
	raw, _ := windowshistorystate.EncodeReports(r)
	consumed, _ := windowshistorystate.NewConsumption(local)
	con, _ := windowshistorystate.EncodeConsumption(consumed)
	m := &eventMemory{values: map[string][]byte{"reports.json": raw, "consumed.json": con}}
	pending, e := windowshistorystate.StageCapability(m, local, c, now)
	if e != nil {
		t.Fatal(e)
	}
	record, e := windowshistoryrequest.NewSearch(local.DeviceID, local.CertificateHash, 1, c.GrantID, windowseventhistory.Search{Channel: "System", Start: now.Add(-time.Hour), End: now.Add(-time.Minute)}, now)
	if e != nil {
		t.Fatal(e)
	}
	policy, _ := windowshistoryrequest.Authorize(record.Description, c, local, now)
	if windowshistorystate.BeginClaim(m, local, record.Description, c, policy, now) != nil || windowshistorystate.Consume(m, local, record.Description, c, policy, now) != nil {
		t.Fatal("could not establish exact original floor")
	}
	next := windowsEventHistoryContext(after)
	retry, e := windowshistorystate.StageCapability(m, next, c, now.Add(time.Minute))
	if e != nil || !bytes.Equal(pending, retry) {
		t.Fatal("renewal rewrote capability bytes")
	}
	if windowshistorystate.Consume(m, next, record.Description, c, policy, now.Add(time.Minute)) == nil {
		t.Fatal("renewal recaptured history")
	}
}
