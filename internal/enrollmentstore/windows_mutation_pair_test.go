package enrollmentstore

import (
	"encoding/json"
	"localrmm/internal/actionpermit"
	msi "localrmm/internal/windowsmanagedmsi"
	job "localrmm/internal/windowsupdatejob"
	"testing"
)

func TestCoordinatedWindowsMutationPairRequiresFreshReciprocalIdentity(t *testing.T) {
	d := func(s string) string { return actionpermit.Digest([]byte(s)) }
	obj := func(v any) string { b, _ := json.Marshal(v); return actionpermit.Digest(b) }
	mb := msi.Binding{ManagerID: id("manager", 1), DeviceID: id("agent", 2), IncarnationDigest: d("anchor"), ExecutorID: id("executor", 3), ExecutorKeyID: d("MSI executor"), KeyID: d("MSI manager"), DeliveryGrantID: id("grant", 4), InstallGrantID: id("grant", 5)}
	wb := job.Binding{ManagerID: mb.ManagerID, DeviceID: mb.DeviceID, IncarnationDigest: mb.IncarnationDigest, ExecutorID: id("executor", 6), ExecutorKeyID: d("WUA executor"), KeyID: d("WUA manager"), GrantID: id("grant", 7)}
	m := msi.Grant{Version: msi.CoordinatedGrantVersion, Binding: mb, DeliveryEnabled: true, InstallEnabled: true, DeliveryAcknowledged: true, InstallAcknowledged: true, ServiceRiskAcknowledged: true, ExpiresAt: 1800000100, MutationPlanDigest: d("plan"), PeerBindingDigest: obj(wb)}
	w := job.Consent{Version: job.CoordinatedConsentVersion, Scope: job.Scope, Binding: wb, Enabled: true, Acknowledged: true, ExpiresAt: m.ExpiresAt, MutationPlanDigest: m.MutationPlanDigest, PeerBindingDigest: obj(mb)}
	if !coordinatedWindowsMutationPair(m, w) {
		t.Fatal("exact pair rejected")
	}
	for _, change := range []func(*msi.Grant, *job.Consent){func(m *msi.Grant, w *job.Consent) {
		m.Version = msi.GrantVersion
		m.MutationPlanDigest = ""
		m.PeerBindingDigest = ""
	}, func(m *msi.Grant, w *job.Consent) {
		w.Version = job.ConsentVersion
		w.MutationPlanDigest = ""
		w.PeerBindingDigest = ""
	}, func(m *msi.Grant, w *job.Consent) { w.PeerBindingDigest = d("other") }, func(m *msi.Grant, w *job.Consent) { m.PeerBindingDigest = d("other") }, func(m *msi.Grant, w *job.Consent) { w.MutationPlanDigest = d("other") }, func(m *msi.Grant, w *job.Consent) { w.Binding.IncarnationDigest = d("other") }} {
		a, b := m, w
		change(&a, &b)
		if coordinatedWindowsMutationPair(a, b) {
			t.Fatal("unpaired participant admitted")
		}
	}
}

func TestScheduledMSIPairRequiresBackgroundAndIndependentWUAConsent(t *testing.T) {
	d := func(s string) string { return actionpermit.Digest([]byte(s)) }
	obj := func(v any) string { b, _ := json.Marshal(v); return actionpermit.Digest(b) }
	mb := msi.Binding{ManagerID: id("manager", 1), DeviceID: id("agent", 2), IncarnationDigest: d("anchor"), ExecutorID: id("executor", 3), ExecutorKeyID: d("MSI executor"), KeyID: d("MSI manager"), DeliveryGrantID: id("grant", 4), InstallGrantID: id("grant", 5)}
	wb := job.Binding{ManagerID: mb.ManagerID, DeviceID: mb.DeviceID, IncarnationDigest: mb.IncarnationDigest, ExecutorID: id("executor", 6), ExecutorKeyID: d("WUA executor"), KeyID: d("WUA manager"), GrantID: id("grant", 7)}
	m := msi.Grant{Version: msi.ScheduledGrantVersion, ReusableAcknowledged: true, ScheduledEnabled: true, ScheduledAcknowledged: true, Binding: mb, DeliveryEnabled: true, InstallEnabled: true, DeliveryAcknowledged: true, InstallAcknowledged: true, ServiceRiskAcknowledged: true, ExpiresAt: 1800000100, MutationPlanDigest: d("plan"), PeerBindingDigest: obj(wb)}
	w := job.Consent{Version: job.BackgroundConsentVersion, BackgroundAcknowledged: true, Scope: job.Scope, Binding: wb, Enabled: true, Acknowledged: true, ExpiresAt: m.ExpiresAt, MutationPlanDigest: m.MutationPlanDigest, PeerBindingDigest: obj(mb)}
	if !coordinatedWindowsMutationPair(m, w) {
		t.Fatal("fresh MSI schedule rejected manual background WUA")
	}
	w.Version = job.ScheduledBackgroundConsentVersion
	w.ScheduleScope = job.ScheduleScope
	w.ScheduleAcknowledged = true
	if !coordinatedWindowsMutationPair(m, w) {
		t.Fatal("fresh MSI schedule rejected independently scheduled WUA")
	}
	w.Version = job.CoordinatedConsentVersion
	w.BackgroundAcknowledged = false
	w.ScheduleScope = ""
	w.ScheduleAcknowledged = false
	if coordinatedWindowsMutationPair(m, w) {
		t.Fatal("foreground WUA adopted scheduled MSI")
	}
	w.Version = job.BackgroundConsentVersion
	w.BackgroundAcknowledged = true
	m.ScheduledAcknowledged = false
	if coordinatedWindowsMutationPair(m, w) {
		t.Fatal("missing MSI schedule acknowledgement accepted")
	}
}
