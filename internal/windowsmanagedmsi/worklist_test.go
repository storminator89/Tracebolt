package windowsmanagedmsi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestManagedMSIWorklistWorstCaseMetadataBounds(t *testing.T) {
	now := int64(1800000000)
	key := Digest([]byte("manager"))
	manager := "manager_" + strings.Repeat("1", 32)
	// Maximum string sizes permitted by the package contract are exercised by the
	// existing package tests; here multiply complete reviewed records/requests.
	selection := Selection{SHA256: Digest([]byte("package")), Size: MaxRetainedPayloadBytes, ProductCode: "{11111111-2222-3333-4444-555555555555}", PackageCode: "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", Version: "1.2.3", Architecture: "amd64", Name: strings.Repeat("N", 120), TermsReviewDigest: Digest([]byte("terms")), ReviewReference: strings.Repeat("R", 160)}
	a := Artifact{Package: selection, NativeAcceptanceDigest: Digest([]byte("native")), PublisherStatus: "unverified", PublisherEvidenceDigest: Digest([]byte("publisher"))}
	w := Worklist{ID: "worklist_" + strings.Repeat("a", 32), Revision: 1, Name: strings.Repeat("W", 120), CreatedBy: "operator_" + strings.Repeat("b", 32), CreatedAt: now, ArtifactID: ArtifactIdentity(a), Package: selection, NativeAcceptanceDigest: a.NativeAcceptanceDigest, PublisherStatus: a.PublisherStatus, PublisherEvidenceDigest: a.PublisherEvidenceDigest, Group: WorklistGroup{ID: strings.Repeat("G", 80), Name: strings.Repeat("H", 120), Revision: MaxWorklistRevision}, Targets: []WorklistTarget{}, Batches: []WorklistBatch{}}
	for i := 1; i <= MaxDevices; i++ {
		b := Binding{ManagerID: manager, DeviceID: fmt.Sprintf("agent_%032x", i), IncarnationDigest: Digest([]byte(fmt.Sprint(i))), ExecutorID: fmt.Sprintf("executor_%032x", i), ExecutorKeyID: Digest([]byte(fmt.Sprint("executor", i))), KeyID: key, DeliveryGrantID: fmt.Sprintf("grant_%032x", i), InstallGrantID: fmt.Sprintf("grant_%032x", i+100)}
		w.Targets = append(w.Targets, WorklistTarget{Name: strings.Repeat("D", 120), Binding: b})
	}
	for i := 1; i <= MaxWorklistBatches; i++ {
		b := WorklistBatch{ID: fmt.Sprintf("batch_%032x", i), Kind: "deliver", ActorID: w.CreatedBy, SessionDigest: Digest([]byte(fmt.Sprint("session", i))), SessionExpiresAt: now + 3600, CreatedAt: now, ExpiresAt: now + 60, ClosedAt: now, CloseReason: "stopped", Acknowledgements: WorklistAcknowledgements{Acknowledged: true}, Items: []WorklistBatchItem{}}
		for k, t := range w.Targets {
			b.Items = append(b.Items, WorklistBatchItem{Request: WorklistRequest{DeviceID: t.Binding.DeviceID, Operation: "deliver", ArtifactID: w.ArtifactID, ArtifactRetiredCount: "0", BindingDigest: BindingDigest(t.Binding), TransferID: fmt.Sprintf("transfer_%032x", i*100+k), ExpiresAt: now + 60}, State: "not_dispatched"})
		}
		b.ConfirmationDigest = b.Digest()
		w.Batches = append(w.Batches, b)
	}
	if e := w.Validate(); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(w)
	t.Logf("25-target nine-batch record: %d bytes (limit %d)", len(raw), MaxWorklistBytes)
	j := WorklistJournal{Version: WorklistVersion, ManagerID: manager, KeyID: key, Revision: 1, ClockFloor: now, Worklists: []Worklist{}}
	for i := 0; i < MaxWorklists; i++ {
		copy := w
		copy.ID = fmt.Sprintf("worklist_%032x", i+1)
		if i > 0 {
			copy.ArchivedAt = now
		}
		j.Worklists = append(j.Worklists, copy)
	}
	raw, _ = json.Marshal(j)
	if j.Validate() != nil || len(raw) > MaxWorklistJournalBytes {
		t.Fatal("aggregate bound", len(raw))
	}
	t.Logf("nine maximum-count records: %d bytes (limit %d)", len(raw), MaxWorklistJournalBytes)
	w.Revision = MaxWorklistRevision + 1
	if w.Validate() == nil {
		t.Fatal("unsafe UI revision")
	}
	w.Revision = 1
	w.Batches[0].CreatedAt = now + 1
	w.Batches[0].ExpiresAt = now + 61
	w.Batches[0].ClosedAt = now + 1
	w.Batches[0].ConfirmationDigest = w.Batches[0].Digest()
	j.Worklists[0] = w
	if j.Validate() == nil {
		t.Fatal("future retained batch")
	}
}
