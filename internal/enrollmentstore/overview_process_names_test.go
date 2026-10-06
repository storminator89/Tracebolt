package enrollmentstore

import (
	"context"
	"fmt"
	"localrmm/internal/completeoverview"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewledger"
	"localrmm/internal/overviewwire"
	"reflect"
	"strings"
	"testing"
	"time"
)

// All identities and stat bytes are invented; no host source is read. Exercise
// the parser, strict snapshot, generation, wire, durable store and paged search.
func TestCompleteOverviewProcessCommWireStoreRoundTrip(t *testing.T) {
	f, store, path, snap, cert := overviewFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	source := completeoverview.Empty(id("sample", 900), at, completeoverview.ReasonReadFailed)
	names := []string{"kworker/0:0", "rcu_exp_par_gp_kthread_worker/0", `literal\name`}
	for i, name := range names {
		fields := make([]string, 50)
		for j := range fields {
			fields[j] = "0"
		}
		fields[0], fields[1], fields[11], fields[12], fields[17] = "I", "2", "123", "77", "1"
		pid := uint32(i + 1)
		row, err := completeoverview.ParseProcessStat([]byte(fmt.Sprintf("%d (%s) %s\n", pid, name, strings.Join(fields, " "))), pid, 4096, 100)
		if err != nil {
			t.Fatal(err)
		}
		source.Processes.Items = append(source.Processes.Items, row)
	}
	// An unreadable row keeps all details null rather than receiving zero values.
	source.Processes.Items = append(source.Processes.Items, completeoverview.Process{PID: 4, Observation: completeoverview.Observation{Status: completeoverview.Denied, Reason: completeoverview.ReasonPermissionDenied}})
	count := uint64(len(source.Processes.Items))
	source.Processes.Meta = completeoverview.SectionMeta{GenerationID: source.GenerationID, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: &count, CountExact: true, FieldCoverage: completeoverview.FieldCoverage{Observed: 3, Denied: 1}}
	raw, err := completeoverview.Encode(source)
	if err != nil {
		t.Fatal(err)
	}
	source, err = completeoverview.DecodeStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := overviewwire.GenerationID(snap.Approval.DeviceID, "processes", 1)
	if err != nil {
		t.Fatal(err)
	}
	manifest, chunks, err := overviewgeneration.Build(ctx, source, "processes", generation, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := overviewgeneration.ManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	binding := OverviewBinding{"processes", 1, generation, hash}
	message := func(operation string, payload any) overviewwire.Message {
		t.Helper()
		raw, err := overviewwire.EncodeMessage(operation, "processes", 1, generation, hash, payload)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := overviewwire.DecodeMessage(operation, raw)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	begin := message("begin", manifest)
	if _, err = store.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), binding, *begin.Manifest, at); err != nil {
		t.Fatal(err)
	}
	for _, chunk := range chunks {
		appendMessage := message("append", chunk)
		if _, err = store.OverviewAppend(ctx, snap.InvitationID, cert.CertificateHash(), binding, *appendMessage.Chunk, at); err != nil {
			t.Fatal(err)
		}
	}
	message("finalize", struct{}{})
	if _, err = store.OverviewFinalize(ctx, snap.InvitationID, cert.CertificateHash(), binding, at); err != nil {
		t.Fatal(err)
	}
	store.Close()
	store = f.open(t, path)
	page, err := store.OverviewPage(ctx, snap.Approval.DeviceID, overviewledger.PageRequest{Section: "processes", Limit: 100}, at.Add(time.Second))
	if err != nil || !page.Exhausted || len(page.Items) != 4 || page.Manifest.Processes.FieldCoverage != source.Processes.Meta.FieldCoverage {
		t.Fatalf("persisted process page: %+v %v", page, err)
	}
	for i, row := range page.Items {
		if row.Process == nil || !reflect.DeepEqual(*row.Process, source.Processes.Items[i]) {
			t.Fatalf("stored comm or observation changed at row %d", i)
		}
	}
	for _, search := range []string{"kworker/", `literal\`} {
		page, err = store.OverviewPage(ctx, snap.Approval.DeviceID, overviewledger.PageRequest{Section: "processes", Limit: 100, Search: search}, at.Add(time.Second))
		if err != nil || len(page.Items) != 1 || !strings.Contains(*page.Items[0].Process.Name, search) {
			t.Fatalf("literal comm search failed: %q %v", search, err)
		}
	}
}
