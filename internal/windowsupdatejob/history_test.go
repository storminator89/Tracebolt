package windowsupdatejob

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestHistoryRetainsLifetimeBoundAndExactOutcomes(t *testing.T) {
	f := fixture(t)
	ctx := context.Background()
	f.guard.current.LeafNotAfter = f.at.Unix() + 3600
	for i := 0; i < MaxJobs; i++ {
		f.id = fmt.Sprintf("update_%032x", i+1)
		f.source.value.CapturedAt = f.at.Unix()
		f.approve(t)
		f.at = f.at.Add(time.Minute)
	}
	history, e := f.m.History(ctx, f.consent.Binding.DeviceID)
	if e != nil || history.Available || history.Reason != "capacity_exhausted" || history.RemainingCapacity != 0 || len(history.Jobs) != MaxJobs {
		t.Fatal(history, e)
	}
	raw, _ := json.Marshal(history)
	for _, field := range []string{"preview", "signature", "envelope", "actorId", "publicKey"} {
		if bytes.Contains(raw, []byte(`"`+field+`":`)) {
			t.Fatal("history leaked authority", field)
		}
	}
	for i, j := range history.Jobs {
		if j.ID != fmt.Sprintf("update_%032x", MaxJobs-i) || j.RequestedAt <= 0 || j.ApprovedAt <= 0 || j.ClaimedAt != 0 || j.State != "expired" {
			t.Fatal("history reordered or invented outcome", j)
		}
		exact, e := f.m.View(ctx, history.DeviceID, f.actor, j.ID)
		if e != nil || exact.Job == nil || exact.Job.ID != j.ID {
			t.Fatal("old exact outcome missing", e)
		}
	}
	if _, e = f.m.View(ctx, history.DeviceID, f.actor, "update_"+strings.Repeat("f", 32)); e == nil {
		t.Fatal("missing exact outcome fell back")
	}
	// Returned snapshots cannot mutate retained evidence.
	history.Jobs[0].Selection.Revision++
	after, e := f.m.History(ctx, history.DeviceID)
	if e != nil || after.Jobs[0].Selection == history.Jobs[0].Selection {
		t.Fatal("history alias changed evidence", e)
	}
}
