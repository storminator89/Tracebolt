package windowsservicehealth

import (
	"encoding/json"
	"fmt"
	"localrmm/internal/windowsmanaged"
	"strings"
	"testing"
	"time"
)

func TestServiceHistoryPrunesOnlyClosedAndRemainsBounded(t *testing.T) {
	s, in := configured(t)
	in.AuthorityUntil = at.Add(90 * 24 * time.Hour)
	for n := 0; n < 105; n++ {
		for i := 0; i < 5; i++ {
			if n > 0 || i > 0 {
				advance(&in, 30, "stopped")
			}
			evaluate(t, &s, in)
		}
		for i := 0; i < 3; i++ {
			advance(&in, 30, "running")
			evaluate(t, &s, in)
		}
	}
	if len(s.Incidents) != MaxIncidents || s.NextID != 105 {
		t.Fatal(len(s.Incidents), s.NextID)
	}
	before, _ := Encode(s)
	_ = s.View(in, in.ReceivedAt.Add(31*24*time.Hour), epoch)
	after, _ := Encode(s)
	if string(before) != string(after) {
		t.Fatal("read pruned")
	}
	advance(&in, int((31*24*time.Hour)/time.Second), "start_pending")
	evaluate(t, &s, in)
	if len(s.Incidents) != 0 {
		t.Fatal("closed history not pruned")
	}
}
func TestServiceBoundedWorstCaseEscapedNames(t *testing.T) {
	in := input()
	names := []string{}
	in.Sample.Services.Rows = []windowsmanaged.Service{}
	for i := 0; i < 15; i++ {
		name := fmt.Sprintf("%02d", i) + strings.Repeat("&", 254)
		in.Sample.Services.Rows = append(in.Sample.Services.Rows, windowsmanaged.Service{Name: name, DisplayName: strings.Repeat("&", 256), State: "stopped"})
		if i < 8 {
			names = append(names, name)
		}
	}
	in.Sample.Services.ObservedCount = 15
	in.Sample.Services.Source = "fixture service metadata"
	in.Sample.Services.Scope = "caller-visible only"
	snap := windowsmanaged.Snapshot{SchemaVersion: windowsmanaged.SchemaVersion, CollectionProfile: windowsmanaged.CollectionProfile, GenerationID: "sample_" + strings.Repeat("1", 32), CollectedAt: at, Services: in.Sample.Services,
		Hostname: unavailableSection[windowsmanaged.Hostname](), Processes: unavailableSection[windowsmanaged.Process](), Software: unavailableSection[windowsmanaged.Software](), Network: unavailableSection[windowsmanaged.InterfaceAddress]()}
	accepted, e := windowsmanaged.Encode(snap)
	if e != nil {
		t.Fatal("worst-case source is not accepted wire metadata", e)
	}
	if len(accepted) > windowsmanaged.MaxSnapshotBytes {
		t.Fatal("snapshot limit", len(accepted))
	}
	s := New()
	if e := s.Configure(in, true, names, 0, at); e != nil {
		t.Fatal(e)
	}
	tick := func(state string) {
		in.Sequence++
		in.ReceivedAt = in.ReceivedAt.Add(30 * time.Second)
		in.Sample.CollectedAt = in.ReceivedAt
		for i := range in.Sample.Services.Rows {
			in.Sample.Services.Rows[i].State = state
		}
		evaluate(t, &s, in)
	}
	for cycle := 0; cycle < 13; cycle++ {
		for i := 0; i < 5; i++ {
			tick("stopped")
		}
		for i := 0; i < 3; i++ {
			tick("running")
		}
	}
	if len(s.Incidents) != MaxIncidents || s.NextID != 104 {
		t.Fatal("worst-case fixture did not generate bounded history", len(s.Incidents), s.NextID)
	}
	raw, e := Encode(s)
	if e != nil || len(raw) > MaxStateBytes {
		t.Fatal("durable bound", len(raw), e)
	}
	view, e := json.Marshal(s.View(in, in.ReceivedAt, epoch))
	if e != nil || len(view) > MaxViewBytes {
		t.Fatal("view bound", len(view), e)
	}
	t.Logf("valid worst-case escaped-name state=%d view=%d bytes", len(raw), len(view))
}

func unavailableSection[T any]() windowsmanaged.Section[T] {
	return windowsmanaged.Section[T]{Source: "fixture", Scope: "fixture", Quality: "unavailable", Rows: []T{}}
}
