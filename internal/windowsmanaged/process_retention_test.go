package windowsmanaged

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"localrmm/internal/windowsinventory"
)

func TestProcessMetricSelfRetentionInventoryCapsAndBytes(t *testing.T) {
	for _, byteLimited := range []bool{false, true} {
		r := fixtureReport()
		selfPID := uint32(windowsinventory.MaxProcesses)
		if byteLimited {
			r = largeReport()
			selfPID = MaxProcessRows - 1
		} else {
			r.Processes.Rows = nil
			for pid := selfPID; pid > 0; pid-- {
				r.Processes.Rows = append(r.Processes.Rows, Process{PID: pid, Name: "fixture.exe", Threads: 1})
			}
		}
		before, _ := json.Marshal(r)
		legacy, _, err := FromReport(r, fixtureGeneration)
		if err != nil {
			t.Fatal(err)
		}
		s, device, err := FromReportForProcessMetrics(r, fixtureGeneration, selfPID)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := Encode(s)
		if err != nil || len(raw) > MaxSnapshotBytes || len(s.Processes.Rows) > MaxProcessRows || len(s.Processes.Rows) == 0 {
			t.Fatal("bounded retained inventory", err)
		}
		if legacy.Processes.Rows[len(legacy.Processes.Rows)-1].PID == selfPID || s.Processes.Rows[len(s.Processes.Rows)-1].PID != selfPID {
			t.Fatal("fixture did not reproduce tail loss or self was lost", byteLimited)
		}
		if s.Processes.ObservedCount != uint32(len(r.Processes.Rows)) || !s.Processes.CountExact || s.Processes.Complete || !s.Processes.Truncated || s.Processes.Quality != QualityPartial || !s.CollectedAt.Equal(r.CollectedAt) {
			t.Fatal("retention changed original count, capture or partial truth")
		}
		for i, row := range s.Processes.Rows {
			if i > 0 && row.PID <= s.Processes.Rows[i-1].PID {
				t.Fatal("retained rows not PID-sorted")
			}
			if row.PID != selfPID && row.PID != legacy.Processes.Rows[i].PID {
				t.Fatal("did not remove highest nonself rows")
			}
		}
		after, _ := json.Marshal(r)
		if !bytes.Equal(before, after) || !reflect.DeepEqual(device.CPU, r.CPU) {
			t.Fatal("mutated caller report or basic metrics")
		}
		for i, j := 0, len(r.Processes.Rows)-1; i < j; i, j = i+1, j-1 {
			r.Processes.Rows[i], r.Processes.Rows[j] = r.Processes.Rows[j], r.Processes.Rows[i]
		}
		again, _, err := FromReportForProcessMetrics(r, fixtureGeneration, selfPID)
		other, _ := Encode(again)
		if err != nil || !bytes.Equal(raw, other) {
			t.Fatal("input permutation changed output", err)
		}
	}
}

func TestProcessMetricSelfRetentionMissingAndInventoryOnlyUnchanged(t *testing.T) {
	for _, r := range []windowsinventory.Report{fixtureReport(), largeReport()} {
		legacy, d, err := FromReport(r, fixtureGeneration)
		if err != nil {
			t.Fatal(err)
		}
		for _, pid := range []uint32{0, ^uint32(0)} {
			s, gotD, err := FromReportForProcessMetrics(r, fixtureGeneration, pid)
			if err != nil || !reflect.DeepEqual(legacy, s) || !reflect.DeepEqual(d, gotD) {
				t.Fatal("absent or disabled self changed ordinary output", pid, err)
			}
		}
	}
	r := fixtureReport()
	r.Processes.Rows = nil
	r.Processes.Complete, r.Processes.Quality = false, "denied"
	s, _, err := FromReportForProcessMetrics(r, fixtureGeneration, 9999)
	if err != nil || s.Processes.Quality != QualityDenied || len(s.Processes.Rows) != 0 || s.Processes.ObservedCount != 0 {
		t.Fatal("fabricated self in denied enumeration", err)
	}
}
