package api

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"localrmm/internal/store"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsresource"
	"localrmm/internal/windowsservicehealth"
)

var updateWindowsInboxFixture = flag.Bool("update-windows-inbox-fixture", false, "regenerate reviewed Windows inbox Go/TypeScript fixture")

func TestWindowsIncidentInboxWireFixture(t *testing.T) {
	base := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	epoch := "11111111111111111111111111111111"
	input := func(sec int) windowscapacity.Input {
		at := base.Add(time.Duration(sec) * time.Second)
		in := capacityFixtureInput(base)
		in.ReceivedAt = at
		in.Sequence = uint64(sec + 1)
		in.Disk.CollectedAt = at
		in.CPU = in.Disk
		in.Memory = in.Disk
		in.Services = windowsservicehealth.Sample{CollectedAt: at, Services: windowsmanaged.Section[windowsmanaged.Service]{Quality: "healthy", Complete: true, CountExact: true, ObservedCount: 1, Rows: []windowsmanaged.Service{{Name: "FixtureService", State: "stopped"}}}}
		return in
	}
	s := windowscapacity.New()
	in := input(0)
	if err := s.Configure(in, true, 90, 0, base); err != nil {
		t.Fatal(err)
	}
	service := windowsservicehealth.New()
	if err := service.Configure(windowsservicehealth.Input{Input: in.Input, Sample: in.Services}, true, []string{"FixtureService"}, 0, base); err != nil {
		t.Fatal(err)
	}
	contact := windowscontact.New()
	for sec := 0; sec <= 210; sec += 30 {
		in = input(sec)
		if err := s.Evaluate(in, in.ReceivedAt, epoch); err != nil {
			t.Fatal(err)
		}
		if err := service.Evaluate(windowsservicehealth.Input{Input: in.Input, Sample: in.Services}, in.ReceivedAt, epoch); err != nil {
			t.Fatal(err)
		}
		if err := contact.Evaluate(input(0).Input, in.ReceivedAt, epoch); err != nil {
			t.Fatal(err)
		}
	}
	snap := store.WindowsIncidentSnapshot{Contacts: map[string]windowscontact.State{in.DeviceID: contact}, Capacities: map[string]windowscapacity.State{in.DeviceID: s}, Resources: []windowsresource.State{{Version: 1, Metric: windowsresource.CPU, Assessment: s}, {Version: 1, Metric: windowsresource.Memory, Assessment: s}}, Services: map[string]windowsservicehealth.State{in.DeviceID: service}, Acknowledgements: map[string]store.WindowsIncidentAcknowledgement{}}
	target := windowsInboxTarget(in, "cpu", s.Incidents[0].ID, s.Incidents[0].OpenedAt)
	snap.Acknowledgements[target.Key()] = store.WindowsIncidentAcknowledgement{Version: 1, Target: target, AcknowledgedAt: in.ReceivedAt}
	views := map[string]windowsInboxView{}
	var err error
	views["active"], err = projectWindowsInbox(snap, map[string]windowscapacity.Input{in.DeviceID: in}, in.ReceivedAt, epoch, epoch, windowsInboxQuery{Scope: "active", Ack: "all", Limit: 25})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Configure(in, false, 90, 1, in.ReceivedAt); err != nil {
		t.Fatal(err)
	}
	snap.Capacities[in.DeviceID] = s
	views["resolved"], err = projectWindowsInbox(snap, map[string]windowscapacity.Input{in.DeviceID: in}, in.ReceivedAt, epoch, epoch, windowsInboxQuery{Scope: "resolved", Ack: "all", Limit: 25})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(views, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	path := filepath.Join("..", "..", "tests", "fixtures", "windows-incident-inbox-view.json")
	if *updateWindowsInboxFixture {
		if err = os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, raw) {
		t.Fatal("Windows inbox Go/TypeScript fixture changed; review before regeneration")
	}
}
