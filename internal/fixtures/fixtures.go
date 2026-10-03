// Package fixtures supplies explicitly synthetic examples. No fleet enrollment occurs.
package fixtures

import (
	"localrmm/internal/model"
	"localrmm/internal/rules"
	"time"
)

func pointer(v float64) *float64 { return &v }
func Seed(now time.Time) ([]model.Device, []model.Case) {
	at := now.UTC().Add(-3 * time.Minute)
	devices := []model.Device{}
	specs := []struct {
		id, name, platform, os, site, group, status string
		cpu, mem, disk                              float64
		uptime                                      string
		tags                                        []string
	}{
		{"demo-win-01", "BER-DC-01", "windows", "Windows Server 2025", "Berlin HQ", "Infrastructure", "critical", 24, 62, 47, "18d 4h", []string{"production", "directory"}},
		{"demo-linux-01", "FRA-APP-02", "linux", "Ubuntu 24.04 LTS", "Frankfurt DC", "Application servers", "attention", 38, 73, 94.6, "42d 8h", []string{"production", "web"}},
		{"demo-mac-01", "MUC-DESIGN-04", "macos", "macOS Tahoe 26", "Munich Studio", "Workstations", "attention", 12, 48, 38, "3d 6h", []string{"design", "apple-silicon"}},
		{"demo-win-02", "BER-FIN-07", "windows", "Windows 11 Enterprise", "Berlin HQ", "Workstations", "healthy", 16, 44, 32, "5d 2h", []string{"finance", "managed"}},
		{"demo-linux-02", "FRA-DB-01", "linux", "Debian 13", "Frankfurt DC", "Infrastructure", "healthy", 28, 67, 54, "23d 11h", []string{"database", "production"}},
		{"demo-mac-02", "HAM-ENG-12", "macos", "macOS Sequoia 15", "Hamburg Office", "Workstations", "healthy", 8, 36, 41, "1d 9h", []string{"engineering", "apple-silicon"}},
		{"demo-win-03", "BER-SALES-03", "windows", "Windows 11 Pro", "Berlin HQ", "Workstations", "stale", 0, 0, 0, "unknown", []string{"sales", "last-seen-2h"}},
	}
	for i, s := range specs {
		ip := "192.0.2." + []string{"11", "22", "34", "47", "51", "62", "73"}[i]
		quality := "healthy"
		seen := at
		metric := func(v float64) model.Metric {
			return model.Metric{Value: pointer(v), Unit: "%", Quality: quality, Source: "synthetic-fixture", CollectedAt: seen}
		}
		if s.status == "stale" {
			quality = "stale"
			seen = now.UTC().Add(-2 * time.Hour)
		}
		d := model.Device{ID: s.id, Name: s.name, Platform: s.platform, OS: s.os, Site: s.site, Group: s.group, IP: &ip, Status: s.status, Source: "synthetic", Synthetic: true, LastSeen: seen, AgentVersion: model.Version + "-demo", CPU: metric(s.cpu), Memory: metric(s.mem), Disk: metric(s.disk), Uptime: s.uptime, Tags: s.tags, Capabilities: []model.Capability{{ID: "metrics", Name: "Health metrics", Status: "supported", Detail: "Synthetic example observations only; no native endpoint has been enrolled."}, {ID: "service", Name: "Service state", Status: "limited", Detail: "Fixture evidence only. Native OS service adapters are not implemented."}, {ID: "updates", Name: "Patch assessment", Status: "unsupported", Detail: "Installed OS version is not a missing-update or vulnerability assessment."}}, Evidence: []model.Evidence{}, Trend: []float64{s.cpu * .7, s.cpu * .9, s.cpu * .85, s.cpu, s.cpu * .92, s.cpu * 1.1, s.cpu}, CaseIDs: []string{}}
		if s.status == "stale" {
			d.CPU.Value = nil
			d.Memory.Value = nil
			d.Disk.Value = nil
			d.Trend = []float64{}
		}
		devices = append(devices, d)
	}
	cases := []model.Case{}
	signals := []rules.Signals{{ServiceName: "DNS Server", ServiceRequired: true, ServiceRunning: false, ServiceQuality: "healthy"}, {DiskUsedPercent: pointer(94.6), DiskQuality: "healthy"}, {DNSFailures: 7, DNSQuality: "healthy", LinkUp: true, LinkQuality: "healthy"}}
	for i, s := range signals {
		cs := rules.Evaluate(devices[i], s, at)
		for _, c := range cs {
			devices[i].CaseIDs = append(devices[i].CaseIDs, c.ID)
			devices[i].Evidence = append(devices[i].Evidence, c.Evidence...)
		}
		cases = append(cases, cs...)
	}
	devices[6].Evidence = []model.Evidence{{ID: "demo-win-03-stale", Title: "Telemetry stale", Source: "synthetic-fixture", Quality: "stale", CollectedAt: devices[6].LastSeen, Detail: "No recent fixture sample is available. No conclusion about endpoint health is possible.", Value: "2 hours since sample", Synthetic: true}}
	return devices, cases
}
