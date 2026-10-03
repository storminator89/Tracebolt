// Package rules contains deterministic, evidence-backed diagnostic rules.
// It does not invoke AI or execute suggested remediation.
package rules

import (
	"fmt"
	"localrmm/internal/model"
	"time"
)

type Signals struct {
	ServiceName     string
	ServiceRequired bool
	ServiceRunning  bool
	ServiceQuality  string
	DiskUsedPercent *float64
	DiskQuality     string
	DNSFailures     int
	DNSQuality      string
	LinkUp          bool
	LinkQuality     string
}

func Runbooks() []model.Runbook {
	return []model.Runbook{
		{ID: "service", Title: "Service availability", Description: "Verify the intended service state and scope the failure before changing anything.", ReadOnly: true, Steps: []string{"Confirm this service is expected to be running on this endpoint.", "Inspect the service state, last exit code and relevant bounded log evidence.", "Check recent configuration and dependency changes.", "Document the finding. Any restart requires separate operator approval."}},
		{ID: "storage", Title: "Storage pressure", Description: "Confirm filesystem pressure without scanning personal files or deleting data.", ReadOnly: true, Steps: []string{"Verify the affected local volume and available capacity.", "Compare the last samples and confirm whether growth is continuing.", "Check approved application retention settings with the owner.", "Propose a scoped cleanup; do not delete or move files automatically."}},
		{ID: "network", Title: "DNS resolution", Description: "Separate observed lookup failures from transport and configuration hypotheses.", ReadOnly: true, Steps: []string{"Verify the scope and timestamp of the recorded DNS failures.", "Inspect approved resolver configuration and interface state.", "Compare failures against a known approved destination; no network probe runs in this MVP.", "Record the observation before proposing configuration changes."}},
	}
}
func Evaluate(d model.Device, s Signals, at time.Time) []model.Case {
	out := []model.Case{}
	add := func(category, severity, title, summary, rule string, evidence []model.Evidence) {
		ids := []string{}
		for _, e := range evidence {
			ids = append(ids, e.ID)
		}
		steps := []string{}
		for _, b := range Runbooks() {
			if b.ID == category {
				steps = b.Steps
			}
		}
		id := "case-" + d.ID + "-" + category
		out = append(out, model.Case{ID: id, Title: title, DeviceID: d.ID, DeviceName: d.Name, Severity: severity, Status: "open", Category: category, Summary: summary, RuleID: rule, Confidence: "evidence-backed", CreatedAt: at, UpdatedAt: at, EvidenceIDs: ids, Evidence: evidence, RunbookID: category, NextSteps: steps, Timeline: []model.Activity{{ID: id + "-created", Type: "case", Title: "Rule matched", Detail: rule + " evaluated against explicitly synthetic observations. No automated action ran.", Time: at, DeviceID: d.ID, CaseID: id}}, Notes: []model.Note{}, Synthetic: d.Synthetic})
	}
	evidence := func(suffix, title, value, detail string) model.Evidence {
		return model.Evidence{ID: d.ID + "-" + suffix, Title: title, Value: value, Detail: detail, Source: "synthetic-fixture", Quality: "healthy", CollectedAt: at, Synthetic: d.Synthetic}
	}
	if s.ServiceRequired && !s.ServiceRunning && s.ServiceQuality == "healthy" {
		add("service", "critical", s.ServiceName+" is stopped", "A configured critical service is recorded as stopped. Its required-running policy is explicit. The failure cause is not established.", "service.required_stopped.v1", []model.Evidence{evidence("service-state", "Service state", "stopped", "Service: "+s.ServiceName+"; configured expected state: running."), evidence("service-policy", "Service policy", "required", "The demo policy explicitly marks this service as required. Other stopped services are not treated as failures.")})
	}
	if s.DiskUsedPercent != nil && *s.DiskUsedPercent >= 90 && *s.DiskUsedPercent <= 100 && s.DiskQuality == "healthy" {
		add("storage", "warning", "Storage pressure on system volume", fmt.Sprintf("The fixture system volume is %.1f%% used, above the 90%% rule threshold. This establishes capacity pressure, not hardware failure or its cause.", *s.DiskUsedPercent), "storage.used_gte_90.v1", []model.Evidence{evidence("disk-used", "System volume usage", fmt.Sprintf("%.1f%%", *s.DiskUsedPercent), "Measured used-capacity ratio; available space should be confirmed before any cleanup.")})
	}
	if s.DNSFailures >= 3 && s.DNSQuality == "healthy" && s.LinkUp && s.LinkQuality == "healthy" {
		add("network", "warning", "Repeated DNS lookup failures", "Three or more recorded DNS failures occurred while the fixture interface remained up. A resolver problem is a hypothesis; upstream reachability and domain-specific issues remain untested.", "network.dns_failures_gte_3_link_up.v1", []model.Evidence{evidence("dns-failures", "Recorded DNS failures", fmt.Sprintf("%d failures", s.DNSFailures), "Synthetic bounded five-minute observation window; no live probes were executed."), evidence("link-state", "Interface state", "up", "A configured interface is reported up; that alone does not prove Internet connectivity.")})
	}
	return out
}
