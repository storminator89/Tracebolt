package analysis

import (
	"context"
	"fmt"
	"localrmm/internal/health"
	"localrmm/internal/model"
	"math"
	"strings"
)

const HealthDataScope = "health-summary-v1"

// AnalyzeHealth accepts only a typed manager health snapshot under a separate,
// explicit provider/device scope. It does not relax BuildPacket's managed-data
// export filter, accept model-selected tools, or access the journal. The caller
// must authorize this scope before calling it. No arbitrary telemetry is copied.
func (s *Service) AnalyzeHealth(ctx context.Context, incident health.Incident, check health.Check) (Result, error) {
	c, p, err := healthPacket(incident, check)
	if err != nil {
		return Result{}, err
	}
	result, err := s.analyzePacket(ctx, c, p)
	if err == nil {
		result.Limitations = append(result.Limitations,
			"This explicitly scoped health summary contains an incident event and the check snapshot at analysis admission, not historical raw samples or journal content.",
			"Only typed rule fields are exported. Secret-pattern masking is best effort and is not a guarantee of anonymization; selected service names can reveal application details.")
	}
	return result, err
}

func healthPacket(x health.Incident, check health.Check) (model.Case, Packet, error) {
	bad := func() (model.Case, Packet, error) { return model.Case{}, Packet{}, ErrInvalidPacket }
	if !validID(x.ID) || !strings.HasPrefix(x.ID, "health_") || x.ResolvedAt != nil || x.OpenedAt.IsZero() || x.LastObservedAt.IsZero() || check.Key != x.Key || check.Kind != x.Kind || check.Target != x.Target || check.ObservedAt == nil || check.ObservedAt.IsZero() || check.State != "open" {
		return bad()
	}
	title, summary, runbook := "", "", ""
	switch x.Kind {
	case "filesystem":
		if x.Key != "filesystem:root" || x.Target != "/" || check.Value == nil || math.IsNaN(*check.Value) || math.IsInf(*check.Value, 0) || *check.Value < 0 || *check.Value > 100 {
			return bad()
		}
		title, summary, runbook = "Root-Dateisystem fast voll", "Fortlaufende Messwerte bestätigten mindestens 90 Prozent Root-Dateisystembelegung über 120 Sekunden. Die Ursache ist unbekannt.", "storage"
	case "service":
		if _, err := health.Services([]string{x.Target}); err != nil || x.Key != "service:"+x.Target || check.Value != nil {
			return bad()
		}
		title, summary, runbook = "Überwachter Dienst inaktiv", "Der ausgewählte Dienst meldete über 120 Sekunden inaktiv oder fehlgeschlagen. Die Ursache ist unbekannt.", "service"
	case "offline":
		if x.Key != "offline:contact" || x.Target != "agent" || check.Value != nil {
			return bad()
		}
		title, summary, runbook = "Agent-Kontakt fehlt", "Mehr als zwei Minuten ohne akzeptierte Übertragung, danach 60 Sekunden Bestätigung durch den Manager. Dies beweist keinen Geräteausfall.", "network"
	default:
		return bad()
	}
	// IDs describe the event/sample within this packet, not a device identity.
	event := model.Evidence{ID: "health-event", Title: "Bestätigter Regelvorfall", Source: "manager.health.incident", Detail: summary, Value: x.Kind, Quality: "healthy", CollectedAt: x.OpenedAt}
	value := "open"
	if check.Value != nil {
		value = fmt.Sprintf("%.2f %%", *check.Value)
	}
	target := x.Target
	// Defensive masking of credential-like service instance labels. There is no
	// generic log sanitizer here: raw logs are excluded entirely from this scope.
	lowered := strings.ToLower(target)
	for _, marker := range []string{"password", "passwd", "secret", "token", "apikey", "api_key", "credential"} {
		if strings.Contains(lowered, marker) {
			target = "[masked-service-name]"
			break
		}
	}
	detail := "Current manager check snapshot; not a historical raw sample. Target: " + target
	quality := "healthy"
	if x.Kind == "offline" {
		if x.LastObservedAt.Sub(*check.ObservedAt) > health.MaxAge {
			quality = "stale"
		}
		detail += ". Timestamp is the last accepted report, not the time the device became unavailable. A newer report alone does not establish the required confirmed recovery interval."
	}
	snapshot := model.Evidence{ID: "health-snapshot", Title: "Prüfung bei Analysebeginn", Source: "manager.health.check", Detail: detail, Value: value, Quality: quality, CollectedAt: check.ObservedAt.UTC()}
	c := model.Case{ID: x.ID, Title: title, Summary: summary, Category: x.Kind, RuleID: "health:" + x.Kind, RunbookID: runbook, CreatedAt: x.OpenedAt.UTC(), UpdatedAt: x.LastObservedAt.UTC(), EvidenceIDs: []string{event.ID, snapshot.ID}}
	from, to := event.CollectedAt, snapshot.CollectedAt
	if to.Before(from) {
		from, to = to, from
	}
	p := Packet{SchemaVersion: PacketVersion, DataScope: HealthDataScope, Case: CaseContext{ID: c.ID, Title: c.Title, Summary: c.Summary, Category: c.Category, RuleID: c.RuleID, RunbookID: c.RunbookID, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}, Evidence: []model.Evidence{event, snapshot}, MissingEvidenceIDs: []string{}, ObservationWindow: ObservationWindow{From: &from, To: &to}, Gaps: []DataGap{{Code: "no-logs", EvidenceIDs: []string{}, Detail: "Journal content is outside this approved scope. No logs were requested or searched."}, {Code: "no-historical-samples", EvidenceIDs: []string{"health-event"}, Detail: "The incident stores confirmed rule transitions, not every underlying raw sample."}}}
	if quality == "stale" {
		p.Gaps = append(p.Gaps, DataGap{Code: "quality-stale", EvidenceIDs: []string{snapshot.ID}, Detail: "An old report cannot prove current endpoint state."})
	}
	// Reject unexpected/future evidence rather than silently changing its age.
	if snapshot.CollectedAt.After(x.LastObservedAt.Add(health.MaxAge)) || from.IsZero() || to.IsZero() {
		return bad()
	}
	if _, err := p.encode(); err != nil {
		return bad()
	}
	return c, p, nil
}
