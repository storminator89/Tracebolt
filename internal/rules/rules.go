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
		{ID: "service", Title: "Dienstverfügbarkeit", Description: "Zuerst den Soll-Zustand prüfen und den Fehler eingrenzen, bevor etwas geändert wird.", ReadOnly: true, Steps: []string{"Prüfen, ob dieser Dienst auf dem Gerät tatsächlich laufen soll.", "Dienstzustand, letzten Exit-Code und gezielt begrenzte Log-Evidenz prüfen.", "Letzte Änderungen an Konfiguration und Abhängigkeiten prüfen.", "Ergebnis dokumentieren. Ein Neustart erfordert eine separate Freigabe."}},
		{ID: "storage", Title: "Speicherplatz prüfen", Description: "Den Speicherengpass bestätigen, ohne persönliche Dateien zu durchsuchen oder Daten zu löschen.", ReadOnly: true, Steps: []string{"Betroffenes lokales Volume und verfügbare Kapazität bestätigen.", "Letzte Messwerte vergleichen und prüfen, ob die Belegung weiter steigt.", "Freigegebene Aufbewahrungsregeln der Anwendung mit der verantwortlichen Person prüfen.", "Eine klar begrenzte Bereinigung vorschlagen. Dateien nicht automatisch löschen oder verschieben."}},
		{ID: "network", Title: "DNS-Auflösung prüfen", Description: "Beobachtete DNS-Fehler von Vermutungen über Netzwerk und Konfiguration trennen.", ReadOnly: true, Steps: []string{"Zeitraum und Umfang der erfassten DNS-Fehler prüfen.", "Freigegebene Resolver-Konfiguration und Schnittstellenzustand prüfen.", "Mit einem bekannten, freigegebenen Ziel vergleichen. Dieses MVP führt keine Netzwerkprobe aus.", "Beobachtung dokumentieren, bevor Konfigurationsänderungen vorgeschlagen werden."}},
	}
}
func Evaluate(d model.Device, s Signals, at time.Time) []model.Case {
	out := []model.Case{}
	// These V1 rules consume seeded demo signals only. Native observations are not
	// silently promoted to incidents without an implemented, provenance-aware input adapter.
	if !d.Synthetic {
		return out
	}
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
		out = append(out, model.Case{ID: id, Title: title, DeviceID: d.ID, DeviceName: d.Name, Severity: severity, Status: "open", Category: category, Summary: summary, RuleID: rule, Confidence: "evidence-backed", CreatedAt: at, UpdatedAt: at, EvidenceIDs: ids, Evidence: evidence, RunbookID: category, NextSteps: steps, Timeline: []model.Activity{{ID: id + "-created", Type: "case", Title: "Regel erfüllt", Detail: rule + " wurde anhand ausdrücklich synthetischer Beobachtungen geprüft. Es wurde keine automatische Aktion ausgeführt.", Time: at, DeviceID: d.ID, CaseID: id}}, Notes: []model.Note{}, Synthetic: d.Synthetic})
	}
	evidence := func(suffix, title, value, detail string) model.Evidence {
		return model.Evidence{ID: d.ID + "-" + suffix, Title: title, Value: value, Detail: detail, Source: "synthetic-fixture", Quality: "healthy", CollectedAt: at, Synthetic: d.Synthetic}
	}
	if s.ServiceRequired && !s.ServiceRunning && s.ServiceQuality == "healthy" {
		add("service", "critical", s.ServiceName+" ist gestoppt", "Ein als kritisch konfigurierter Dienst ist als gestoppt erfasst. Die Vorgabe verlangt ausdrücklich einen laufenden Dienst. Die Fehlerursache ist noch nicht belegt.", "service.required_stopped.v1", []model.Evidence{evidence("service-state", "Dienstzustand", "stopped", "Dienst: "+s.ServiceName+"; konfigurierter Soll-Zustand: läuft."), evidence("service-policy", "Dienstvorgabe", "required", "Die Demo-Vorgabe kennzeichnet diesen Dienst ausdrücklich als erforderlich. Andere gestoppte Dienste gelten nicht automatisch als Fehler.")})
	}
	if s.DiskUsedPercent != nil && *s.DiskUsedPercent >= 90 && *s.DiskUsedPercent <= 100 && s.DiskQuality == "healthy" {
		add("storage", "warning", "Datenträger nahezu voll", fmt.Sprintf("Das synthetische Systemvolume ist zu %.1f%% belegt und überschreitet den Grenzwert von 90%%. Das belegt einen Kapazitätsengpass. Ein Hardwarefehler oder dessen Ursache ist damit nicht belegt.", *s.DiskUsedPercent), "storage.used_gte_90.v1", []model.Evidence{evidence("disk-used", "Belegung des Systemvolumes", fmt.Sprintf("%.1f%%", *s.DiskUsedPercent), "Gemessener Belegungsgrad. Vor einer Bereinigung muss der verfügbare Speicherplatz bestätigt werden.")})
	}
	if s.DNSFailures >= 3 && s.DNSQuality == "healthy" && s.LinkUp && s.LinkQuality == "healthy" {
		add("network", "warning", "DNS-Auflösung fehlgeschlagen", "Mindestens drei DNS-Fehler wurden erfasst, während die synthetische Schnittstelle aktiv blieb. Ein Resolver-Problem ist eine Hypothese. Erreichbarkeit und domänenspezifische Fehler wurden noch nicht geprüft.", "network.dns_failures_gte_3_link_up.v1", []model.Evidence{evidence("dns-failures", "Erfasste DNS-Fehler", fmt.Sprintf("%d failures", s.DNSFailures), "Synthetisches Beobachtungsfenster von fünf Minuten. Es wurden keine Live-Proben ausgeführt."), evidence("link-state", "Schnittstellenzustand", "up", "Die konfigurierte Schnittstelle wird als aktiv gemeldet. Das allein belegt keine Internetverbindung.")})
	}
	return out
}
