package analysis

import (
	"context"
	"localrmm/internal/model"
	"time"
)

// NetworkReview is a fixed manager-side result, never user-supplied evidence.
// It contains no target identifier, address, hostname, port, or free text.
type NetworkReview struct {
	Kind, State, Reason string
	ObservedAt          time.Time
}

func ValidNetworkReview(x NetworkReview) bool {
	if x.ObservedAt.IsZero() {
		return false
	}
	switch x.Kind {
	case "dns":
		return x.State == "ok" && x.Reason == "dns_resolved" || x.State == "network_error" && (x.Reason == "dns_failed" || x.Reason == "timeout")
	case "tcp":
		return x.State == "ok" && x.Reason == "tcp_connected" || x.State == "network_error" && (x.Reason == "dns_failed" || x.Reason == "timeout" || x.Reason == "tcp_failed")
	}
	return false
}

func (s *Service) AnalyzeNetworkReview(ctx context.Context, x NetworkReview) (Result, error) {
	if !ValidNetworkReview(x) {
		return Result{}, ErrInvalidPacket
	}
	at := x.ObservedAt.UTC()
	summary := "One manager-side network check observation; this is not device or application health."
	c := model.Case{ID: "network-check-review", Title: "Manager network check", Summary: summary, Category: "network", RuleID: "manager-network-check", RunbookID: "network", CreatedAt: at, UpdatedAt: at}
	e := model.Evidence{ID: "network-check", Title: "Manager-side check result", Source: "manager.application-check", Detail: "One observation from the manager; DNS uses the system resolver. TCP tests one connection only, without application or TLS data.", Value: x.Kind + "/" + x.State + "/" + x.Reason, Quality: "healthy", CollectedAt: at}
	p := Packet{SchemaVersion: PacketVersion, DataScope: "application-network-review-once-v1", Case: CaseContext{ID: c.ID, Title: c.Title, Summary: c.Summary, Category: c.Category, RuleID: c.RuleID, RunbookID: c.RunbookID, CreatedAt: at, UpdatedAt: at}, Evidence: []model.Evidence{e}, MissingEvidenceIDs: []string{}, ObservationWindow: ObservationWindow{From: &at, To: &at}, Gaps: []DataGap{{Code: "single-observation", EvidenceIDs: []string{"network-check"}, Detail: "One manager-side observation does not establish device health, DNS authority, complete resolution, application health, or a root cause."}}}
	return s.analyzePacket(ctx, c, p)
}
