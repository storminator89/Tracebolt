package analysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"localrmm/internal/health"
	"localrmm/internal/journalcache"
	"localrmm/internal/journalview"
	"localrmm/internal/model"
	"localrmm/internal/proactivejournal"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxJournalMessageBytes = 1024

// AnalyzeJournal may only receive an independently approved and revalidated
// bounded snapshot page. Its result includes sensitive source/model text: keep it solely
// in memory until the original capture expiry, never in the health-result store.
func (s *Service) AnalyzeJournal(ctx context.Context, x health.Incident, check health.Check, page journalcache.Page) (Result, error) {
	c, p, err := healthPacket(x, check)
	if err != nil {
		return Result{}, err
	}
	if !proactivejournal.BoundedPage(page) || x.Kind != "service" || page.Query.Unit != x.Target || !page.Query.End.Equal(x.OpenedAt.UTC().Truncate(time.Microsecond)) {
		return Result{}, ErrInvalidPacket
	}
	p.DataScope = proactivejournal.DataScope
	p.Gaps = []DataGap{{Code: "bounded-journal-only", EvidenceIDs: []string{}, Detail: "Only the exact approved service/window and warning-or-higher priority were captured. No full journal or dependency search was performed."}}
	metadata := fmt.Sprintf("Unit: %s; window: %s to %s; query: %s; snapshot: %s; coverage: %s/%s; selected source rows: %d..%d of %d", page.Query.Unit, page.Query.Start.Format("2006-01-02T15:04:05.999999Z"), page.Query.End.Format("2006-01-02T15:04:05.999999Z"), page.Identity.QueryDigest, page.SnapshotDigest, page.Coverage, page.Reason, page.Offset, page.Offset+len(page.Rows), page.TotalCapturedRows)
	p.Evidence = append(p.Evidence, model.Evidence{ID: "journal-window", Title: "Approved service log query", Source: "agent journal projection", Detail: metadata, Value: string(page.Coverage), Quality: "healthy", CollectedAt: page.ObservedAt.UTC()})
	for i, row := range page.Rows {
		if row.Unit != x.Target || row.Timestamp.Before(page.Query.Start) || row.Timestamp.After(page.Query.End) || row.Priority < 0 || row.Priority > page.Query.MaxPriority || len(row.Message) > journalview.MaxMessageBytes || !utf8.ValidString(row.Message) {
			return Result{}, ErrInvalidPacket
		}
		raw, _ := json.Marshal(row)
		sum := sha256.Sum256(raw)
		clear(raw)
		message, masked := journalview.MaskForExport(row.Message)
		clipped := len(message) > MaxJournalMessageBytes
		if clipped {
			message = message[:MaxJournalMessageBytes]
			for !utf8.ValidString(message) {
				message = message[:len(message)-1]
			}
		}
		id := fmt.Sprintf("journal-row-%03d", page.Offset+i)
		p.Evidence = append(p.Evidence, model.Evidence{ID: id, Title: fmt.Sprintf("Journal source row %d", page.Offset+i), Source: "journal:" + row.Unit, Detail: message, Value: fmt.Sprintf("priority=%d; projected-row-sha256=%s", row.Priority, hex.EncodeToString(sum[:])), Quality: "healthy", CollectedAt: row.Timestamp.UTC()})
		if masked || clipped {
			p.Gaps = append(p.Gaps, DataGap{Code: "journal-message-filtered", EvidenceIDs: []string{id}, Detail: "Recognized secret patterns were masked and/or this row was clipped to 1024 bytes. Masking is not a secrecy guarantee."})
		}
		at := row.Timestamp.UTC()
		if p.ObservationWindow.From == nil || at.Before(*p.ObservationWindow.From) {
			p.ObservationWindow.From = &at
		}
		if p.ObservationWindow.To == nil || at.After(*p.ObservationWindow.To) {
			p.ObservationWindow.To = &at
		}
	}
	if page.Coverage == journalview.Partial || page.TotalCapturedRows > len(page.Rows) || !page.CountExact {
		p.Gaps = append(p.Gaps, DataGap{Code: "journal-partial", EvidenceIDs: []string{"journal-window"}, Detail: "Selected rows are only part of the bounded captured source. Missing rows or inaccessible history cannot disprove a cause."})
	}
	if len(page.Rows) == 0 {
		p.Gaps = append(p.Gaps, DataGap{Code: "journal-empty", EvidenceIDs: []string{"journal-window"}, Detail: "The approved bounded query returned no rows. This does not prove no relevant events exist."})
	}
	// Remove only the health builder's no-logs claim; do not relax BuildPacket's
	// existing managed-profile restriction or accept arbitrary browser evidence.
	result, err := s.analyzePacket(ctx, c, p)
	if err == nil {
		limits := []string{}
		for _, v := range result.Limitations {
			if strings.Contains(v, "no checks or remediation run automatically") {
				v = "Only separately approved fixed journal reads run. Model output executes no checks, shell commands or remediation."
			}
			if !strings.Contains(v, "No logs, changes, dependencies") {
				limits = append(limits, v)
			}
		}
		result.Limitations = append(limits, journalview.RedactionWarning, "Journal-backed source and model text are kept only until the original capture expiry. They are not stored as durable health evidence.")
	}
	return result, err
}
