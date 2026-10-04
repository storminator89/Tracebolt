// Package analysis prepares bounded evidence for optional, read-only local AI
// assistance. It never collects additional data or executes a proposed check.
package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/model"
	"sort"
	"time"
	"unicode/utf8"
)

const (
	PacketVersion     = "tracebolt.evidence-packet.v1"
	MaxEvidence       = 32
	MaxSourceEvidence = 128
	MaxPacketBytes    = 24 * 1024
	MaxFieldBytes     = 2048
)

var ErrInvalidPacket = errors.New("invalid or oversized evidence packet")

// CaseContext deliberately excludes device names, IPs, notes and timeline text.
// It is still untrusted data, including its title and summary.
type CaseContext struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Summary   string    `json:"summary"`
	Category  string    `json:"category"`
	RuleID    string    `json:"ruleId"`
	RunbookID string    `json:"runbookId"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	Synthetic bool      `json:"synthetic"`
}

// Packet is a snapshot, not an instruction channel. Evidence retains its
// original ID, source, time, quality and synthetic label without truncation.
type Packet struct {
	SchemaVersion      string            `json:"schemaVersion"`
	Case               CaseContext       `json:"case"`
	Evidence           []model.Evidence  `json:"evidence"`
	MissingEvidenceIDs []string          `json:"missingEvidenceIDs"`
	ObservationWindow  ObservationWindow `json:"observationWindow"`
	Gaps               []DataGap         `json:"gaps"`
}

// ObservationWindow is the extent of available timestamps, not a claim of
// continuous observation or an operator-selected collection window.
type ObservationWindow struct {
	From *time.Time `json:"from"`
	To   *time.Time `json:"to"`
}

type DataGap struct {
	Code        string   `json:"code"`
	EvidenceIDs []string `json:"evidenceIDs"`
	Detail      string   `json:"detail"`
}

// BuildPacket takes only evidence explicitly referenced by the trusted case.
// It sorts healthy observations before stale/unavailable ones, newest first,
// deduplicates identical observations, and reports missing/poor-quality data.
// Oversize/ambiguous input is rejected, never silently truncated.
// Callers must load the case/evidence from their own store, not a request body.
func BuildPacket(c model.Case, available []model.Evidence) (Packet, error) {
	bad := func(reason string) (Packet, error) { return Packet{}, fmt.Errorf("%w: %s", ErrInvalidPacket, reason) }
	if !exportableCollectionProfile(c.CollectionProfile) {
		return bad("case provenance is not approved for AI export")
	}
	if !validID(c.ID) || !bounded(c.Title, 256) || !bounded(c.Summary, MaxFieldBytes) || !bounded(c.Category, 64) || !bounded(c.RuleID, 128) || !bounded(c.RunbookID, 64) {
		return bad("case metadata exceeds bounds")
	}
	for _, e := range c.Evidence {
		if !exportableCollectionProfile(e.CollectionProfile) {
			return bad("case evidence provenance is not approved for AI export")
		}
	}
	if len(c.EvidenceIDs) > MaxEvidence || len(available) > MaxSourceEvidence {
		return bad("evidence count exceeds bounds")
	}
	wanted := make(map[string]bool, len(c.EvidenceIDs))
	for _, id := range c.EvidenceIDs {
		if !validID(id) {
			return bad("invalid case evidence ID")
		}
		wanted[id] = true
	}
	selected := make(map[string]model.Evidence, len(c.EvidenceIDs))
	for _, e := range available {
		if !wanted[e.ID] {
			continue
		}
		if !exportableCollectionProfile(e.CollectionProfile) {
			return bad("evidence provenance is not approved for AI export")
		}
		e.CollectedAt = e.CollectedAt.UTC()
		if previous, exists := selected[e.ID]; exists {
			if previous != e {
				return bad("ambiguous evidence ID")
			}
			continue
		}
		if !bounded(e.Title, 256) || !nonemptyBounded(e.Source, MaxFieldBytes) || !bounded(e.Detail, MaxFieldBytes) || !bounded(e.Value, MaxFieldBytes) || !validQuality(e.Quality) {
			return bad("evidence metadata exceeds bounds or has unknown quality")
		}
		// A missing timestamp is explicit unavailable provenance, not a current observation.
		if e.CollectedAt.IsZero() && e.Quality != "unknown" && e.Quality != "denied" {
			return bad("available evidence has no collection timestamp")
		}
		selected[e.ID] = e
	}
	p := Packet{
		SchemaVersion: PacketVersion,
		Case:          CaseContext{ID: c.ID, Title: c.Title, Summary: c.Summary, Category: c.Category, RuleID: c.RuleID, RunbookID: c.RunbookID, CreatedAt: c.CreatedAt.UTC(), UpdatedAt: c.UpdatedAt.UTC(), Synthetic: c.Synthetic},
		Evidence:      []model.Evidence{}, MissingEvidenceIDs: []string{}, Gaps: []DataGap{},
	}
	for id := range wanted {
		if e, ok := selected[id]; ok {
			p.Evidence = append(p.Evidence, e)
		} else {
			p.MissingEvidenceIDs = append(p.MissingEvidenceIDs, id)
		}
	}
	sort.Strings(p.MissingEvidenceIDs)
	qualityRank := map[string]int{"healthy": 0, "stale": 1, "unknown": 2, "denied": 3}
	sort.Slice(p.Evidence, func(i, j int) bool {
		a, b := p.Evidence[i], p.Evidence[j]
		if a.Quality != b.Quality {
			return qualityRank[a.Quality] < qualityRank[b.Quality]
		}
		if !a.CollectedAt.Equal(b.CollectedAt) {
			return a.CollectedAt.After(b.CollectedAt)
		}
		return a.ID < b.ID
	})
	if len(p.MissingEvidenceIDs) > 0 {
		p.Gaps = append(p.Gaps, DataGap{"missing-evidence", append([]string{}, p.MissingEvidenceIDs...), "Case-referenced observations were not supplied."})
	}
	for _, e := range p.Evidence {
		if e.Quality != "healthy" {
			p.Gaps = append(p.Gaps, DataGap{"quality-" + e.Quality, []string{e.ID}, "This observation cannot establish current state; preserve its collection quality."})
		}
		if !e.CollectedAt.IsZero() {
			at := e.CollectedAt
			if p.ObservationWindow.From == nil || at.Before(*p.ObservationWindow.From) {
				p.ObservationWindow.From = &at
			}
			if p.ObservationWindow.To == nil || at.After(*p.ObservationWindow.To) {
				p.ObservationWindow.To = &at
			}
		}
	}
	if len(p.Evidence) == 0 {
		p.Gaps = append(p.Gaps, DataGap{"no-evidence", []string{}, "No case-linked observations are available. No cause can be inferred."})
	}
	if _, err := p.encode(); err != nil {
		return Packet{}, err
	}
	return p, nil
}

func (p Packet) encode() ([]byte, error) {
	b, err := json.Marshal(p)
	if err != nil || len(b) > MaxPacketBytes {
		return nil, fmt.Errorf("%w: serialized packet exceeds bounds", ErrInvalidPacket)
	}
	return b, nil
}

func packetHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func bounded(s string, max int) bool         { return len(s) <= max && utf8.ValidString(s) }
func nonemptyBounded(s string, max int) bool { return s != "" && bounded(s, max) }

// IDs are opaque but tightly bounded canonical tokens, not markup or URLs.
func validID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}

func validQuality(q string) bool {
	return q == "healthy" || q == "stale" || q == "unknown" || q == "denied"
}

func exportableCollectionProfile(profile string) bool {
	return profile == "" || profile == "basic-readonly-v1"
}
