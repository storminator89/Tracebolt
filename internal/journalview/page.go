package journalview

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxPageRows         = 100
	MaxPageBytes        = 64 << 10
	pageMetadataReserve = 3072
)

var ErrPageConflict = errors.New("journal_view_page_conflict")

type Page struct {
	SchemaVersion     string    `json:"schemaVersion"`
	Scope             string    `json:"scope"`
	SnapshotDigest    string    `json:"snapshotDigest"`
	Query             Query     `json:"query"`
	ObservedAt        time.Time `json:"observedAt"`
	Coverage          Coverage  `json:"coverage"`
	Reason            Reason    `json:"reason"`
	Rows              []Row     `json:"rows"`
	ObservedCount     uint64    `json:"observedCount"`
	CountExact        bool      `json:"countExact"`
	RedactionApplied  bool      `json:"redactionApplied"`
	RedactionWarning  string    `json:"redactionWarning"`
	TotalCapturedRows int       `json:"totalCapturedRows"`
	Offset            int       `json:"offset"`
	NextOffset        *int      `json:"nextOffset"`
	NextCursor        string    `json:"nextCursor,omitempty"`
	Exhausted         bool      `json:"exhausted,omitempty"`
}

func (Page) String() string               { return "journalview.Page{content redacted}" }
func (p Page) GoString() string           { return p.String() }
func (p Page) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, p.String()) }

// SnapshotDigest binds canonical validated Encode bytes. It is an identity check,
// not an authorization token, MAC or authenticated server cursor.
func SnapshotDigest(s Snapshot) (string, error) {
	b, err := Encode(s)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// SelectPage never rereads a source. The caller supplies the expected immutable
// snapshot digest and a continuation index. A server must separately authorize
// the snapshot and authenticate/bind any external cursor. Offset zero is valid
// for empty snapshots; offset==total is otherwise a conflict, not another page.
func SelectPage(s Snapshot, expectedDigest string, offset, limit int) (Page, error) {
	if limit < 1 || limit > MaxPageRows {
		return Page{}, ErrInvalidInput
	}
	digest, err := SnapshotDigest(s)
	if err != nil {
		return Page{}, err
	}
	if expectedDigest != digest || offset < 0 || offset > len(s.Rows) || offset == len(s.Rows) && offset != 0 {
		return Page{}, ErrPageConflict
	}
	p := Page{SchemaVersion: s.SchemaVersion, Scope: s.Scope, SnapshotDigest: digest, Query: s.Query, ObservedAt: s.ObservedAt, Coverage: s.Coverage, Reason: s.Reason, Rows: make([]Row, 0, limit), ObservedCount: s.ObservedCount, CountExact: s.CountExact, RedactionApplied: s.RedactionApplied, RedactionWarning: s.RedactionWarning, TotalCapturedRows: len(s.Rows), Offset: offset, NextCursor: s.NextCursor, Exhausted: s.Exhausted}
	size := pageMetadataReserve
	for i := offset; i < len(s.Rows) && len(p.Rows) < limit; i++ {
		row := s.Rows[i]
		encoded, _ := json.Marshal(row) // already validated by Encode
		if len(encoded)+1 > MaxPageBytes-size {
			break
		}
		size += len(encoded) + 1
		p.Rows = append(p.Rows, row)
	}
	if offset+len(p.Rows) < len(s.Rows) {
		next := offset + len(p.Rows)
		p.NextOffset = &next
	}
	if _, err := EncodePage(p); err != nil {
		return Page{}, err
	}
	return p, nil
}

// EncodePage bounds the deliberate page wire representation. The digest format
// is checked; only SelectPage establishes its relation to a full snapshot.
func EncodePage(p Page) ([]byte, error) {
	if !validSnapshotMode(Snapshot{SchemaVersion: p.SchemaVersion, Query: p.Query, Coverage: p.Coverage, NextCursor: p.NextCursor, Exhausted: p.Exhausted}) || p.Scope != Scope || ValidateQuery(p.Query, p.ObservedAt) != nil || p.RedactionWarning != RedactionWarning || !validDigest(p.SnapshotDigest) || !validReason(p.Reason) || p.Rows == nil || len(p.Rows) > MaxPageRows || p.TotalCapturedRows < 0 || p.TotalCapturedRows > MaxRows || p.ObservedCount > MaxScannedRows || p.ObservedCount < uint64(p.TotalCapturedRows) || p.Offset < 0 || p.Offset > p.TotalCapturedRows || p.Offset == p.TotalCapturedRows && p.Offset != 0 || len(p.Rows) > p.TotalCapturedRows-p.Offset {
		return nil, ErrInvalidSnapshot
	}
	end := p.Offset + len(p.Rows)
	if end < p.TotalCapturedRows {
		if len(p.Rows) == 0 || p.NextOffset == nil || *p.NextOffset != end {
			return nil, ErrInvalidSnapshot
		}
	} else if p.NextOffset != nil {
		return nil, ErrInvalidSnapshot
	}
	switch p.Coverage {
	case Complete:
		if p.Reason != ReasonNone || !p.CountExact || p.ObservedCount != uint64(p.TotalCapturedRows) {
			return nil, ErrInvalidSnapshot
		}
	case Partial:
		if p.Reason == ReasonNone || p.CountExact {
			return nil, ErrInvalidSnapshot
		}
	case Failed:
		if p.Reason == ReasonNone || p.CountExact || p.TotalCapturedRows != 0 || p.ObservedCount != 0 || p.RedactionApplied {
			return nil, ErrInvalidSnapshot
		}
	default:
		return nil, ErrInvalidSnapshot
	}
	size := pageMetadataReserve
	for _, row := range p.Rows {
		if !validUTC(row.Timestamp) || row.Timestamp.Before(p.Query.Start) || row.Timestamp.After(p.Query.End) || row.Unit != p.Query.Unit || row.Priority < 0 || row.Priority > p.Query.MaxPriority || len(row.Message) > MaxMessageBytes || !utf8.ValidString(row.Message) {
			return nil, ErrInvalidSnapshot
		}
		b, e := json.Marshal(row)
		if e != nil {
			return nil, ErrInvalidSnapshot
		}
		size += len(b) + 1
		if size > MaxPageBytes {
			return nil, ErrSourceLimit
		}
	}
	b, e := json.Marshal(p)
	if e != nil {
		return nil, ErrInvalidSnapshot
	}
	if len(b) > MaxPageBytes {
		return nil, ErrSourceLimit
	}
	return b, nil
}
func validDigest(s string) bool {
	if len(s) != len("sha256:")+64 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	for _, c := range s[len("sha256:"):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
