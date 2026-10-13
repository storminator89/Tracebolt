package macoslogwindow

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"
)

const (
	ProjectionSchema   = "tracebolt.macos-log-window-projection.v1"
	MaxRows            = 500
	MaxProjectionBytes = 512 << 10
	MaxMessageBytes    = 4 << 10
	MaxLabelBytes      = 256

	// Requirements for a future native adapter, not an accepted raw schema or
	// evidence of a reader implemented here. It must enforce these before decode.
	MaxCandidateEntries = 4096
	MaxCandidateBytes   = 8 << 20

	Observed    = "observed"
	Partial     = "partial"
	Denied      = "denied"
	Unavailable = "unavailable"
	Lost        = "result_lost"

	ReasonRowLimit       = "row_limit"
	ReasonByteLimit      = "byte_limit"
	ReasonCandidateLimit = "candidate_limit"
	ReasonSourcePartial  = "source_partial"
	ReasonAccessDenied   = "access_denied"
	ReasonUnsupported    = "unsupported_source"
	ReasonInvalidSource  = "invalid_source"
	ReasonBudget         = "budget_exceeded"
	ReasonUnavailable    = "source_unavailable"
	ReasonLost           = "result_lost"
)

// Row is a deliberately small internal projection, not an Apple record shape.
// Nil labels/messages mean unavailable; a pointer to "" means observed empty.
// Strings (including <private>, HTML, newlines and predicate-looking text) are
// untrusted data. Labels are not service identities, paths or join keys. There
// are no PIDs, source cursors or executable arguments. Equal rows may be genuine.
type Row struct {
	Timestamp        time.Time `json:"timestamp"`
	Process          *string   `json:"process"`
	Subsystem        *string   `json:"subsystem"`
	Category         *string   `json:"category"`
	Message          *string   `json:"message"`
	MessageTruncated bool      `json:"messageTruncated"`
}

// Projection is memory-only content. Observed means only that the bounded source
// query ended normally, never complete retained system history. Empty observed,
// partial, denied, unavailable and consumed-but-lost are distinct. CapturedAt is
// present only for observed/partial results; failed/lost states invent no capture.
// A parser cannot prove those claims: a future trusted adapter must establish them.
type Projection struct {
	SchemaVersion string     `json:"schemaVersion"`
	Request       Request    `json:"request"`
	State         string     `json:"state"`
	Reason        string     `json:"reason"`
	CapturedAt    *time.Time `json:"capturedAt"`
	Rows          []Row      `json:"rows"`
}

func (Projection) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("<macos-log-window projection redacted>"))
}
func (Row) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("<macos-log-window row redacted>"))
}

func validText(s *string, max int) bool {
	return s == nil || len(*s) <= max && utf8.ValidString(*s)
}

func validRowData(r Row) bool {
	return validText(r.Process, MaxLabelBytes) && validText(r.Subsystem, MaxLabelBytes) &&
		validText(r.Category, MaxLabelBytes) && validText(r.Message, MaxMessageBytes) &&
		(!r.MessageTruncated || r.Message != nil)
}

// The private wire slice stops before decoding row 501, rather than allocating
// an arbitrarily long []Row from a small array of empty objects and checking later.
// It also bounds each row's text before canonical re-encoding can expand escapes.
type boundedRows []Row

func (rows *boundedRows) UnmarshalJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	token, err := d.Token()
	if err != nil || token != json.Delim('[') {
		return ErrInvalid
	}
	out := make(boundedRows, 0)
	for d.More() {
		if len(out) == MaxRows {
			return ErrBounds
		}
		var r Row
		if d.Decode(&r) != nil || !validRowData(r) {
			return ErrInvalid
		}
		out = append(out, r)
	}
	if token, err = d.Token(); err != nil || token != json.Delim(']') {
		return ErrInvalid
	}
	*rows = out
	return nil
}

func validState(p Projection) bool {
	switch p.State {
	case Observed:
		return p.Reason == "" && p.CapturedAt != nil
	case Partial:
		return p.CapturedAt != nil && (p.Reason == ReasonRowLimit || p.Reason == ReasonByteLimit ||
			p.Reason == ReasonCandidateLimit || p.Reason == ReasonSourcePartial || p.Reason == ReasonBudget)
	case Denied:
		return p.CapturedAt == nil && len(p.Rows) == 0 && p.Reason == ReasonAccessDenied
	case Unavailable:
		return p.CapturedAt == nil && len(p.Rows) == 0 && (p.Reason == ReasonUnsupported ||
			p.Reason == ReasonInvalidSource || p.Reason == ReasonCandidateLimit ||
			p.Reason == ReasonBudget || p.Reason == ReasonUnavailable)
	case Lost:
		return p.CapturedAt == nil && len(p.Rows) == 0 && p.Reason == ReasonLost
	}
	return false
}

func validateProjection(p Projection, expected Request, now time.Time) error {
	if err := ValidateLive(expected, now); err != nil {
		return err
	}
	if p.SchemaVersion != ProjectionSchema || ValidateRequest(p.Request) != nil || p.Request != expected ||
		p.Rows == nil || !validState(p) {
		return ErrInvalid
	}
	if len(p.Rows) > MaxRows {
		return ErrBounds
	}
	if p.CapturedAt != nil && (!validTime(*p.CapturedAt) || p.CapturedAt.Before(expected.CreatedAt) ||
		p.CapturedAt.After(now) || !p.CapturedAt.Before(expected.ExpiresAt)) {
		return ErrInvalid
	}
	for _, r := range p.Rows {
		if !validTime(r.Timestamp) || r.Timestamp.Before(expected.Start) || !r.Timestamp.Before(expected.End) ||
			!validRowData(r) {
			return ErrInvalid
		}
	}
	return nil
}

// EncodeProjection never truncates or silently returns a prefix on failure.
// The encoded bound includes JSON escaping and the original request envelope.
func EncodeProjection(p Projection, expected Request, now time.Time) ([]byte, error) {
	if err := validateProjection(p, expected, now); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, ErrInvalid
	}
	if len(raw) > MaxProjectionBytes {
		return nil, ErrBounds
	}
	return raw, nil
}

// DecodeProjection accepts only Tracebolt's canonical internal projection. It
// deliberately does not accept `log show` output or any proposed Apple schema.
// expected must come from independently accepted request metadata, not this body.
func DecodeProjection(raw []byte, expected Request, now time.Time) (Projection, error) {
	var wire struct {
		SchemaVersion string      `json:"schemaVersion"`
		Request       Request     `json:"request"`
		State         string      `json:"state"`
		Reason        string      `json:"reason"`
		CapturedAt    *time.Time  `json:"capturedAt"`
		Rows          boundedRows `json:"rows"`
	}
	if err := decodeCanonical(raw, &wire, MaxProjectionBytes); err != nil {
		return Projection{}, err
	}
	p := Projection{wire.SchemaVersion, wire.Request, wire.State, wire.Reason, wire.CapturedAt, []Row(wire.Rows)}
	if err := validateProjection(p, expected, now); err != nil {
		return Projection{}, err
	}
	return p, nil
}
