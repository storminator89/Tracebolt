// Package windowseventwire defines the bounded, purpose-separated selected
// Windows event-message transport. It grants no local read or durable authority.
package windowseventwire

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"localrmm/internal/windowseventcontent"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowsevents"
)

// EventDTO preserves all six original native fields without passing a uint64
// through a browser number. Timestamp retains the original 100ns precision.
type EventDTO struct {
	RecordID  string    `json:"recordId"`
	EventID   uint16    `json:"eventId"`
	Level     uint8     `json:"level"`
	Provider  string    `json:"provider"`
	Timestamp time.Time `json:"timestamp"`
	Channel   string    `json:"channel"`
}
type RequestDTO struct {
	Events []EventDTO `json:"events"`
}
type DescriptionDTO struct {
	SchemaVersion        string                       `json:"schemaVersion"`
	Identity             windowseventrequest.Identity `json:"identity"`
	DeviceID             string                       `json:"deviceId"`
	CertificateHash      string                       `json:"certificateHash"`
	GrantID              string                       `json:"grantId"`
	HeaderGenerationID   string                       `json:"headerGenerationId"`
	HeaderCollectedAt    time.Time                    `json:"headerCollectedAt"`
	HeaderSnapshotDigest string                       `json:"headerSnapshotDigest"`
	Query                RequestDTO                   `json:"query"`
	Budgets              windowseventrequest.Budgets  `json:"budgets"`
	CreatedAt            time.Time                    `json:"createdAt"`
	ExpiresAt            time.Time                    `json:"expiresAt"`
}
type EventResultDTO struct {
	Event     EventDTO `json:"event"`
	Message   string   `json:"message"`
	Quality   string   `json:"quality"`
	Complete  bool     `json:"complete"`
	Truncated bool     `json:"truncated"`
	Reason    string   `json:"reason,omitempty"`
}
type ReportDTO struct {
	Source      string           `json:"source"`
	Warning     string           `json:"warning"`
	Quality     string           `json:"quality"`
	CollectedAt time.Time        `json:"collectedAt"`
	Complete    bool             `json:"complete"`
	Truncated   bool             `json:"truncated"`
	Events      []EventResultDTO `json:"events"`
}
type GrantDTO struct {
	Description  DescriptionDTO `json:"description"`
	PolicyDigest string         `json:"policyDigest"`
	ClaimedAt    time.Time      `json:"claimedAt"`
}
type ResultDTO struct {
	Claim  Claim     `json:"claim"`
	Report ReportDTO `json:"report"`
}
type RecordDTO struct {
	Description  DescriptionDTO               `json:"description"`
	State        string                       `json:"state"`
	PolicyDigest string                       `json:"policyDigest"`
	ClaimedAt    *time.Time                   `json:"claimedAt"`
	Receipt      *windowseventrequest.Receipt `json:"receipt"`
	CanceledAt   *time.Time                   `json:"canceledAt"`
	ExpiredAt    *time.Time                   `json:"expiredAt"`
}

func eventDTO(e windowsevents.Event) EventDTO {
	return EventDTO{strconv.FormatUint(e.RecordID, 10), e.EventID, e.Level, e.Provider, e.Timestamp, e.Channel}
}
func (e EventDTO) Native() (windowsevents.Event, error) {
	id, ok := canonicalSequence(e.RecordID)
	if !ok {
		return windowsevents.Event{}, ErrContract
	}
	native := windowsevents.Event{RecordID: id, EventID: e.EventID, Level: e.Level, Provider: e.Provider, Timestamp: e.Timestamp, Channel: e.Channel}
	if windowseventcontent.ValidateRequest(windowseventcontent.Request{Events: []windowsevents.Event{native}}) != nil {
		return windowsevents.Event{}, ErrContract
	}
	return native, nil
}
func requestDTO(q windowseventcontent.Request) RequestDTO {
	out := RequestDTO{Events: make([]EventDTO, len(q.Events))}
	for i, e := range q.Events {
		out.Events[i] = eventDTO(e)
	}
	return out
}
func (q RequestDTO) Native() (windowseventcontent.Request, error) {
	if len(q.Events) < 1 || len(q.Events) > windowseventcontent.MaxSelectedEvents {
		return windowseventcontent.Request{}, ErrContract
	}
	out := windowseventcontent.Request{Events: make([]windowsevents.Event, len(q.Events))}
	for i, e := range q.Events {
		n, err := e.Native()
		if err != nil {
			return windowseventcontent.Request{}, err
		}
		out.Events[i] = n
	}
	if windowseventcontent.ValidateRequest(out) != nil {
		return windowseventcontent.Request{}, ErrContract
	}
	return out, nil
}
func DescriptionForBrowser(d windowseventrequest.Description) (DescriptionDTO, error) {
	if windowseventrequest.ValidateDescription(d) != nil {
		return DescriptionDTO{}, ErrContract
	}
	return DescriptionDTO{d.SchemaVersion, d.Identity, d.DeviceID, d.CertificateHash, d.GrantID, d.HeaderGenerationID, d.HeaderCollectedAt, d.HeaderSnapshotDigest, requestDTO(d.Query), d.Budgets, d.CreatedAt, d.ExpiresAt}, nil
}
func (d DescriptionDTO) Native() (windowseventrequest.Description, error) {
	q, e := d.Query.Native()
	if e != nil {
		return windowseventrequest.Description{}, e
	}
	out := windowseventrequest.Description{SchemaVersion: d.SchemaVersion, Identity: d.Identity, DeviceID: d.DeviceID, CertificateHash: d.CertificateHash, GrantID: d.GrantID, HeaderGenerationID: d.HeaderGenerationID, HeaderCollectedAt: d.HeaderCollectedAt, HeaderSnapshotDigest: d.HeaderSnapshotDigest, Query: q, Budgets: d.Budgets, CreatedAt: d.CreatedAt, ExpiresAt: d.ExpiresAt}
	if windowseventrequest.ValidateDescription(out) != nil {
		return windowseventrequest.Description{}, ErrContract
	}
	return out, nil
}

// ReportForBrowser deliberately accepts a valid partial report regardless of
// the native reader's separate fixed error return. Callers must inspect both.
func ReportForBrowser(r windowseventcontent.Report, q windowseventcontent.Request) (ReportDTO, error) {
	if windowseventcontent.ValidateReport(r, q) != nil {
		return ReportDTO{}, ErrContract
	}
	out := ReportDTO{r.Source, r.Warning, r.Quality, r.CollectedAt, r.Complete, r.Truncated, make([]EventResultDTO, len(r.Events))}
	for i, e := range r.Events {
		out.Events[i] = EventResultDTO{eventDTO(e.Event), e.Message, e.Quality, e.Complete, e.Truncated, e.Reason}
	}
	return out, nil
}
func (r ReportDTO) Native(q windowseventcontent.Request) (windowseventcontent.Report, error) {
	if len(r.Events) < 1 || len(r.Events) > windowseventcontent.MaxSelectedEvents {
		return windowseventcontent.Report{}, ErrContract
	}
	out := windowseventcontent.Report{Source: r.Source, Warning: r.Warning, Quality: r.Quality, CollectedAt: r.CollectedAt, Complete: r.Complete, Truncated: r.Truncated, Events: make([]windowseventcontent.Result, len(r.Events))}
	for i, e := range r.Events {
		n, err := e.Event.Native()
		if err != nil {
			return windowseventcontent.Report{}, err
		}
		out.Events[i] = windowseventcontent.Result{Event: n, Message: e.Message, Quality: e.Quality, Complete: e.Complete, Truncated: e.Truncated, Reason: e.Reason}
	}
	if windowseventcontent.ValidateReport(out, q) != nil {
		return windowseventcontent.Report{}, ErrContract
	}
	return out, nil
}
func RecordForBrowser(r windowseventrequest.Record) (RecordDTO, error) {
	if windowseventrequest.Validate(r) != nil {
		return RecordDTO{}, ErrContract
	}
	d, e := DescriptionForBrowser(r.Description)
	if e != nil {
		return RecordDTO{}, e
	}
	return RecordDTO{d, r.State, r.PolicyDigest, r.ClaimedAt, r.Receipt, r.CanceledAt, r.ExpiredAt}, nil
}
func (r RecordDTO) Native() (windowseventrequest.Record, error) {
	d, e := r.Description.Native()
	if e != nil {
		return windowseventrequest.Record{}, e
	}
	out := windowseventrequest.Record{Description: d, State: r.State, PolicyDigest: r.PolicyDigest, ClaimedAt: r.ClaimedAt, Receipt: r.Receipt, CanceledAt: r.CanceledAt, ExpiredAt: r.ExpiredAt}
	if windowseventrequest.Validate(out) != nil {
		return windowseventrequest.Record{}, ErrContract
	}
	return out, nil
}
func (v Grant) MarshalJSON() ([]byte, error) { return EncodeGrant(v) }
func (v *Grant) UnmarshalJSON(b []byte) error {
	out, e := DecodeGrant(b)
	if e == nil {
		*v = out
	}
	return e
}
func (v Result) MarshalJSON() ([]byte, error) { return EncodeResult(v) }
func (v *Result) UnmarshalJSON(b []byte) error {
	out, e := DecodeResult(b)
	if e == nil {
		*v = out
	}
	return e
}
func (v Status) MarshalJSON() ([]byte, error) { return EncodeStatusResponse(v) }
func (v *Status) UnmarshalJSON(b []byte) error {
	out, e := DecodeStatus(b)
	if e == nil {
		*v = out
	}
	return e
}

func redact(f fmt.State)                          { _, _ = io.WriteString(f, "<windows-event-content wire redacted>") }
func (EventDTO) Format(f fmt.State, _ rune)       { redact(f) }
func (RequestDTO) Format(f fmt.State, _ rune)     { redact(f) }
func (DescriptionDTO) Format(f fmt.State, _ rune) { redact(f) }
func (EventResultDTO) Format(f fmt.State, _ rune) { redact(f) }
func (ReportDTO) Format(f fmt.State, _ rune)      { redact(f) }
func (GrantDTO) Format(f fmt.State, _ rune)       { redact(f) }
func (ResultDTO) Format(f fmt.State, _ rune)      { redact(f) }
func (RecordDTO) Format(f fmt.State, _ rune)      { redact(f) }
func (Grant) Format(f fmt.State, _ rune)          { redact(f) }
func (Result) Format(f fmt.State, _ rune)         { redact(f) }
func (Status) Format(f fmt.State, _ rune)         { redact(f) }
func (Verified) Format(f fmt.State, _ rune)       { redact(f) }

// Keep json imported here explicitly: marshaling these public envelopes must
// exercise their safe DTO conversion even outside the provided encoder.
var _ json.Marshaler = Result{}
var _ json.Marshaler = Grant{}
var _ json.Marshaler = Status{}
