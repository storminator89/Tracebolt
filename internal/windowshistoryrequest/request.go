// Package windowshistoryrequest defines the separate consent and consume-once
// metadata contract for bounded Windows event history. It has no transport,
// source execution, durable storage, or permission-grant side effects.
package windowshistoryrequest

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowseventhistory"
	"localrmm/internal/windowsevents"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	ConsentVersion = "tracebolt.windows-event-history-consent.v1"
	SchemaVersion  = "tracebolt.windows-event-history-request.v1"
	Scope          = "windows-application-system-event-history-v1"
	Lifetime       = 15 * time.Minute
	MaxHeaderAge   = 24 * time.Hour
	MaxRecordBytes = 32 << 10
	Pending        = "pending"
	Claimed        = "claimed"
	Accepted       = "accepted"
	Canceled       = "canceled"
	Expired        = "expired"
	Privacy        = "Read bounded older Application/System event headers and explicitly selected messages for the authenticated operator. Searches cover at most seven days within the thirty days before original creation, at most 100 headers and 256 KiB. Messages may contain credentials, personal data and other secrets. Results stay in bounded process memory until the original operation expiry, never in telemetry, durable result records, diagnostics, notifications or AI/provider export. This separate scope does not authorize other channels, arbitrary queries, subscriptions or increased host permissions."
	HTTPPrivacy    = "WARNING: HTTP-test sends event history and selected message content in plaintext. Network observers can read credentials, personal data and other secrets. Signatures do not encrypt content or authenticate manager responses. Production requires HTTPS."
)

var (
	ErrInvalid  = errors.New("windows_history_request_invalid")
	ErrDisabled = errors.New("windows_event_history_disabled")
	ErrConflict = errors.New("windows_history_request_conflict")
	ErrConsumed = errors.New("windows_history_request_consumed")
	ErrExpired  = errors.New("windows_history_request_expired")
	ErrCanceled = errors.New("windows_history_request_canceled")
)

// Consent is a new, independently protected local grant. Existing event-header
// and combined setup consent cannot be decoded as this scope. A sender binding
// binds the existing endpoint identity and destination; Profile comes from its
// trusted configuration, never a request body.
type Consent struct {
	SchemaVersion             string `json:"schemaVersion"`
	Scope                     string `json:"scope"`
	SenderBinding             string `json:"senderBinding"`
	GrantID                   string `json:"grantId"`
	Profile                   string `json:"profile"`
	Enabled                   bool   `json:"enabled"`
	HistoryAcknowledged       bool   `json:"historyAcknowledged"`
	ContentAcknowledged       bool   `json:"contentAcknowledged"`
	HTTPPlaintextAcknowledged bool   `json:"httpPlaintextAcknowledged"`
}

// LocalContext comes from activated local configuration, never from the remote
// request or consent document. All identity values must match independently.
type LocalContext struct {
	SenderBinding   string
	Profile         string
	DeviceID        string
	CertificateHash string
}

type Selection struct {
	Channel  string
	RecordID string
}
type Identity struct {
	ID          string `json:"id"`
	Sequence    uint64 `json:"sequence,string"`
	QueryDigest string `json:"queryDigest"`
}
type Budgets struct {
	MaxSearchEvents      int   `json:"maxSearchEvents"`
	MaxSearchBytes       int   `json:"maxSearchBytes"`
	MaxRangeHours        int   `json:"maxRangeHours"`
	MaxLookbackHours     int   `json:"maxLookbackHours"`
	MaxSelectedEvents    int   `json:"maxSelectedEvents"`
	MaxMessageBytes      int   `json:"maxMessageBytes"`
	MaxTotalMessageBytes int   `json:"maxTotalMessageBytes"`
	TimeoutMS            int64 `json:"timeoutMs"`
}

// FixedBudgets is immutable for v1 even if a future reader adds larger modes.
func FixedBudgets() Budgets { return Budgets{100, 256 << 10, 168, 720, 16, 16 << 10, 64 << 10, 5000} }

type Description struct {
	SourceSearch         *windowseventhistory.Search `json:"sourceSearch,omitempty"`
	SearchReceipt        *Receipt                    `json:"searchReceipt,omitempty"`
	SchemaVersion        string                      `json:"schemaVersion"`
	Identity             Identity                    `json:"identity"`
	DeviceID             string                      `json:"deviceId"`
	CertificateHash      string                      `json:"certificateHash"`
	GrantID              string                      `json:"grantId"`
	HeaderGenerationID   string                      `json:"headerGenerationId"`
	HeaderCollectedAt    time.Time                   `json:"headerCollectedAt"`
	HeaderSnapshotDigest string                      `json:"headerSnapshotDigest"`
	Query                windowseventhistory.Request `json:"query"`
	Budgets              Budgets                     `json:"budgets"`
	CreatedAt            time.Time                   `json:"createdAt"`
	ExpiresAt            time.Time                   `json:"expiresAt"`
}
type Receipt struct {
	Identity     Identity  `json:"identity"`
	PolicyDigest string    `json:"policyDigest"`
	ResultDigest string    `json:"resultDigest"`
	AcceptedAt   time.Time `json:"acceptedAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// Record never contains content or formatted OS errors. A future storage adapter
// must commit Claimed before returning work and retain the sequence floor through
// cancellation, expiry and restart. A client must durably consume the same claim
// before calling a reader. This pure state machine alone provides no such proof.
type Record struct {
	Description  Description `json:"description"`
	State        string      `json:"state"`
	PolicyDigest string      `json:"policyDigest"`
	ClaimedAt    *time.Time  `json:"claimedAt"`
	Receipt      *Receipt    `json:"receipt"`
	CanceledAt   *time.Time  `json:"canceledAt"`
	ExpiredAt    *time.Time  `json:"expiredAt"`
}

func validTime(t time.Time) bool { return t.Location() == time.UTC && t.Unix() > 0 && t.Year() <= 9999 }
func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validDigest(s string) bool {
	return strings.HasPrefix(s, "sha256:") && validHex(strings.TrimPrefix(s, "sha256:"), 64)
}
func digest(v any) (string, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return "", ErrInvalid
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
func canonical(raw []byte, v any, max int) error {
	if len(raw) == 0 || len(raw) > max || !utf8.Valid(raw) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	b, e := json.Marshal(v)
	if e != nil || !bytes.Equal(b, raw) {
		return ErrInvalid
	}
	return nil
}
func ValidateConsent(c Consent, binding, profile string) error {
	if c.SchemaVersion != ConsentVersion || c.Scope != Scope || !validHex(binding, 64) || c.SenderBinding != binding || !validHex(c.GrantID, 32) || c.Profile != profile || (profile != "tls" && profile != "http-test") || !c.HistoryAcknowledged || !c.ContentAcknowledged || c.HTTPPlaintextAcknowledged != (profile == "http-test") {
		return ErrInvalid
	}
	return nil
}
func EncodeConsent(c Consent, binding, profile string) ([]byte, error) {
	if ValidateConsent(c, binding, profile) != nil {
		return nil, ErrInvalid
	}
	return json.Marshal(c)
}
func DecodeConsent(raw []byte, binding, profile string) (Consent, error) {
	var c Consent
	if canonical(raw, &c, 2048) != nil || ValidateConsent(c, binding, profile) != nil {
		return Consent{}, ErrInvalid
	}
	return c, nil
}

// QueryFromSearch resolves exact selected identities only from the accepted
// original search result. Record IDs remain canonical decimal strings.
func QueryFromSearch(report windowseventhistory.Report, selected []Selection) (windowseventhistory.Request, error) {
	if report.Search == nil || windowseventhistory.ValidateReport(report, windowseventhistory.Request{Search: report.Search}) != nil || len(selected) < 1 || len(selected) > FixedBudgets().MaxSelectedEvents {
		return windowseventhistory.Request{}, ErrInvalid
	}
	q := windowseventhistory.Request{Events: make([]windowsevents.Event, 0, len(selected))}
	for _, selection := range selected {
		found := false
		for _, row := range report.Events {
			if row.Event.Channel == selection.Channel && strconv.FormatUint(row.Event.RecordID, 10) == selection.RecordID {
				q.Events = append(q.Events, row.Event)
				found = true
				break
			}
		}
		if !found {
			return windowseventhistory.Request{}, ErrInvalid
		}
	}
	if windowseventhistory.ValidateRequest(q) != nil {
		return windowseventhistory.Request{}, ErrInvalid
	}
	return q, nil
}
func queryDigest(d Description) (string, error) {
	// The domain, identity binding, original sample/capture, selection and immutable
	// expiry are all committed. Sequence and random ID are compared separately.
	return digest(struct {
		Domain          string                      `json:"domain"`
		SourceSearch    *windowseventhistory.Search `json:"sourceSearch,omitempty"`
		SearchReceipt   *Receipt                    `json:"searchReceipt,omitempty"`
		DeviceID        string                      `json:"deviceId"`
		CertificateHash string                      `json:"certificateHash"`
		GrantID         string                      `json:"grantId"`
		Generation      string                      `json:"generation"`
		HeaderTime      time.Time                   `json:"headerTime"`
		HeadersDigest   string                      `json:"headersDigest"`
		Query           windowseventhistory.Request `json:"query"`
		Budgets         Budgets                     `json:"budgets"`
		CreatedAt       time.Time                   `json:"createdAt"`
		ExpiresAt       time.Time                   `json:"expiresAt"`
	}{SchemaVersion, d.SourceSearch, d.SearchReceipt, d.DeviceID, d.CertificateHash, d.GrantID, d.HeaderGenerationID, d.HeaderCollectedAt, d.HeaderSnapshotDigest, d.Query, d.Budgets, d.CreatedAt, d.ExpiresAt})
}
func newID(prefix string) (string, error) {
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		return "", ErrInvalid
	}
	return prefix + hex.EncodeToString(id[:]), nil
}
func newRecord(d Description) (Record, error) {
	var e error
	d.Identity.QueryDigest, e = queryDigest(d)
	if e != nil {
		return Record{}, e
	}
	r := Record{Description: d, State: Pending}
	if Validate(r) != nil {
		return Record{}, ErrInvalid
	}
	return r, nil
}
func NewSearch(device, certificate string, sequence uint64, grantID string, search windowseventhistory.Search, now time.Time) (Record, error) {
	if windowseventhistory.ValidateSearch(search, now) != nil {
		return Record{}, ErrInvalid
	}
	id, e := newID("winhistory_")
	if e != nil {
		return Record{}, e
	}
	generation, e := newID("sample_")
	if e != nil {
		return Record{}, e
	}
	hd, e := digest(search)
	if e != nil {
		return Record{}, e
	}
	return newRecord(Description{SchemaVersion: SchemaVersion, Identity: Identity{ID: id, Sequence: sequence}, DeviceID: device, CertificateHash: certificate, GrantID: grantID, HeaderGenerationID: generation, HeaderCollectedAt: now, HeaderSnapshotDigest: hd, Query: windowseventhistory.Request{Events: []windowsevents.Event{}, Search: windowseventhistory.CloneSearch(&search)}, Budgets: FixedBudgets(), CreatedAt: now, ExpiresAt: now.Add(Lifetime)})
}

// NewMessages consumes the exact accepted search receipt and matching report.
// A new request identity/floor never refreshes the original operation expiry.
func NewMessages(device, certificate string, sequence uint64, grantID string, prior Record, report windowseventhistory.Report, selections []Selection, now time.Time) (Record, error) {
	if CheckTime(prior, now) != nil || prior.State != Accepted || prior.Receipt == nil || prior.Description.Query.Search == nil || prior.Description.DeviceID != device || prior.Description.CertificateHash != certificate || prior.Description.GrantID != grantID || sequence <= prior.Description.Identity.Sequence || windowseventhistory.ValidateReport(report, prior.Description.Query) != nil {
		return Record{}, ErrInvalid
	}
	result, e := digest(report)
	if e != nil || result != prior.Receipt.ResultDigest {
		return Record{}, ErrInvalid
	}
	q, e := QueryFromSearch(report, selections)
	if e != nil {
		return Record{}, e
	}
	id, e := newID("winhistory_")
	if e != nil {
		return Record{}, e
	}
	d := prior.Description
	d.Identity = Identity{ID: id, Sequence: sequence}
	d.Query = q
	d.SourceSearch = windowseventhistory.CloneSearch(prior.Description.Query.Search)
	receipt := *prior.Receipt
	d.SearchReceipt = &receipt
	return newRecord(d)
}
func ValidateDescription(d Description) error {
	if d.Budgets != FixedBudgets() || d.SchemaVersion != SchemaVersion || !enrollmentcrypto.ValidID(d.Identity.ID, "winhistory_") || d.Identity.Sequence == 0 || !enrollmentcrypto.ValidID(d.DeviceID, "agent_") || !validHex(d.CertificateHash, 64) || !validHex(d.GrantID, 32) || !strings.HasPrefix(d.HeaderGenerationID, "sample_") || !validHex(strings.TrimPrefix(d.HeaderGenerationID, "sample_"), 32) || !validDigest(d.HeaderSnapshotDigest) || !validTime(d.HeaderCollectedAt) || !validTime(d.CreatedAt) || !validTime(d.ExpiresAt) || d.ExpiresAt != d.CreatedAt.Add(Lifetime) || d.HeaderCollectedAt != d.CreatedAt || windowseventhistory.ValidateRequest(d.Query) != nil {
		return ErrInvalid
	}
	if d.Query.Search != nil {
		if d.Query.Events == nil || d.SourceSearch != nil || d.SearchReceipt != nil || windowseventhistory.ValidateSearch(*d.Query.Search, d.CreatedAt) != nil {
			return ErrInvalid
		}
		hd, e := digest(*d.Query.Search)
		if e != nil || hd != d.HeaderSnapshotDigest {
			return ErrInvalid
		}
	} else {
		x := d.SearchReceipt
		if d.SourceSearch == nil || x == nil || windowseventhistory.ValidateSearch(*d.SourceSearch, d.CreatedAt) != nil || !enrollmentcrypto.ValidID(x.Identity.ID, "winhistory_") || x.Identity.ID == d.Identity.ID || x.Identity.Sequence == 0 || x.Identity.Sequence >= d.Identity.Sequence || !validDigest(x.Identity.QueryDigest) || !validDigest(x.PolicyDigest) || !validDigest(x.ResultDigest) || !validTime(x.AcceptedAt) || x.AcceptedAt.Before(d.CreatedAt) || !x.AcceptedAt.Before(d.ExpiresAt) || x.ExpiresAt != d.ExpiresAt {
			return ErrInvalid
		}
		hd, e := digest(*d.SourceSearch)
		if e != nil || hd != d.HeaderSnapshotDigest {
			return ErrInvalid
		}
		for _, row := range d.Query.Events {
			if row.Channel != d.SourceSearch.Channel || row.Timestamp.Before(d.SourceSearch.Start) || !row.Timestamp.Before(d.SourceSearch.End) || d.SourceSearch.Level != nil && row.Level != *d.SourceSearch.Level || d.SourceSearch.EventID != nil && row.EventID != *d.SourceSearch.EventID {
				return ErrInvalid
			}
		}
		original := d
		original.Identity = x.Identity
		original.Query = windowseventhistory.Request{Events: []windowsevents.Event{}, Search: windowseventhistory.CloneSearch(d.SourceSearch)}
		original.SourceSearch = nil
		original.SearchReceipt = nil
		h, e := queryDigest(original)
		if e != nil || h != x.Identity.QueryDigest {
			return ErrInvalid
		}
	}
	h, e := queryDigest(d)
	if e != nil || h != d.Identity.QueryDigest {
		return ErrInvalid
	}
	return nil
}

// ValidateAgainstSearch is a manager-side creation check against the exact
// accepted search and surviving memory. It cannot recreate lost search results.
func ValidateAgainstSearch(d Description, prior Record, report windowseventhistory.Report) error {
	if ValidateDescription(d) != nil || Validate(prior) != nil || prior.State != Accepted || prior.Receipt == nil || d.SearchReceipt == nil || *d.SearchReceipt != *prior.Receipt || d.DeviceID != prior.Description.DeviceID || d.CertificateHash != prior.Description.CertificateHash || d.GrantID != prior.Description.GrantID || d.HeaderGenerationID != prior.Description.HeaderGenerationID || d.HeaderCollectedAt != prior.Description.HeaderCollectedAt || d.HeaderSnapshotDigest != prior.Description.HeaderSnapshotDigest || d.CreatedAt != prior.Description.CreatedAt || d.ExpiresAt != prior.Description.ExpiresAt || prior.Description.Query.Search == nil || windowseventhistory.ValidateReport(report, prior.Description.Query) != nil {
		return ErrInvalid
	}
	hash, e := digest(report)
	if e != nil || hash != prior.Receipt.ResultDigest {
		return ErrInvalid
	}
	selections := make([]Selection, len(d.Query.Events))
	for i, row := range d.Query.Events {
		selections[i] = Selection{row.Channel, strconv.FormatUint(row.RecordID, 10)}
	}
	q, e := QueryFromSearch(report, selections)
	if e != nil {
		return ErrInvalid
	}
	a, _ := json.Marshal(q)
	b, _ := json.Marshal(d.Query)
	if !bytes.Equal(a, b) {
		return ErrInvalid
	}
	return nil
}
func LastEvent(r Record) time.Time {
	if r.ExpiredAt != nil {
		return *r.ExpiredAt
	}
	if r.CanceledAt != nil {
		return *r.CanceledAt
	}
	if r.Receipt != nil {
		return r.Receipt.AcceptedAt
	}
	if r.ClaimedAt != nil {
		return *r.ClaimedAt
	}
	if r.Description.SearchReceipt != nil {
		return r.Description.SearchReceipt.AcceptedAt
	}
	return r.Description.CreatedAt
}
func Validate(r Record) error {
	d := r.Description
	if ValidateDescription(d) != nil {
		return ErrInvalid
	}
	if d.SearchReceipt != nil && r.ClaimedAt != nil && (r.ClaimedAt.Before(d.SearchReceipt.AcceptedAt) || r.PolicyDigest != d.SearchReceipt.PolicyDigest) {
		return ErrInvalid
	}
	if (r.ClaimedAt == nil) != (r.PolicyDigest == "") || r.ClaimedAt != nil && (!validDigest(r.PolicyDigest) || !validTime(*r.ClaimedAt) || r.ClaimedAt.Before(d.CreatedAt) || !r.ClaimedAt.Before(d.ExpiresAt)) {
		return ErrInvalid
	}
	if r.Receipt != nil {
		x := r.Receipt
		if r.ClaimedAt == nil || x.Identity != d.Identity || x.PolicyDigest != r.PolicyDigest || !validDigest(x.ResultDigest) || !validTime(x.AcceptedAt) || x.AcceptedAt.Before(*r.ClaimedAt) || !x.AcceptedAt.Before(d.ExpiresAt) || x.ExpiresAt != d.ExpiresAt {
			return ErrInvalid
		}
	}
	prior := d.CreatedAt
	if d.SearchReceipt != nil {
		prior = d.SearchReceipt.AcceptedAt
	}
	if r.ClaimedAt != nil {
		prior = *r.ClaimedAt
	}
	if r.Receipt != nil {
		prior = r.Receipt.AcceptedAt
	}
	if r.CanceledAt != nil {
		if !validTime(*r.CanceledAt) || r.CanceledAt.Before(prior) || !r.CanceledAt.Before(d.ExpiresAt) {
			return ErrInvalid
		}
		prior = *r.CanceledAt
	}
	if r.ExpiredAt != nil && (!validTime(*r.ExpiredAt) || r.ExpiredAt.Before(prior) || r.ExpiredAt.Before(d.ExpiresAt)) {
		return ErrInvalid
	}
	switch r.State {
	case Pending:
		if r.ClaimedAt != nil || r.Receipt != nil || r.CanceledAt != nil || r.ExpiredAt != nil {
			return ErrInvalid
		}
	case Claimed:
		if r.ClaimedAt == nil || r.Receipt != nil || r.CanceledAt != nil || r.ExpiredAt != nil {
			return ErrInvalid
		}
	case Accepted:
		if r.Receipt == nil || r.CanceledAt != nil || r.ExpiredAt != nil {
			return ErrInvalid
		}
	case Canceled:
		if r.CanceledAt == nil || r.ExpiredAt != nil {
			return ErrInvalid
		}
	case Expired:
		if r.ExpiredAt == nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	b, e := json.Marshal(r)
	if e != nil || len(b) > MaxRecordBytes {
		return ErrInvalid
	}
	return nil
}
func CheckTime(r Record, now time.Time) error {
	if Validate(r) != nil || !validTime(now) || now.Before(LastEvent(r)) {
		return ErrInvalid
	}
	if r.State == Expired || !now.Before(r.Description.ExpiresAt) {
		return ErrExpired
	}
	if r.State == Canceled {
		return ErrCanceled
	}
	return nil
}

// Authorize must run against freshly read protected local consent, both before
// capture and before releasing retained content. A previous successful call is
// not a reusable permission lease and does not prove a durable consumption mark.
func Authorize(d Description, c Consent, local LocalContext, now time.Time) (string, error) {
	if ValidateDescription(d) != nil || ValidateConsent(c, local.SenderBinding, local.Profile) != nil || d.DeviceID != local.DeviceID || d.CertificateHash != local.CertificateHash || !validTime(now) || now.Before(d.CreatedAt) {
		return "", ErrInvalid
	}
	if !now.Before(d.ExpiresAt) {
		return "", ErrExpired
	}
	if !c.Enabled || c.GrantID != d.GrantID {
		return "", ErrDisabled
	}
	policy, e := digest(c)
	if e != nil || d.SearchReceipt != nil && (policy != d.SearchReceipt.PolicyDigest || now.Before(d.SearchReceipt.AcceptedAt)) {
		return "", ErrInvalid
	}
	return policy, nil
}
func Claim(r Record, expected Identity, c Consent, local LocalContext, now time.Time) (Record, error) {
	if e := CheckTime(r, now); e != nil {
		return Record{}, e
	}
	if r.Description.Identity != expected {
		return Record{}, ErrConflict
	}
	if r.State != Pending {
		return Record{}, ErrConsumed
	}
	policy, e := Authorize(r.Description, c, local, now)
	if e != nil {
		return Record{}, e
	}
	r.State = Claimed
	r.PolicyDigest = policy
	r.ClaimedAt = &now
	if Validate(r) != nil {
		return Record{}, ErrInvalid
	}
	return r, nil
}

// Accept consumes a validated result into digest-only authority metadata. The
// caller may cache its content only after this record is durably committed.
func Accept(r Record, expected Identity, c Consent, local LocalContext, report windowseventhistory.Report, now time.Time) (Record, error) {
	if e := CheckTime(r, now); e != nil {
		return Record{}, e
	}
	if expected != r.Description.Identity {
		return Record{}, ErrConflict
	}
	if r.State != Claimed {
		return Record{}, ErrConsumed
	}
	policy, e := Authorize(r.Description, c, local, now)
	if e != nil {
		return Record{}, e
	}
	if policy != r.PolicyDigest || windowseventhistory.ValidateReport(report, r.Description.Query) != nil || report.CollectedAt.Before(*r.ClaimedAt) || report.CollectedAt.After(now) {
		return Record{}, ErrInvalid
	}
	result, e := digest(report)
	if e != nil {
		return Record{}, e
	}
	r.State = Accepted
	r.Receipt = &Receipt{expected, policy, result, now, r.Description.ExpiresAt}
	if Validate(r) != nil {
		return Record{}, ErrInvalid
	}
	return r, nil
}
func Cancel(r Record, expected Identity, now time.Time) (Record, error) {
	if e := CheckTime(r, now); e != nil {
		return Record{}, e
	}
	if expected != r.Description.Identity {
		return Record{}, ErrConflict
	}
	r.State = Canceled
	r.CanceledAt = &now
	if Validate(r) != nil {
		return Record{}, ErrInvalid
	}
	return r, nil
}
func Expire(r Record, now time.Time) (Record, error) {
	if Validate(r) != nil || !validTime(now) || now.Before(LastEvent(r)) || now.Before(r.Description.ExpiresAt) {
		return Record{}, ErrInvalid
	}
	if r.State == Expired {
		return r, nil
	}
	r.State = Expired
	r.ExpiredAt = &now
	if Validate(r) != nil {
		return Record{}, ErrInvalid
	}
	return r, nil
}
func Encode(r Record) ([]byte, error) {
	if Validate(r) != nil {
		return nil, ErrInvalid
	}
	return json.Marshal(r)
}
func Decode(raw []byte) (Record, error) {
	var r Record
	if canonical(raw, &r, MaxRecordBytes) != nil || Validate(r) != nil {
		return Record{}, ErrInvalid
	}
	return r, nil
}
