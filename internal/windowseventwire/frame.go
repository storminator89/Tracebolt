package windowseventwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowseventcontent"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowsevents"
)

const (
	MaxBodyBytes            = 512 << 10
	MaxMetadataBytes        = 32 << 10
	CapabilitySchemaVersion = "tracebolt.windows-event-content-capability.v1"
	CapabilityMaxAge        = 5 * time.Minute
)

var ErrContract = errors.New("windows_event_wire_invalid")

// Capability is independently sequenced public grant metadata. Reporting disabled
// consent preserves its original grant; neither enabled metadata nor a manager
// response grants any permission on the endpoint. CollectedAt never refreshes on
// a retry. The authenticated receiver must match device, certificate, profile and
// sender binding against its own activated identity and commit sequence state.
type Capability struct {
	SchemaVersion   string                      `json:"schemaVersion"`
	DeviceID        string                      `json:"deviceId"`
	CertificateHash string                      `json:"certificateHash"`
	Sequence        uint64                      `json:"sequence,string"`
	Consent         windowseventrequest.Consent `json:"consent"`
	PolicyDigest    string                      `json:"policyDigest"`
	CollectedAt     time.Time                   `json:"collectedAt"`
}

// Claim binds every operation to the exact request and original expiry. It is
// metadata, not proof that the manager or endpoint has durably consumed work.
type Claim struct {
	Identity        windowseventrequest.Identity `json:"identity"`
	PolicyDigest    string                       `json:"policyDigest"`
	DeviceID        string                       `json:"deviceId"`
	CertificateHash string                       `json:"certificateHash"`
	GrantID         string                       `json:"grantId"`
	ExpiresAt       time.Time                    `json:"expiresAt"`
}
type Grant struct {
	Description  windowseventrequest.Description `json:"description"`
	PolicyDigest string                          `json:"policyDigest"`
	ClaimedAt    time.Time                       `json:"claimedAt"`
}

// Result is memory-only, including when obtained via its JSON marshaler. Never
// place its serialization in telemetry, durable state, diagnostics or AI export.
type Result struct {
	Claim  Claim                      `json:"claim"`
	Report windowseventcontent.Report `json:"report"`
}
type StatusInput struct {
	Claim       Claim  `json:"claim"`
	LocalStatus string `json:"localStatus"`
}
type Status struct {
	Record        windowseventrequest.Record `json:"record"`
	LocalStatus   string                     `json:"localStatus"`
	ContentStatus string                     `json:"contentStatus"`
}
type statusDTO struct {
	Record        RecordDTO `json:"record"`
	LocalStatus   string    `json:"localStatus"`
	ContentStatus string    `json:"contentStatus"`
}

func validPath(path string) bool {
	return path == PeekPath || path == ClaimPath || path == ResultPath || path == StatusPath || path == CapabilityPath
}
func BodyLimit(path string) int64 {
	if path == ResultPath {
		return MaxBodyBytes
	}
	return MaxMetadataBytes
}
func ValidDigest(v string) bool {
	return strings.HasPrefix(v, "sha256:") && validHex(strings.TrimPrefix(v, "sha256:"), 64)
}
func validHex(v string, n int) bool {
	if len(v) != n {
		return false
	}
	for _, r := range v {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
func validTime(t time.Time) bool { return t.Location() == time.UTC && t.Unix() > 0 && t.Year() <= 9999 }
func ValidIdentity(i windowseventrequest.Identity) bool {
	return enrollmentcrypto.ValidID(i.ID, "winevent_") && i.Sequence > 0 && ValidDigest(i.QueryDigest)
}
func ValidLocalStatus(s string) bool {
	switch s {
	case "", "checking", "disabled", "denied", "reader_unavailable", "result_lost", "expired", "canceled":
		return true
	}
	return false
}

// decode requires the sole canonical representation. Re-encoding rejects
// duplicate, missing, unknown, case-folded keys, noncanonical numbers, nulls and
// trailing data without including body-derived diagnostics in returned errors.
func decode(raw []byte, max int, out any) error {
	if len(raw) == 0 || len(raw) > max || !utf8.Valid(raw) {
		return ErrContract
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrContract
	}
	canonical, e := json.Marshal(out)
	if e != nil || !bytes.Equal(raw, canonical) {
		return ErrContract
	}
	return nil
}
func encode(v any, max int) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil || len(b) > max || !utf8.Valid(b) {
		return nil, ErrContract
	}
	return b, nil
}
func digest(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
func PolicyDigest(c windowseventrequest.Consent) (string, error) {
	b, e := windowseventrequest.EncodeConsent(c, c.SenderBinding, c.Profile)
	if e != nil {
		return "", ErrContract
	}
	return digest(b), nil
}
func ValidateCapability(c Capability) error {
	if c.SchemaVersion != CapabilitySchemaVersion || !enrollmentcrypto.ValidID(c.DeviceID, "agent_") || !validHex(c.CertificateHash, 64) || c.Sequence == 0 || !validTime(c.CollectedAt) {
		return ErrContract
	}
	p, e := PolicyDigest(c.Consent)
	if e != nil || p != c.PolicyDigest {
		return ErrContract
	}
	return nil
}
func CapabilityFor(c windowseventrequest.Consent, local windowseventrequest.LocalContext, sequence uint64, at time.Time) (Capability, error) {
	if windowseventrequest.ValidateConsent(c, local.SenderBinding, local.Profile) != nil {
		return Capability{}, ErrContract
	}
	p, e := PolicyDigest(c)
	if e != nil {
		return Capability{}, e
	}
	out := Capability{CapabilitySchemaVersion, local.DeviceID, local.CertificateHash, sequence, c, p, at}
	if ValidateCapability(out) != nil {
		return Capability{}, ErrContract
	}
	return out, nil
}

// CapabilityFresh is a creation gate using original capture time, never receipt
// time. Disabled capabilities are valid metadata; callers separately test Enabled.
func CapabilityFresh(c Capability, now time.Time) error {
	if ValidateCapability(c) != nil || !validTime(now) || now.Before(c.CollectedAt) || !now.Before(c.CollectedAt.Add(CapabilityMaxAge)) {
		return ErrContract
	}
	return nil
}
func EncodeCapability(c Capability) ([]byte, error) {
	if ValidateCapability(c) != nil {
		return nil, ErrContract
	}
	return encode(c, MaxMetadataBytes)
}
func DecodeCapability(raw []byte) (Capability, error) {
	var c Capability
	if decode(raw, MaxMetadataBytes, &c) != nil || ValidateCapability(c) != nil {
		return Capability{}, ErrContract
	}
	return c, nil
}
func EncodePeek() ([]byte, error) { return []byte("{}"), nil }
func DecodePeek(b []byte) error {
	if !bytes.Equal(b, []byte("{}")) {
		return ErrContract
	}
	return nil
}
func ValidateClaim(c Claim) error {
	if !ValidIdentity(c.Identity) || !ValidDigest(c.PolicyDigest) || !enrollmentcrypto.ValidID(c.DeviceID, "agent_") || !validHex(c.CertificateHash, 64) || !validHex(c.GrantID, 32) || !validTime(c.ExpiresAt) {
		return ErrContract
	}
	return nil
}
func ClaimFor(d windowseventrequest.Description, policy string) (Claim, error) {
	if windowseventrequest.ValidateDescription(d) != nil {
		return Claim{}, ErrContract
	}
	c := Claim{d.Identity, policy, d.DeviceID, d.CertificateHash, d.GrantID, d.ExpiresAt}
	if ValidateClaim(c) != nil {
		return Claim{}, ErrContract
	}
	return c, nil
}
func ValidateClaimFor(c Claim, d windowseventrequest.Description) error {
	expected, e := ClaimFor(d, c.PolicyDigest)
	if e != nil || c != expected {
		return ErrContract
	}
	return nil
}
func EncodeClaim(c Claim) ([]byte, error) {
	if ValidateClaim(c) != nil {
		return nil, ErrContract
	}
	return encode(c, MaxMetadataBytes)
}
func DecodeClaim(raw []byte) (Claim, error) {
	var c Claim
	if decode(raw, MaxMetadataBytes, &c) != nil || ValidateClaim(c) != nil {
		return Claim{}, ErrContract
	}
	return c, nil
}
func EncodeDescription(d windowseventrequest.Description) ([]byte, error) {
	dto, e := DescriptionForBrowser(d)
	if e != nil {
		return nil, e
	}
	return encode(dto, MaxMetadataBytes)
}
func DecodeDescription(raw []byte) (windowseventrequest.Description, error) {
	var dto DescriptionDTO
	if decode(raw, MaxMetadataBytes, &dto) != nil {
		return windowseventrequest.Description{}, ErrContract
	}
	return dto.Native()
}
func ValidateGrant(g Grant) error {
	return contractError(windowseventrequest.Validate(windowseventrequest.Record{Description: g.Description, State: windowseventrequest.Claimed, PolicyDigest: g.PolicyDigest, ClaimedAt: &g.ClaimedAt}))
}
func contractError(e error) error {
	if e != nil {
		return ErrContract
	}
	return nil
}
func GrantFor(r windowseventrequest.Record) (Grant, error) {
	if windowseventrequest.Validate(r) != nil || r.State != windowseventrequest.Claimed || r.ClaimedAt == nil {
		return Grant{}, ErrContract
	}
	return Grant{r.Description, r.PolicyDigest, *r.ClaimedAt}, nil
}
func EncodeGrant(g Grant) ([]byte, error) {
	if ValidateGrant(g) != nil {
		return nil, ErrContract
	}
	d, e := DescriptionForBrowser(g.Description)
	if e != nil {
		return nil, e
	}
	return encode(GrantDTO{d, g.PolicyDigest, g.ClaimedAt}, MaxMetadataBytes)
}
func DecodeGrant(raw []byte) (Grant, error) {
	var dto GrantDTO
	if decode(raw, MaxMetadataBytes, &dto) != nil {
		return Grant{}, ErrContract
	}
	d, e := dto.Description.Native()
	if e != nil {
		return Grant{}, e
	}
	g := Grant{d, dto.PolicyDigest, dto.ClaimedAt}
	if ValidateGrant(g) != nil {
		return Grant{}, ErrContract
	}
	return g, nil
}
func reportQuery(r windowseventcontent.Report) windowseventcontent.Request {
	q := windowseventcontent.Request{Events: make([]windowsevents.Event, len(r.Events))}
	for i, p := range r.Events {
		q.Events[i] = p.Event
	}
	return q
}
func validateResultShape(v Result) error {
	if ValidateClaim(v.Claim) != nil || windowseventcontent.ValidateReport(v.Report, reportQuery(v.Report)) != nil || v.Report.CollectedAt.Before(v.Claim.ExpiresAt.Add(-windowseventrequest.Lifetime)) || !v.Report.CollectedAt.Before(v.Claim.ExpiresAt) {
		return ErrContract
	}
	return nil
}
func ValidateResult(v Result, d windowseventrequest.Description) error {
	if validateResultShape(v) != nil || ValidateClaimFor(v.Claim, d) != nil || windowseventcontent.ValidateReport(v.Report, d.Query) != nil {
		return ErrContract
	}
	return nil
}
func ValidateResultForGrant(v Result, g Grant) error {
	if ValidateGrant(g) != nil || ValidateResult(v, g.Description) != nil || v.Claim.PolicyDigest != g.PolicyDigest || v.Report.CollectedAt.Before(g.ClaimedAt) {
		return ErrContract
	}
	return nil
}
func EncodeResult(v Result) ([]byte, error) {
	if validateResultShape(v) != nil {
		return nil, ErrContract
	}
	r, e := ReportForBrowser(v.Report, reportQuery(v.Report))
	if e != nil {
		return nil, e
	}
	return encode(ResultDTO{v.Claim, r}, MaxBodyBytes)
}
func DecodeResult(raw []byte) (Result, error) {
	var dto ResultDTO
	if decode(raw, MaxBodyBytes, &dto) != nil {
		return Result{}, ErrContract
	}
	q := RequestDTO{Events: make([]EventDTO, len(dto.Report.Events))}
	for i, p := range dto.Report.Events {
		q.Events[i] = p.Event
	}
	native, e := q.Native()
	if e != nil {
		return Result{}, e
	}
	r, e := dto.Report.Native(native)
	if e != nil {
		return Result{}, e
	}
	v := Result{dto.Claim, r}
	if validateResultShape(v) != nil {
		return Result{}, ErrContract
	}
	return v, nil
}

// ResultDigest commits exact canonical wire bytes; store it separately from the
// foundation Receipt.ResultDigest, which commits the validated native Report.
func ResultDigest(v Result) (string, error) {
	b, e := EncodeResult(v)
	if e != nil {
		return "", e
	}
	return digest(b), nil
}
func ReportDigest(r windowseventcontent.Report, q windowseventcontent.Request) (string, error) {
	if windowseventcontent.ValidateReport(r, q) != nil {
		return "", ErrContract
	}
	b, e := json.Marshal(r)
	if e != nil {
		return "", ErrContract
	}
	return digest(b), nil
}
func EncodeStatus(v StatusInput) ([]byte, error) {
	if ValidateClaim(v.Claim) != nil || !ValidLocalStatus(v.LocalStatus) {
		return nil, ErrContract
	}
	return encode(v, MaxMetadataBytes)
}
func DecodeStatusInput(raw []byte) (StatusInput, error) {
	var v StatusInput
	if decode(raw, MaxMetadataBytes, &v) != nil {
		return StatusInput{}, ErrContract
	}
	if _, e := EncodeStatus(v); e != nil {
		return StatusInput{}, e
	}
	return v, nil
}
func EncodeReceipt(v windowseventrequest.Receipt) ([]byte, error) {
	if !ValidIdentity(v.Identity) || !ValidDigest(v.PolicyDigest) || !ValidDigest(v.ResultDigest) || !validTime(v.AcceptedAt) || !validTime(v.ExpiresAt) || !v.AcceptedAt.Before(v.ExpiresAt) || v.AcceptedAt.Before(v.ExpiresAt.Add(-windowseventrequest.Lifetime)) {
		return nil, ErrContract
	}
	return encode(v, MaxMetadataBytes)
}
func DecodeReceipt(raw []byte) (windowseventrequest.Receipt, error) {
	var v windowseventrequest.Receipt
	if decode(raw, MaxMetadataBytes, &v) != nil {
		return windowseventrequest.Receipt{}, ErrContract
	}
	if _, e := EncodeReceipt(v); e != nil {
		return windowseventrequest.Receipt{}, e
	}
	return v, nil
}
func validateStatus(v Status) error {
	if windowseventrequest.Validate(v.Record) != nil || !ValidLocalStatus(v.LocalStatus) || (v.ContentStatus != "available" && v.ContentStatus != "unavailable") || (v.ContentStatus == "available" && v.Record.State != windowseventrequest.Accepted) {
		return ErrContract
	}
	return nil
}
func EncodeStatusResponse(v Status) ([]byte, error) {
	if validateStatus(v) != nil {
		return nil, ErrContract
	}
	r, e := RecordForBrowser(v.Record)
	if e != nil {
		return nil, e
	}
	return encode(statusDTO{r, v.LocalStatus, v.ContentStatus}, MaxMetadataBytes)
}
func DecodeStatus(raw []byte) (Status, error) {
	var dto statusDTO
	if decode(raw, MaxMetadataBytes, &dto) != nil {
		return Status{}, ErrContract
	}
	r, e := dto.Record.Native()
	if e != nil {
		return Status{}, e
	}
	v := Status{r, dto.LocalStatus, dto.ContentStatus}
	if validateStatus(v) != nil {
		return Status{}, ErrContract
	}
	return v, nil
}
