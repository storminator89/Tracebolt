package windowshistoryworker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"
	"unicode/utf8"

	"localrmm/internal/windowseventhistory"
	"localrmm/internal/windowshistoryrequest"
)

const maxRequestBytes = 32 << 10

// Request contains only bounded selected-event metadata. Local and Consent are
// comparisons, never authority: Serve must independently reload both from the
// verified installed identity. No path, executable, query selector, credential
// or caller-selected environment can cross this private IPC boundary.
type Request struct {
	Description  windowshistoryrequest.Description  `json:"description"`
	PolicyDigest string                             `json:"policyDigest"`
	ClaimedAt    time.Time                          `json:"claimedAt"`
	Local        windowshistoryrequest.LocalContext `json:"local"`
	Consent      windowshistoryrequest.Consent      `json:"consent"`
}

// Even header selections and local bindings are private diagnostic metadata.
func (Request) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("<windows-history-worker request redacted>"))
}

type wireResponse struct {
	Identity     windowshistoryrequest.Identity `json:"identity"`
	PolicyDigest string                         `json:"policyDigest"`
	ClaimedAt    time.Time                      `json:"claimedAt"`
	Report       windowseventhistory.Report     `json:"report"`
}

func validateRequest(req Request, now time.Time) error {
	if len(req.PolicyDigest) != len("sha256:")+64 || req.ClaimedAt.IsZero() ||
		req.ClaimedAt.Location() != time.UTC || req.ClaimedAt.Before(req.Description.CreatedAt) ||
		!req.ClaimedAt.Before(req.Description.ExpiresAt) || req.ClaimedAt.After(now) {
		return windowshistoryrequest.ErrInvalid
	}
	policy, err := windowshistoryrequest.Authorize(req.Description, req.Consent, req.Local, now)
	if err != nil {
		return err
	}
	if policy != req.PolicyDigest {
		return windowshistoryrequest.ErrInvalid
	}
	return nil
}

func encodeRequest(req Request) ([]byte, error) {
	// Authorize validates bounded fields before hashing or marshaling them. Use
	// the immutable claim time for shape validation, then recheck wall time at
	// every execution/release boundary.
	if err := validateRequest(req, req.ClaimedAt); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(req)
	if err != nil || len(raw) > maxRequestBytes {
		return nil, windowshistoryrequest.ErrInvalid
	}
	return raw, nil
}

func decodeCanonical(raw []byte, target any, limit int) error {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return windowshistoryrequest.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return windowshistoryrequest.ErrInvalid
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(raw, canonical) {
		return windowshistoryrequest.ErrInvalid
	}
	return nil
}

func decodeRequest(raw []byte) (Request, error) {
	var req Request
	if decodeCanonical(raw, &req, maxRequestBytes) != nil {
		return Request{}, windowshistoryrequest.ErrInvalid
	}
	if err := validateRequest(req, req.ClaimedAt); err != nil {
		return Request{}, err
	}
	return req, nil
}

func cloneRequest(req Request) Request {
	req.Description.Query.Search = windowseventhistory.CloneSearch(req.Description.Query.Search)
	req.Description.SourceSearch = windowseventhistory.CloneSearch(req.Description.SourceSearch)
	if req.Description.SearchReceipt != nil {
		receipt := *req.Description.SearchReceipt
		req.Description.SearchReceipt = &receipt
	}
	if req.Description.Query.Events != nil {
		events := make([]windowseventhistory.Event, len(req.Description.Query.Events))
		copy(events, req.Description.Query.Events)
		req.Description.Query.Events = events
	}
	return req
}

func sameRequest(a, b Request) bool {
	aRaw, aErr := encodeRequest(a)
	bRaw, bErr := encodeRequest(b)
	return aErr == nil && bErr == nil && bytes.Equal(aRaw, bRaw)
}

func validateReport(report windowseventhistory.Report, req Request, now time.Time) error {
	if windowseventhistory.ValidateReport(report, req.Description.Query) != nil ||
		report.CollectedAt.Before(req.ClaimedAt) || report.CollectedAt.After(now) ||
		!report.CollectedAt.Before(req.Description.ExpiresAt) {
		return ErrMetadata
	}
	return nil
}

func encodeResponse(report windowseventhistory.Report, req Request, now time.Time) ([]byte, error) {
	if err := validateReport(report, req, now); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(wireResponse{req.Description.Identity, req.PolicyDigest, req.ClaimedAt, report})
	if err != nil || len(raw) > MaxResponseBytes {
		return nil, ErrBounds
	}
	return raw, nil
}

func decodeResponse(raw []byte, req Request, now time.Time) (windowseventhistory.Report, error) {
	var wire wireResponse
	if decodeCanonical(raw, &wire, MaxResponseBytes) != nil || wire.Identity != req.Description.Identity ||
		wire.PolicyDigest != req.PolicyDigest || wire.ClaimedAt != req.ClaimedAt ||
		validateReport(wire.Report, req, now) != nil {
		return windowseventhistory.Report{}, ErrMetadata
	}
	return wire.Report, nil
}
