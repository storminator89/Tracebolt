package windowssessionworker

import (
	"bytes"
	"encoding/json"
	"io"
	"time"
	"unicode/utf8"

	"localrmm/internal/windowssessions"
)

const maxRequestBytes = 1024

// The IPC contract has no config path, credentials, arbitrary queries, command
// options or serialized configuration. All authority is reread in the child.
type wireRequest struct {
	SenderBinding string    `json:"senderBinding"`
	GrantID       string    `json:"grantId"`
	GenerationID  string    `json:"generationId"`
	CollectedAt   time.Time `json:"collectedAt"`
}

func validateRequest(req windowssessions.Request) error {
	// Reject overlong strings before any serialization allocates a wire copy.
	if req.Consent.SchemaVersion != windowssessions.ConsentVersion || req.Consent.Scope != windowssessions.Scope ||
		len(req.SenderBinding) != 64 || len(req.Consent.SenderBinding) != 64 ||
		len(req.Consent.GrantID) != 32 || len(req.GenerationID) != len("sample_")+32 {
		return windowssessions.ErrInvalid
	}
	if _, err := windowssessions.EncodeConsent(req.Consent, req.SenderBinding); err != nil {
		return windowssessions.ErrInvalid
	}
	if !req.Consent.Enabled {
		return windowssessions.ErrDisabled
	}
	// The snapshot validator also validates the original generation and exact
	// UTC capture representation, without opening a source or allocating rows.
	return windowssessions.Validate(emptySnapshot(req, windowssessions.ErrUnavailable.Error()))
}

func encodeRequest(req windowssessions.Request) ([]byte, error) {
	if err := validateRequest(req); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(wireRequest{req.SenderBinding, req.Consent.GrantID, req.GenerationID, req.CollectedAt})
	if err != nil || len(raw) > maxRequestBytes {
		return nil, windowssessions.ErrInvalid
	}
	return raw, nil
}

func decodeRequest(raw []byte) (windowssessions.Request, error) {
	if len(raw) == 0 || len(raw) > maxRequestBytes || !utf8.Valid(raw) {
		return windowssessions.Request{}, windowssessions.ErrInvalid
	}
	var wire wireRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(new(any)) != io.EOF {
		return windowssessions.Request{}, windowssessions.ErrInvalid
	}
	req := windowssessions.Request{
		Consent: windowssessions.Consent{
			SchemaVersion: windowssessions.ConsentVersion, Scope: windowssessions.Scope,
			SenderBinding: wire.SenderBinding, GrantID: wire.GrantID, Enabled: true,
		},
		SenderBinding: wire.SenderBinding, GenerationID: wire.GenerationID, CollectedAt: wire.CollectedAt,
	}
	canonical, err := encodeRequest(req)
	if err != nil || !bytes.Equal(raw, canonical) {
		return windowssessions.Request{}, windowssessions.ErrInvalid
	}
	return req, nil
}

func sameRequest(a, b windowssessions.Request) bool {
	return validateRequest(b) == nil && a.Consent == b.Consent &&
		a.SenderBinding == b.SenderBinding && a.GenerationID == b.GenerationID &&
		a.CollectedAt.Equal(b.CollectedAt)
}
