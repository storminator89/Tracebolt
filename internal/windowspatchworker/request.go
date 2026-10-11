package windowspatchworker

import (
	"bytes"
	"encoding/json"
	"io"
	"time"
	"unicode/utf8"

	"localrmm/internal/windowspatchcontext"
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

func validateRequest(req windowspatchcontext.Request) error {
	// Reject overlong strings before any serialization allocates a wire copy.
	if req.Consent.SchemaVersion != windowspatchcontext.ConsentVersion || req.Consent.Scope != windowspatchcontext.Scope ||
		len(req.SenderBinding) != 64 || len(req.Consent.SenderBinding) != 64 ||
		len(req.Consent.GrantID) != 32 || len(req.GenerationID) != len("sample_")+32 {
		return windowspatchcontext.ErrInvalid
	}
	if _, err := windowspatchcontext.EncodeConsent(req.Consent, req.SenderBinding); err != nil {
		return windowspatchcontext.ErrInvalid
	}
	if !req.Consent.Enabled {
		return windowspatchcontext.ErrDisabled
	}
	// The snapshot validator also validates the original generation and exact
	// UTC capture representation, without opening a source or allocating rows.
	return windowspatchcontext.Validate(emptySnapshot(req, windowspatchcontext.ErrUnavailable.Error()))
}

func encodeRequest(req windowspatchcontext.Request) ([]byte, error) {
	if err := validateRequest(req); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(wireRequest{req.SenderBinding, req.Consent.GrantID, req.GenerationID, req.CollectedAt})
	if err != nil || len(raw) > maxRequestBytes {
		return nil, windowspatchcontext.ErrInvalid
	}
	return raw, nil
}

func decodeRequest(raw []byte) (windowspatchcontext.Request, error) {
	if len(raw) == 0 || len(raw) > maxRequestBytes || !utf8.Valid(raw) {
		return windowspatchcontext.Request{}, windowspatchcontext.ErrInvalid
	}
	var wire wireRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(new(any)) != io.EOF {
		return windowspatchcontext.Request{}, windowspatchcontext.ErrInvalid
	}
	req := windowspatchcontext.Request{
		Consent: windowspatchcontext.Consent{
			SchemaVersion: windowspatchcontext.ConsentVersion, Scope: windowspatchcontext.Scope,
			SenderBinding: wire.SenderBinding, GrantID: wire.GrantID, Enabled: true,
		},
		SenderBinding: wire.SenderBinding, GenerationID: wire.GenerationID, CollectedAt: wire.CollectedAt,
	}
	canonical, err := encodeRequest(req)
	if err != nil || !bytes.Equal(raw, canonical) {
		return windowspatchcontext.Request{}, windowspatchcontext.ErrInvalid
	}
	return req, nil
}

func sameRequest(a, b windowspatchcontext.Request) bool {
	return validateRequest(b) == nil && a.Consent == b.Consent &&
		a.SenderBinding == b.SenderBinding && a.GenerationID == b.GenerationID &&
		a.CollectedAt.Equal(b.CollectedAt)
}
