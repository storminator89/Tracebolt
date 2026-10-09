package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"localrmm/internal/inventorystate"
	"localrmm/internal/inventorywire"
	"localrmm/internal/lanconfig"
	"net/http"
	"time"
)

// deliver sends one purpose-bound request, never a telemetry signature. Only
// the dedicated, strictly decoded state-conflict response permits a status
// query. Error bodies, headers and OS errors never leave this adapter.
func (s *inventorySender) deliver(ctx context.Context, w inventorystate.Work) ([]byte, bool, error) {
	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}
	if s.completeUpdates {
		if _, ok := readCompleteUpdatesConsent(s.material); !ok {
			return nil, false, errCompleteUpdatesDisabled
		}
	}
	decode, sign, receiptDecode, prefix := inventorywire.DecodeMessage, inventorywire.NewSignedRequest, inventorywire.DecodeReceipt, inventorywire.PathPrefix
	if s.completeUpdates {
		decode, sign, receiptDecode, prefix = inventorywire.DecodeCachedUpdatesMessage, inventorywire.NewCachedUpdatesSignedRequest, inventorywire.DecodeCachedUpdatesReceipt, inventorywire.CachedUpdatesPathPrefix
	}
	body := w.Body()
	if _, err := decode(w.Operation, body); err != nil {
		return nil, false, ErrState
	}
	var req *http.Request
	var err error
	m := s.material
	if m.config.Profile == "http-test" {
		req, err = sign(ctx, m.config.ManagerOrigin, m.certificate, w.Operation, w.Sequence, s.now().UTC(), body)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, m.config.ManagerOrigin+prefix+w.Operation, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if err != nil {
		return nil, false, ErrConfiguration
	}
	if s.completeUpdates {
		if _, ok := readCompleteUpdatesConsent(s.material); !ok {
			return nil, false, errCompleteUpdatesDisabled
		}
	}
	response, err := s.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, false, ErrInventoryTransport
	}
	defer response.Body.Close()
	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusConflict {
		return nil, false, ErrInventoryTransport
	}
	if len(response.Header.Values("Content-Encoding")) != 0 || len(response.Header.Values("Content-Type")) != 1 || (response.Header.Get("Content-Type") != "application/json" && response.Header.Get("Content-Type") != "application/json; charset=utf-8") {
		return nil, false, ErrInventoryReceipt
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, inventorywire.MaxReceiptBytes+1))
	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}
	if err != nil || len(raw) > inventorywire.MaxReceiptBytes {
		return nil, false, ErrInventoryReceipt
	}
	if response.StatusCode == http.StatusConflict {
		if !inventoryDomainConflictResponse(raw, s.completeUpdates) {
			return nil, false, ErrInventoryTransport
		}
		return nil, true, nil
	}
	receipt, err := receiptDecode(raw, w.Operation, body)
	if err != nil {
		return nil, false, ErrInventoryReceipt
	}
	// Expiry is intentionally excluded: it is a future deadline. Observed event
	// times must not be implausibly ahead, including on unauthenticated HTTP.
	latest := s.now().UTC().Add(30 * time.Second)
	for _, at := range []time.Time{receipt.StartedAt, receipt.ReceivedAt, receipt.CompletedAt, receipt.AttemptedAt, receipt.CollectedAt} {
		if at.After(latest) {
			return nil, false, ErrInventoryReceipt
		}
	}
	return raw, false, nil
}

func inventoryDomainConflictResponse(raw []byte, updates bool) bool {
	// StrictObject deliberately disallows nested values; decode precisely one
	// outer member here, then apply it to the fixed scalar error object.
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return false
	}
	key, err := d.Token()
	if err != nil || key != "error" {
		return false
	}
	var inner json.RawMessage
	if d.Decode(&inner) != nil || d.More() {
		return false
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return false
	}
	if _, err = d.Token(); err != io.EOF {
		return false
	}
	var conflict struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	code := "inventory_state_conflict"
	if updates {
		code = "cached_updates_state_conflict"
	}
	return lanconfig.StrictObject(inner, &conflict, "code", "message") == nil && conflict.Code == code && conflict.Message == "Agent telemetry could not be accepted."
}
