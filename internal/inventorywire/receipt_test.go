package inventorywire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

func receiptFixture(t *testing.T, op string, request []byte, result any) []byte {
	t.Helper()
	m, e := DecodeMessage(op, request)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(request)
	raw, e := json.Marshal(map[string]any{"schemaVersion": ReceiptVersion, "operation": op, "sequence": strconv.FormatUint(m.Sequence, 10), "generationId": m.GenerationID, "manifestHash": m.ManifestHash, "requestSha256": hex.EncodeToString(h[:]), "result": result})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestCompleteReceiptAllPurposeExactBinding(t *testing.T) {
	hash, m, chunks := inventoryMessages(t)
	now := m.CollectedAt.Add(time.Minute)
	cases := []struct {
		op, hash        string
		payload, result any
	}{
		{"begin", hash, m, map[string]any{"startedAt": now, "expiresAt": now.Add(15 * time.Minute)}},
		{"append", hash, chunks[0], map[string]any{"ordinal": 0, "rows": 1, "receivedAt": now}},
		{"finalize", hash, struct{}{}, map[string]any{"collectedAt": m.CollectedAt, "completedAt": now}},
		{"abort", hash, struct{}{}, map[string]bool{"aborted": true}},
		{"status", hash, struct{}{}, map[string]any{"state": "pending", "acceptedChunks": 0, "expectedChunks": 1, "acceptedRows": 0, "startedAt": now, "expiresAt": now.Add(15 * time.Minute), "completedAt": ""}},
		{"failure", "", map[string]any{"attemptedAt": m.CollectedAt, "reason": "source_missing"}, map[string]any{"attemptedAt": m.CollectedAt, "receivedAt": now, "reason": "source_missing"}},
	}
	for _, tc := range cases {
		t.Run(tc.op, func(t *testing.T) {
			request, e := EncodeMessage(tc.op, 1, m.GenerationID, tc.hash, tc.payload)
			if e != nil {
				t.Fatal(e)
			}
			raw := receiptFixture(t, tc.op, request, tc.result)
			r, e := DecodeReceipt(raw, tc.op, request)
			if e != nil || r.Sequence != 1 {
				t.Fatal("valid receipt", e)
			}
			mutations := [][]byte{append(bytes.Clone(raw), []byte(`{}`)...), bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":1`), 1), bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":"1","sequence":"1"`), 1), bytes.Replace(raw, []byte(`"result":`), []byte(`"result":null,"extra":`), 1), bytes.Replace(raw, []byte(`"operation":"`+tc.op+`"`), []byte(`"operation":"other"`), 1)}
			for _, bad := range mutations {
				if _, e := DecodeReceipt(bad, tc.op, request); e == nil {
					t.Fatal("ambiguous receipt accepted")
				}
			}
			if _, e := DecodeReceipt(raw, tc.op, append([]byte(" "), request...)); e == nil {
				t.Fatal("receipt adopted for different exact request bytes")
			}
		})
	}
}
func TestCompleteReceiptRejectsSemanticMismatch(t *testing.T) {
	hash, m, chunks := inventoryMessages(t)
	now := m.CollectedAt.Add(time.Minute)
	req, _ := EncodeMessage("append", 1, m.GenerationID, hash, chunks[0])
	for _, result := range []any{map[string]any{"ordinal": 1, "rows": 1, "receivedAt": now}, map[string]any{"ordinal": 0, "rows": 0, "receivedAt": now}, map[string]any{"ordinal": 0, "rows": 1, "receivedAt": now.Format("2006-01-02T15:04:05-07:00")}, map[string]any{"ordinal": 0, "rows": 1, "receivedAt": nil}} {
		if _, e := DecodeReceipt(receiptFixture(t, "append", req, result), "append", req); e == nil {
			t.Fatal("invalid append receipt accepted")
		}
	}
	req, _ = EncodeMessage("status", 1, m.GenerationID, hash, struct{}{})
	base := func() map[string]any {
		return map[string]any{"state": "complete", "acceptedChunks": 1, "expectedChunks": 1, "acceptedRows": 1, "startedAt": now, "expiresAt": now.Add(time.Hour), "completedAt": now.Format(time.RFC3339Nano)}
	}
	for _, mutate := range []func(map[string]any){func(v map[string]any) { v["completedAt"] = "" }, func(v map[string]any) { v["acceptedChunks"] = 2 }, func(v map[string]any) { v["state"] = "unknown" }, func(v map[string]any) { v["state"] = "pending" }} {
		v := base()
		mutate(v)
		if _, e := DecodeReceipt(receiptFixture(t, "status", req, v), "status", req); e == nil {
			t.Fatal("invalid status receipt accepted")
		}
	}
}
