package native

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func inventedSender(sequence uint64, body string) []byte {
	r := senderObservation{Version: 1, Binding: strings.Repeat("a", 64), LastSequence: sequence}
	if body != "" {
		hash := sha256.Sum256([]byte(body))
		r.Pending = &pendingObservation{Sequence: sequence, Digest: hex.EncodeToString(hash[:]), Body: []byte(body)}
	}
	b, _ := json.Marshal(r)
	return b
}
func TestRetainedOutageObservationNeedsSameExactBytesAndSequence(t *testing.T) {
	first, present, retained, err := observeSender(senderContinuity{}, inventedSender(3, "invented fixture observation"))
	if err != nil || !present || retained {
		t.Fatal("first pending observation fabricated retention")
	}
	second, present, retained, err := observeSender(first, inventedSender(3, "invented fixture observation"))
	if err != nil || !present || !retained || second.floor != 3 {
		t.Fatal("exact retry retention missing")
	}
	if _, _, _, err = observeSender(first, inventedSender(3, "changed fixture observation")); err == nil {
		t.Fatal("changed bytes at consumed sequence accepted")
	}
	if _, _, retained, err = observeSender(first, inventedSender(4, "different next fixture")); err != nil || retained {
		t.Fatal("new sequence mislabeled exact retry")
	}
	if _, present, retained, err = observeSender(first, inventedSender(3, "")); err != nil || present || retained {
		t.Fatal("acknowledged request fabricated pending retention")
	}
}
func TestSenderCounterAndIdentityCannotMoveBackwards(t *testing.T) {
	s, _, _, err := observeSender(senderContinuity{}, inventedSender(8, ""))
	if err != nil {
		t.Fatal("fixture failed")
	}
	for _, raw := range [][]byte{inventedSender(7, ""), []byte(strings.ReplaceAll(string(inventedSender(8, "")), strings.Repeat("a", 64), strings.Repeat("b", 64))), inventedSender(0, "")} {
		if _, _, _, err = observeSender(s, raw); err == nil {
			t.Fatal("counter or binding regression accepted")
		}
	}
}
func TestPendingDigestAndCanonicalShapeFailClosed(t *testing.T) {
	valid := string(inventedSender(2, "fixture"))
	for _, raw := range []string{valid + " ", strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1), strings.Replace(valid, `"version":1`, `"version":null`, 1), strings.Replace(valid, `"sequence":2`, `"sequence":1`, 1), strings.Replace(valid, `"body":`, `"unknown":true,"body":`, 1), strings.Replace(valid, `"digest":"`, `"digest":"ff`, 1)} {
		if _, _, _, err := observeSender(senderContinuity{}, []byte(raw)); err == nil {
			t.Fatal("invalid fixture record admitted")
		}
	}
}
