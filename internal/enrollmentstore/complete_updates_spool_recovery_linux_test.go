//go:build linux

package enrollmentstore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/inventoryledger"
	"localrmm/internal/inventorystate"
	"localrmm/internal/inventorywire"
)

// A refused first Begin has no Begin ACK. The real spool must authenticate the
// failed status, request a genuine abort and durably retire before recapture.
func TestCompleteUpdatesStaleRefusalRetiresRealLocalSpool(t *testing.T) {
	_, s, _, snap, cert := completeUpdatesFixture(t)
	now := time.Unix(testNow+10, 0).UTC()
	captured := now.Add(-inventoryledger.ObservationTTL - time.Minute)
	spool, err := inventorystate.InitializeCachedUpdatesNew(filepath.Join(t.TempDir(), "spool"), strings.Repeat("1", 64), snap.Approval.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	a, err := spool.Allocate(context.Background(), captured)
	if err != nil {
		t.Fatal(err)
	}
	b, m, chunks := updatesGenerationFixture(t, snap.Approval.DeviceID, a.Sequence, 20, captured)
	mr, _ := json.Marshal(m)
	cr := make([][]byte, len(chunks))
	for i, c := range chunks {
		cr[i], _ = json.Marshal(c)
	}
	if err := spool.Stage(context.Background(), a, mr, cr); err != nil {
		t.Fatal(err)
	}
	begin, ok, err := spool.NextWork()
	if err != nil || !ok || begin.Operation != "begin" {
		t.Fatal("no pending begin", err)
	}
	if _, err = s.CompleteUpdatesBegin(context.Background(), snap.InvitationID, cert.CertificateHash(), b, m, now); err != inventoryledger.ErrConflict {
		t.Fatal("not committed terminal refusal", err)
	}
	status, err := s.CompleteUpdatesStatus(context.Background(), snap.InvitationID, cert.CertificateHash(), b, now)
	if err != nil {
		t.Fatal(err)
	}
	work, err := spool.StatusWork()
	if err != nil {
		t.Fatal(err)
	}
	encodeReceipt := func(w inventorystate.Work, result any) []byte {
		sum := sha256.Sum256(w.Body())
		raw, e := json.Marshal(map[string]any{"schemaVersion": inventorywire.CachedUpdatesReceiptVersion, "operation": w.Operation, "sequence": fmt.Sprint(w.Sequence), "generationId": w.GenerationID, "manifestHash": w.ManifestHash, "requestSha256": fmt.Sprintf("%x", sum), "result": result})
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	x := status.Transfer
	sr := encodeReceipt(work, map[string]any{"state": x.State, "acceptedChunks": x.AcceptedChunks, "expectedChunks": x.Manifest.ChunkCount, "acceptedRows": x.AcceptedRows, "startedAt": x.StartedAt, "expiresAt": x.ExpiresAt, "completedAt": ""})
	if _, err := spool.ValidateStatus(work, sr); err != nil {
		t.Fatal("shared spool rejects stale refusal status", err)
	}
	if err := spool.RequestAbortAfterStatus(work, sr); err != nil {
		t.Fatal(err)
	}
	abort, ok, err := spool.NextWork()
	if err != nil || !ok || abort.Operation != "abort" {
		t.Fatal("no genuine abort work", err)
	}
	if err := s.CompleteUpdatesAbort(context.Background(), snap.InvitationID, cert.CertificateHash(), b, now); err != nil {
		t.Fatal(err)
	}
	if err := spool.Acknowledge(abort, encodeReceipt(abort, map[string]any{"aborted": true})); err != nil {
		t.Fatal("shared spool rejects real abort ACK", err)
	}
	if _, pending, err := spool.NextWork(); err != nil || pending {
		t.Fatal("local stale pending did not retire", err)
	}
	next, err := spool.Allocate(context.Background(), now)
	if err != nil || next.Sequence != a.Sequence+1 {
		t.Fatal("next capture cannot advance preserved floor", err)
	}
}
