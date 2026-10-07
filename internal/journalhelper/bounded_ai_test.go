package journalhelper

import (
	"bytes"
	"context"
	"encoding/json"
	"localrmm/internal/journalview"
	"testing"
	"time"
)

// Synthetic transport and provider only: no socket, helper installation or
// native journal is needed to establish the v4-to-TBJ2 compatibility contract.
func TestV4HelperKeepsBoundedAICaptureOnTBJ2(t *testing.T) {
	for _, minutes := range []int{5, 15} {
		t.Run(time.Duration(minutes).String(), func(t *testing.T) {
			state := browseState()
			d := fixtureDependencies()
			d.Load = func() (State, error) { return state, nil }
			q := generationRequest()
			q.PolicyGeneration = state.PolicyGeneration
			q.Query.End = d.Now().UTC().Truncate(time.Microsecond)
			q.Query.Start = q.Query.End.Add(-time.Duration(minutes) * time.Minute)
			q.Query.MaxPriority = 4
			raw, err := EncodeRequest(q)
			if err != nil || string(raw[:4]) != "TBJ2" {
				t.Fatal("bounded capture uses retained protocol", err)
			}
			parsed, err := readRequest(bytes.NewReader(raw))
			if err != nil || parsed != q {
				t.Fatal("bounded request changed", err)
			}
			calls := 0
			d.Capture = func(ctx context.Context, query journalview.Query, now time.Time) (journalview.Snapshot, error) {
				calls++
				if query != q.Query {
					t.Fatal("expanded source query")
				}
				return journalview.Parse(ctx, query, now, bytes.NewReader(nil))
			}
			srv, err := New(d)
			if err != nil {
				t.Fatal(err)
			}
			result, err := exchange(t, srv, context.Background(), q)
			if err != nil || result.Status != StatusSnapshot || calls != 1 {
				t.Fatal("v4 bounded capture rejected", err, result.Status)
			}
			var snapshot journalview.Snapshot
			err = json.Unmarshal(result.Body(), &snapshot)
			if err != nil || snapshot.SchemaVersion != journalview.SchemaVersion || snapshot.NextCursor != "" || snapshot.Exhausted {
				t.Fatal("retained metadata in bounded result", err)
			}
			state.Policy.Enabled = false
			q.Operation, q.PolicyDigest, q.Revision = VerifyOperation, result.PolicyDigest, result.Revision
			result, err = exchange(t, srv, context.Background(), q)
			if err != nil || result.Status != StatusDenied || len(result.Body()) != 0 || calls != 1 {
				t.Fatal("revoked bounded capture released", err)
			}
		})
	}
}
