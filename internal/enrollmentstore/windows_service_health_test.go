package enrollmentstore

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowsmanaged"
)

// Service policy evidence is projected from the already accepted frame in the
// same bounded authority transaction as the independent percentage policies.
func TestWindowsServiceSourceRetainsOriginalSnapshotAndReceipt(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f, s, path, identity, cert := activeWindowsStore(t, profile)
			ctx := context.Background()
			captured := time.Unix(testNow+10, 0).UTC()
			metricTime := captured.Add(2 * time.Second)
			received := captured.Add(10 * time.Second)
			inputs, err := s.WindowsCapacityInputs(ctx, received)
			if err != nil || len(inputs) != 1 || !inputs[0].Services.CollectedAt.IsZero() || inputs[0].Services.Services.Rows != nil {
				t.Fatal("unobserved identity invented service metadata", err)
			}
			var frame lanstore.Frame
			if err = json.Unmarshal(windowsStoreFrame(t, 1, metricTime), &frame); err != nil {
				t.Fatal(err)
			}
			frame.WindowsInventory.CollectedAt = captured
			section := windowsmanaged.Section[windowsmanaged.Service]{Source: "Invented caller-visible SCM fixture", Scope: "Invented partial service scope", Quality: "partial", ObservedCount: 3, Rows: []windowsmanaged.Service{
				{Name: "Spooler", DisplayName: "Invented spooler", State: "stopped"},
				{Name: "Duplicate", DisplayName: "Invented duplicate one", State: "running"},
				{Name: "Duplicate", DisplayName: "Invented duplicate two", State: "stopped"},
			}}
			frame.WindowsInventory.Services = section
			raw, err := json.Marshal(frame)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = lanstore.ValidateFrame(raw, received); err != nil {
				t.Fatal("existing Windows frame rejected service fixture", err)
			}
			first, err := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), raw, received)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			s = f.open(t, path)
			retryAt := received.Add(3 * time.Minute)
			retry, err := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), raw, retryAt)
			if err != nil || !retry.Duplicate || !retry.ReceivedAt.Equal(first.ReceivedAt) {
				t.Fatal("exact retry changed service receipt", err)
			}
			var before, after int64
			if err = s.db.QueryRowContext(ctx, "SELECT total_changes()").Scan(&before); err != nil {
				t.Fatal(err)
			}
			for _, at := range []time.Time{retryAt, retryAt.Add(time.Second)} {
				inputs, err = s.WindowsCapacityInputs(ctx, at)
				if err != nil || len(inputs) != 1 {
					t.Fatal("service source read failed", err)
				}
				in := inputs[0]
				if !in.Authorized || in.InvitationID != identity.InvitationID || in.CertificateHash != cert.CertificateHash() || in.Sequence != first.Sequence || !in.ReceivedAt.Equal(received) || !in.Services.CollectedAt.Equal(captured) || !in.CPU.CollectedAt.Equal(metricTime) || !reflect.DeepEqual(in.Services.Services, section) {
					t.Fatal("source substituted receipt/metric time, filtered ambiguous rows or changed service provenance")
				}
			}
			if err = s.db.QueryRowContext(ctx, "SELECT total_changes()").Scan(&after); err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Fatal("service source read mutated enrollment state")
			}
			ctl := control(identity, 20)
			ctl.Now = retryAt.Add(2 * time.Second).Unix()
			if _, err = s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: ctl, State: enrollmentstate.Revoked}); err != nil {
				t.Fatal(err)
			}
			inputs, err = s.WindowsCapacityInputs(ctx, time.Unix(ctl.Now, 0).UTC())
			if err != nil || len(inputs) != 1 || inputs[0].Authorized || inputs[0].Sequence != 0 || !inputs[0].ReceivedAt.IsZero() || !inputs[0].Services.CollectedAt.IsZero() || inputs[0].Services.Services.Rows != nil {
				t.Fatal("authority loss disclosed retained service metadata", err)
			}
		})
	}
}
