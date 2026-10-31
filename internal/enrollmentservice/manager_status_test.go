package enrollmentservice

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/managerstatus"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManagerStatusIssuerBoundariesAndAggregateWorkPrivacy(t *testing.T) {
	f := newFixture(t, "tls")
	if f.service.IssuerStatus(context.Background()).State != managerstatus.OK {
		t.Fatal("valid issuer not ready")
	}
	f.now = f.service.issuerStart
	if f.service.IssuerStatus(context.Background()).State != managerstatus.OK {
		t.Fatal("issuer NotBefore boundary rejected")
	}
	f.now = f.service.issuerStart.Add(-time.Nanosecond)
	if f.service.IssuerStatus(context.Background()).State != managerstatus.Invalid {
		t.Fatal("issuer before validity reported ready")
	}
	f.now = f.service.issuerExpiry
	if f.service.IssuerStatus(context.Background()).State != managerstatus.Expired {
		t.Fatal("expired issuer reported ready")
	}
	f.now = f.service.issuerStart.Add(time.Second)
	f.service.signing <- struct{}{}
	f.service.proofs <- struct{}{}
	view := f.service.ManagerStatus(context.Background())
	if view.State != managerstatus.OK || view.Work == nil || view.Work.Used != 2 || view.Work.Limit != 3 || view.Work.RetainedLimit != MaxChallenges || view.Capacity.Limit != MaxRecords {
		t.Fatal("bounded service work/status missing")
	}
	<-f.service.signing
	<-f.service.proofs
	raw, _ := json.Marshal(view)
	for _, secret := range []string{f.path, f.service.Binding().InstanceID, f.issuer.Fingerprint(), "Disposable", "private-source-error-sentinel"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("manager aggregate leaked identity or material")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if f.service.IssuerStatus(ctx).State != managerstatus.Timeout {
		t.Fatal("canceled issuer read admitted")
	}
}

func TestManagerStatusMacOSMaintenanceObservesActualBoundedSteps(t *testing.T) {
	base := time.Now().UTC()
	ticks := make(chan time.Time, 2)
	ticks <- base
	ticks <- base
	close(ticks)
	starts, completions, warnings := 0, 0, 0
	var outcomes []error
	err := macOSInventoryMaintenanceLoop(context.Background(), func(ctx context.Context, at time.Time) error {
		if !at.Equal(base) {
			t.Fatal("untrusted tick timestamp used")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 500*time.Millisecond {
			t.Fatal("maintenance step unbounded")
		}
		if starts == 1 {
			return errors.New("private-error-not-logged")
		}
		return nil
	}, func() time.Time { return base }, ticks, func() { warnings++ }, MaintenanceObserver{Started: func() { starts++ }, Completed: func(err error) { completions++; outcomes = append(outcomes, err) }})
	if err != nil || starts != 2 || completions != 2 || warnings != 1 || outcomes[0] == nil || outcomes[1] != nil {
		t.Fatal("step observation inferred health from warning silence")
	}
}

func TestManagerStatusLinuxMaintenanceObservesActualStoreStep(t *testing.T) {
	f := newFixture(t, "tls")
	cfg := f.config
	cfg.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileComplete
	s, err := enrollmentstore.Open(filepath.Join(t.TempDir(), "private", "complete.db"), cfg, f.issuer.IssuerDER())
	if err != nil {
		t.Fatal("complete store fixture failed")
	}
	defer s.Close()
	service, err := New(s, f.issuer, func() time.Time { return f.now })
	if err != nil {
		t.Fatal("complete service fixture failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	starts, completed := 0, 0
	var outcome error
	err = service.RunInventoryMaintenanceObserved(ctx, func() { t.Error("successful fixture warned") }, MaintenanceObserver{Started: func() { starts++ }, Completed: func(err error) { completed++; outcome = err; cancel() }})
	if err != nil || starts != 1 || completed != 1 || outcome != nil {
		t.Fatal("actual bounded store maintenance step not observed")
	}
}
