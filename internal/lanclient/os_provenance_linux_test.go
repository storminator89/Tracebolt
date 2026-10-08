//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"localrmm/internal/analysis"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/signedhttp"
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
)

// Injected report -> production sender/ingress -> durable manager -> operator
// Device projection. No actual Windows source or network listener is invoked.
func TestWindowsOSProvenanceManagerRetryRestartQualityAndAge(t *testing.T) {
	f := newWindowsManagerFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows")
	ctx := context.Background()
	state, err := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = state.Close() }()
	var reports []windowsinventory.Report
	collect := func(_ context.Context, id string) (windowsmanaged.Snapshot, model.Device, error) {
		quality := "healthy"
		if len(reports) > 0 {
			quality = "denied"
		}
		r := osProvenanceReport(time.Now().UTC(), quality)
		reports = append(reports, r)
		return windowsmanaged.FromReport(r, id)
	}
	var bodies [][]byte
	var signatures []string
	send := func(r *http.Request) (*http.Response, error) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		bodies = append(bodies, bytes.Clone(raw))
		signatures = append(signatures, r.Header.Get(signedhttp.SignatureHeader))
		r.Body = io.NopCloser(bytes.NewReader(raw))
		response := f.serve(t, r, http.StatusOK)
		if len(bodies) == 1 {
			_ = response.Body.Close()
			return nil, errors.New("injected lost response")
		}
		return response, nil
	}
	first, err := runUsingStateWithDependencies(ctx, f.material, state, nil, nil, nil, collect, send)
	if !errors.Is(err, ErrTransport) || first.Sequence != 1 || len(reports) != 1 {
		t.Fatal("fixture did not leave accepted pending evidence", err)
	}
	assertProjection := func(want model.Evidence, now time.Time) {
		t.Helper()
		service, err := enrollmentservice.New(f.store, f.issuer, nil)
		if err != nil {
			t.Fatal(err)
		}
		devices, err := service.Devices(ctx, now)
		if err != nil || len(devices) != 1 {
			t.Fatal("operator device missing", err)
		}
		d := devices[0]
		if d.ID != f.identity.Approval.DeviceID || d.Source != "lan" || d.Status != "unknown" || len(d.CaseIDs) != 0 || len(d.Evidence) != 4 || d.Evidence[0] != want {
			t.Fatal("OS evidence changed identity, quality, age or device health")
		}
		assertWindowsHealthProjection(t, d, f.identity, now)
		// Use an otherwise-valid case and a passing basic-profile control so
		// this assertion isolates the existing Windows AI-profile boundary.
		c := model.Case{ID: "case-os-fixture", Title: "Injected OS observation", Summary: "Source preservation fixture only", Category: "system", RuleID: "fixture.os", RunbookID: "fixture", CreatedAt: want.CollectedAt, UpdatedAt: want.CollectedAt, CollectionProfile: enrollmentcrypto.CollectionProfile, EvidenceIDs: []string{want.ID}, Evidence: []model.Evidence{want}}
		packet, err := analysis.BuildPacket(c, d.Evidence)
		if err != nil || len(packet.Evidence) != 1 || packet.Evidence[0] != want {
			t.Fatal("basic-profile control is not a valid evidence packet", err)
		}
		c.CollectionProfile = enrollmentcrypto.CollectionProfileWindowsInventory
		if _, err := analysis.BuildPacket(c, d.Evidence); !errors.Is(err, analysis.ErrInvalidPacket) {
			t.Fatal("Windows profile gained AI export authority")
		}
	}
	original := *reports[0].OSEvidence
	assertProjection(original, time.Now().UTC())
	before := f.view(t, time.Now().UTC())
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	f.open(t)
	state, err = lanclientstate.OpenExisting(f.material.config.StateDirectory, f.material.binding)
	if err != nil {
		t.Fatal(err)
	}
	second, err := runUsingStateWithDependencies(ctx, f.material, state, nil, nil, nil, collect, send)
	if err != nil || !second.RetriedPending || !second.Duplicate || len(reports) != 1 || !bytes.Equal(bodies[0], bodies[1]) || signatures[0] != signatures[1] {
		t.Fatal("restart recollected or rewrote OS evidence", err)
	}
	after := f.view(t, time.Now().UTC())
	if before.ReceivedAt == nil || after.ReceivedAt == nil || !before.ReceivedAt.Equal(*after.ReceivedAt) {
		t.Fatal("retry refreshed receipt")
	}
	assertProjection(original, time.Now().UTC())
	stale := original
	stale.Quality = "stale"
	assertProjection(stale, after.ReceivedAt.Add(lanstore.SampleMaxAge+time.Second))
	expired := f.view(t, reports[0].CollectedAt.Add(24*time.Hour))
	if expired.Snapshot != nil || expired.Status != "unavailable" {
		t.Fatal("inventory visibility expiry changed")
	}
	// A new failed observation replaces the old version evidence, without a
	// fallback to its prior successful value or an invented current timestamp.
	third, err := runUsingStateWithDependencies(ctx, f.material, state, nil, nil, nil, collect, send)
	if err != nil || third.Sequence != 2 || len(reports) != 2 {
		t.Fatal("new failed observation did not advance", err)
	}
	assertProjection(*reports[1].OSEvidence, time.Now().UTC())
	response := f.serve(t, f.request(t, signedhttp.WindowsPath, bodies[0]), http.StatusConflict)
	_ = response.Body.Close()
	assertProjection(*reports[1].OSEvidence, time.Now().UTC())
}
