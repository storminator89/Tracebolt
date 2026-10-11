package api

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"localrmm/internal/bundle"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var updateWindowsFleetIdentityVectors = flag.Bool("update-windows-fleet-identity-vectors", false, "Export synthetic production HTTP fleet-identity responses for frontend contract tests")

func TestFleetIdentitiesOperatorGuards(t *testing.T) {
	o := newOperatorFixture(t, time.Minute)
	path := "/api/fleet/identities"
	response, _ := o.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("anonymous v2 fleet metadata exposed")
	}
	o.login(t)
	response, value := o.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != http.StatusOK || value["schemaVersion"] != "tracebolt.fleet-identities.v2" || len(value["items"].([]any)) != 0 {
		t.Fatal("unconfigured v2 response", response.StatusCode, value)
	}
	for _, tc := range []struct {
		method, path string
		change       func(*http.Request)
		want         int
	}{
		{"POST", path, nil, 405}, {"GET", path + "?device=host", nil, 400}, {"GET", path + "?", nil, 400},
		{"GET", path, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }, 403},
		{"GET", path, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
	} {
		response, _ = o.call(t, tc.method, tc.path, nil, "", tc.change)
		if response.StatusCode != tc.want || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("v2 fleet guard %s %s: status %d", tc.method, tc.path, response.StatusCode)
		}
	}
}

func windowsFleetIdentityHTTPFrame(t *testing.T, sequence uint64, at time.Time, partial bool) ([]byte, windowsmanaged.Snapshot) {
	t.Helper()
	value := 42.0
	metric := model.Metric{Value: &value, Unit: "%", Quality: "healthy", Source: "Synthetic fixture", CollectedAt: at}
	report := windowsinventory.Report{Schema: windowsinventory.Schema, Platform: "windows", CollectedAt: at, OS: "Synthetic Windows", Uptime: "fixture", CPU: metric, Memory: metric, Disk: metric,
		Hostname:  windowsinventory.Section[windowsinventory.Hostname]{Source: "Synthetic GetComputerNameExW", Scope: "Caller-visible computer name", Quality: "healthy", Complete: true, Rows: []windowsinventory.Hostname{{Value: "synthetic-<fleet>&host"}}},
		Processes: windowsinventory.Section[windowsinventory.Process]{Source: "Synthetic process API", Scope: "Caller-visible processes", Quality: "healthy", Complete: true, Rows: []windowsinventory.Process{{PID: 12, Name: "private-process.exe", Threads: 2}}},
		Services:  windowsinventory.Section[windowsinventory.Service]{Source: "Synthetic service API", Scope: "Caller-visible services", Quality: "denied", Rows: []windowsinventory.Service{}},
		Software:  windowsinventory.Section[windowsinventory.Software]{Source: "Synthetic registry API", Scope: "Caller-visible software", Quality: "limited", Rows: []windowsinventory.Software{{Name: "Private fixture software", Version: "1", Publisher: "Fixture", RegistryView: "64"}}},
		Network:   windowsinventory.Section[windowsinventory.InterfaceAddress]{Source: "Synthetic GetAdaptersAddresses", Scope: "Caller-visible interface addresses; no sockets or traffic", Quality: "healthy", Complete: true, Rows: []windowsinventory.InterfaceAddress{{Index: 7, Name: "Fixture Ethernet", Address: "192.0.2.8", PrefixLength: 24}, {Index: 7, Name: "Fixture Ethernet", Address: "2001:db8::8", PrefixLength: 64}}},
	}
	if partial {
		report.Hostname.Quality, report.Hostname.Complete, report.Hostname.Rows = "unknown", false, []windowsinventory.Hostname{}
		report.Network.Quality, report.Network.Complete = "limited", false
	}
	snapshot, device, err := windowsmanaged.FromReport(report, fmt.Sprintf("sample_%032x", sequence))
	if err != nil {
		t.Fatal(err)
	}
	observation := bundle.Bundle{SchemaVersion: bundle.SchemaVersion, Product: "Tracebolt", Version: "synthetic-fleet-fixture", GeneratedAt: at, Platform: "windows", Architecture: "amd64", Scope: "single-read-only-local-observation", Privacy: []string{}, Observation: device}
	raw, err := json.Marshal(lanstore.Frame{SchemaVersion: lanstore.FrameWindowsInventoryVersion, Sequence: sequence, Observation: observation, WindowsInventory: &snapshot})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = lanstore.ValidateFrame(raw, at); err != nil {
		t.Fatal(err)
	}
	return raw, snapshot
}

func windowsFleetHTTPRead(t *testing.T, f windowsEventOperatorFixture) (json.RawMessage, map[string]any) {
	t.Helper()
	response, err := f.client.Get(f.server.URL + "/api/fleet/identities")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || len(raw) >= fleetIdentitiesResponseBytes {
		t.Fatal("production Windows fleet route", response.StatusCode, err)
	}
	var view map[string]any
	if err = json.Unmarshal(raw, &view); err != nil || view["schemaVersion"] != "tracebolt.fleet-identities.v2" || len(view["items"].([]any)) != 1 {
		t.Fatal("dual-authority route omitted Windows identity", err)
	}
	item := view["items"].([]any)[0].(map[string]any)
	if item["schemaVersion"] != "tracebolt.windows-fleet-identity-view.v1" || item["deviceId"] != f.snap.Approval.DeviceID || item["collectionProfile"] != windowsmanaged.CollectionProfile {
		t.Fatal("route relabeled Windows identity")
	}
	for _, forbidden := range []string{"private-process.exe", "Private fixture software", `"processes"`, `"services"`, `"software"`, `"windowsNetwork"`, windowsEventOperatorMessage} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("private nonidentity field escaped production route")
		}
	}
	return raw, item
}

func TestFleetIdentitiesWindowsHTTPProjectionAndVectors(t *testing.T) {
	// Real TLS operator login, dual Linux/Windows authorities, durable frame
	// ingestion and registered production route. All observations are synthetic.
	f := newWindowsEventOperatorFixtureWithIssuerLifetime(t, false, 2*time.Hour)
	vectors := map[string]json.RawMessage{}
	captured := f.at.Add(time.Second)
	raw, original := windowsFleetIdentityHTTPFrame(t, 2, captured, false)
	if _, err := f.store.SaveObservation(context.Background(), f.snap.InvitationID, f.snap.Issuance.CertificateHash, raw, captured); err != nil {
		t.Fatal(err)
	}
	f.clock.set(captured)
	fresh, item := windowsFleetHTTPRead(t, f)
	vectors["fresh"] = fresh
	latest := item["latest"].(map[string]any)
	if item["status"] != "fresh" || item["sequence"] != "2" || latest["generationId"] != original.GenerationID || len(latest) != 6 || latest["hostname"].(map[string]any)["rows"].([]any)[0].(map[string]any)["value"] != "synthetic-<fleet>&host" {
		t.Fatal("HTTP projection changed original metadata")
	}
	response, legacy := f.call(t, "GET", "/api/fleet/endpoint-identities", nil, "", nil)
	if response.StatusCode != http.StatusOK || legacy["schemaVersion"] != "tracebolt.fleet-endpoint-identity.v1" || len(legacy["items"].([]any)) != 0 {
		t.Fatal("Windows scope changed Linux v1 endpoint")
	}
	captured = captured.Add(time.Second)
	raw, original = windowsFleetIdentityHTTPFrame(t, 3, captured, true)
	receipt, err := f.store.SaveObservation(context.Background(), f.snap.InvitationID, f.snap.Issuance.CertificateHash, raw, captured)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.set(captured)
	partial, item := windowsFleetHTTPRead(t, f)
	vectors["partial"] = partial
	latest = item["latest"].(map[string]any)
	expected, _ := json.Marshal(struct {
		Hostname windowsmanaged.Section[windowsmanaged.Hostname]         `json:"hostname"`
		Network  windowsmanaged.Section[windowsmanaged.InterfaceAddress] `json:"network"`
	}{original.Hostname, original.Network})
	var sections map[string]any
	if err = json.Unmarshal(expected, &sections); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(latest["hostname"], sections["hostname"]) || !reflect.DeepEqual(latest["network"], sections["network"]) {
		t.Fatal("HTTP upgraded unavailable/partial section completeness")
	}
	f.clock.set(captured.Add(121 * time.Second))
	duplicate, err := f.store.SaveObservation(context.Background(), f.snap.InvitationID, f.snap.Issuance.CertificateHash, raw, f.clock.now())
	if err != nil || !duplicate.Duplicate || !duplicate.ReceivedAt.Equal(receipt.ReceivedAt) {
		t.Fatal("HTTP source duplicate refreshed receipt", err)
	}
	stale, item := windowsFleetHTTPRead(t, f)
	vectors["stale"] = stale
	if item["status"] != "stale" || item["sequence"] != "3" || item["receivedAt"] != receipt.ReceivedAt.Format(time.RFC3339Nano) || item["latest"].(map[string]any)["collectedAt"] != captured.Format(time.RFC3339Nano) {
		t.Fatal("retry refreshed HTTP identity freshness")
	}
	if _, err = f.service.Terminate(context.Background(), f.snap.InvitationID, "request_"+strings.Repeat("9", 32), f.snap.Revision, enrollmentstate.Revoked); err != nil {
		t.Fatal(err)
	}
	revoked, item := windowsFleetHTTPRead(t, f)
	vectors["revoked"] = revoked
	if item["status"] != "revoked" || item["latest"] != nil || item["sequence"] != nil {
		t.Fatal("revoked HTTP identity escaped")
	}
	expiry := newWindowsEventOperatorFixtureWithIssuerLifetime(t, false, 2*time.Hour)
	expiry.clock.set(time.Unix(expiry.snap.Intent.NotAfter, 0).UTC())
	expired, item := windowsFleetHTTPRead(t, expiry)
	vectors["expired"] = expired
	if item["status"] != "expired" || item["latest"] != nil {
		t.Fatal("authority-expired HTTP identity escaped")
	}
	if *updateWindowsFleetIdentityVectors {
		// Preserve production response fields verbatim, including synthetic IDs and
		// capture/receipt/authority times. This is fixture evidence, never host data.
		encoded, err := json.MarshalIndent(vectors, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join("..", "..", "web", "src", "windows-fleet-identity-vectors.json")
		if err = os.WriteFile(path, append(encoded, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFleetIdentitiesV2ResponseCapIncludesNewline(t *testing.T) {
	h := operatorHandler{app: setup(t)}
	for _, size := range []int{fleetIdentitiesResponseBytes - 4, fleetIdentitiesResponseBytes - 3} {
		r := httptest.NewRequest("GET", "/api/fleet/identities", nil)
		r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{active: func() bool { return true }}))
		w := httptest.NewRecorder()
		h.writeFleetIdentityBytes(w, r, strings.Repeat("x", size), fleetIdentitiesResponseBytes, nil)
		if size == fleetIdentitiesResponseBytes-4 {
			if w.Code != http.StatusOK || w.Body.Len() != fleetIdentitiesResponseBytes-1 {
				t.Fatal("v2 bounded exact-byte response", w.Code, w.Body.Len())
			}
		} else if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), strings.Repeat("x", 32)) {
			t.Fatal("v2 wire ceiling accepted", w.Code, w.Body.Len())
		}
	}
}

func TestFleetIdentitiesWindowsFinalOutputAuthoritySessionAndCancellation(t *testing.T) {
	for _, crossing := range []string{"expiry", "session_revoked", "cancel"} {
		t.Run(crossing, func(t *testing.T) {
			f := newWindowsEventOperatorFixtureWithIssuerLifetime(t, false, 2*time.Hour)
			h, ok := f.server.Config.Handler.(*operatorHandler)
			if !ok {
				t.Fatal("unexpected production handler")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			active := true
			request := func() *http.Request {
				r := httptest.NewRequest("GET", "/api/fleet/identities", nil)
				return r.WithContext(context.WithValue(ctx, operatorRequestKey{}, operatorRequest{active: func() bool { return active }}))
			}
			f.clock.arm(nil)
			baseline := httptest.NewRecorder()
			h.fleetIdentities(baseline, request())
			finalClock := f.clock.count()
			if baseline.Code != http.StatusOK || finalClock < 5 || !bytes.Contains(baseline.Body.Bytes(), []byte("fixture-windows")) {
				t.Fatal("Windows authority output fixture", baseline.Code, finalClock)
			}
			f.clock.arm(func(n int) {
				if n != finalClock {
					return
				}
				switch crossing {
				case "expiry":
					f.clock.set(time.Unix(f.snap.Intent.NotAfter, 0).UTC())
				case "session_revoked":
					active = false
				case "cancel":
					cancel()
				}
			})
			result := httptest.NewRecorder()
			h.fleetIdentities(result, request())
			want := http.StatusUnauthorized
			if crossing == "expiry" {
				want = http.StatusConflict
			}
			if result.Code != want || bytes.Contains(result.Body.Bytes(), []byte("fixture-windows")) || bytes.Contains(result.Body.Bytes(), []byte(f.snap.Approval.DeviceID)) {
				t.Fatal("encoded Windows identity escaped final authority/session boundary", result.Code)
			}
		})
	}
}
