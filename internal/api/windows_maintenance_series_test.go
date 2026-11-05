package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func readMaintenanceSeries(t *testing.T, o operatorFixture) windowsMaintenanceSeriesView {
	t.Helper()
	r, value := o.call(t, "GET", maintenanceSeriesPath, nil, "", nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, value)
	}
	raw, _ := json.Marshal(value)
	var v windowsMaintenanceSeriesView
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("decode")
	}
	return v
}
func seriesReviewBody(key string, revision uint64, now time.Time, n int) map[string]any {
	dates := []map[string]string{}
	for i := 0; i < n; i++ {
		start := now.Add(time.Hour + time.Duration(i)*7*24*time.Hour)
		dates = append(dates, map[string]string{"startsAt": start.Format(time.RFC3339Nano), "endsAt": start.Add(time.Hour).Format(time.RFC3339Nano)})
	}
	return map[string]any{"key": key, "revision": revision, "intent": "planned-work", "occurrences": dates}
}
func seriesCommitBody(v map[string]any) map[string]any {
	return map[string]any{"reviewToken": v["reviewToken"], "operationId": v["operationId"], "acknowledged": true}
}
func TestWindowsMaintenanceSeriesAPIReviewCommitReceiptsAndExactSibling(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	m, f := installCapacityFixture(t, o)
	if r, _ := o.call(t, "GET", maintenanceSeriesPath, nil, "", nil); r.StatusCode != 401 {
		t.Fatal("anonymous")
	}
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	before := readMaintenance(t, o)
	view := readMaintenanceSeries(t, o)
	target := view.Targets[0]
	body := seriesReviewBody(target.Key, 0, f.now, 4)
	if r, _ := o.call(t, "POST", maintenanceSeriesPath+"/review", body, "", nil); r.StatusCode != 403 {
		t.Fatal("csrf")
	}
	r, review := o.call(t, "POST", maintenanceSeriesPath+"/review", body, csrf, nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, review)
	}
	state, err := m.store.WindowsMaintenanceSeries(context.Background(), m.source.Now)
	if err != nil || len(state) != 0 {
		t.Fatal("review wrote", err)
	}
	r, receipt := o.call(t, "POST", maintenanceSeriesPath+"/commit", seriesCommitBody(review), csrf, nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, receipt)
	}
	if receipt["action"] != "create" || receipt["revision"] != float64(1) || len(receipt["occurrenceIds"].([]any)) != 4 {
		t.Fatal(receipt)
	}
	if r, _ := o.call(t, "POST", maintenanceSeriesPath+"/commit", seriesCommitBody(review), csrf, nil); r.StatusCode != 409 {
		t.Fatal("replay")
	}
	r, retained := o.call(t, "GET", maintenanceSeriesPath+"/receipts/"+review["operationId"].(string), nil, "", nil)
	if r.StatusCode != 200 || !reflect.DeepEqual(receipt, retained) {
		t.Fatal("immutable receipt", r.StatusCode, retained)
	}
	if r, v := o.call(t, "GET", maintenanceSchedulePath, nil, "", nil); r.StatusCode != 409 || v["error"].(map[string]any)["code"] != "windows_maintenance_series_client_required" {
		t.Fatal("legacy truncated", r.StatusCode, v)
	}
	view = readMaintenanceSeries(t, o)
	if len(view.Targets[0].Occurrences) != 4 || view.Targets[0].RemainingSlots != 12 {
		t.Fatal(view)
	}
	r, cancel := o.call(t, "POST", maintenanceSeriesPath+"/cancel/review", map[string]any{"key": target.Key, "revision": 1, "occurrenceId": 2}, csrf, nil)
	if r.StatusCode != 200 || cancel["action"] != "cancel" || len(cancel["occurrences"].([]any)) != 1 {
		t.Fatal(r.StatusCode, cancel)
	}
	if r, v := o.call(t, "POST", maintenanceSeriesPath+"/commit", seriesCommitBody(cancel), csrf, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	view = readMaintenanceSeries(t, o)
	for _, w := range view.Targets[0].Occurrences {
		if (w.ID == 2) != (w.CancelledAt != nil) {
			t.Fatal("wrong sibling changed", w)
		}
	}
	if after := readMaintenance(t, o); !reflect.DeepEqual(before, after) {
		t.Fatal("legacy immediate DTO changed")
	}
	missing, _ := seriesOperationID(f.now)
	r, v := o.call(t, "GET", maintenanceSeriesPath+"/receipts/"+missing, nil, "", nil)
	if r.StatusCode != 200 || v["status"] != "unresolved" {
		t.Fatal("absence misrepresented", r.StatusCode, v)
	}
}
func TestWindowsMaintenanceSeriesAPIStrictReviewAndToken(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	_, f := installCapacityFixture(t, o)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	key := readMaintenanceSeries(t, o).Targets[0].Key
	body := seriesReviewBody(key, 0, f.now, 2)
	for _, raw := range []string{
		`{"startsAt":"x","endsAt":"y","extra":1}`,
		`{"startsAt":"x","startsAt":"x","endsAt":"y"}`,
		`{"startsAt":"x","endsAt":null}`,
		`{"startsAt":"x"}`,
		`null`,
	} {
		b := seriesReviewBody(key, 0, f.now, 2)
		encoded, _ := json.Marshal(b)
		var top map[string]json.RawMessage
		json.Unmarshal(encoded, &top)
		top["occurrences"] = json.RawMessage("[" + raw + "," + raw + "]")
		encoded, _ = json.Marshal(top)
		r, v := o.call(t, "POST", maintenanceSeriesPath+"/review", nil, csrf, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(string(encoded)))
			r.ContentLength = int64(len(encoded))
			r.Header.Set("Content-Type", "application/json")
		})
		if r.StatusCode != 400 {
			t.Fatal("nested accepted", r.StatusCode, v)
		}
	}
	for _, n := range []int{0, 1, 5} {
		r, v := o.call(t, "POST", maintenanceSeriesPath+"/review", seriesReviewBody(key, 0, f.now, n), csrf, nil)
		if r.StatusCode != 400 {
			t.Fatal("unbounded", r.StatusCode, v)
		}
	}
	r, review := o.call(t, "POST", maintenanceSeriesPath+"/review", body, csrf, nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, review)
	}
	invalid := seriesCommitBody(review)
	invalid["reviewToken"] = review["reviewToken"].(string) + "x"
	if r, _ := o.call(t, "POST", maintenanceSeriesPath+"/commit", invalid, csrf, nil); r.StatusCode != 409 {
		t.Fatal("tamper")
	}
	invalid = seriesCommitBody(review)
	invalid["acknowledged"] = false
	if r, _ := o.call(t, "POST", maintenanceSeriesPath+"/commit", invalid, csrf, nil); r.StatusCode != 409 {
		t.Fatal("unchecked")
	}
	invalid = seriesCommitBody(review)
	invalid["operationId"] = "changed"
	if r, _ := o.call(t, "POST", maintenanceSeriesPath+"/commit", invalid, csrf, nil); r.StatusCode != 409 {
		t.Fatal("different operation")
	}
	f.now = f.now.Add(121 * time.Second)
	if r, _ := o.call(t, "POST", maintenanceSeriesPath+"/commit", seriesCommitBody(review), csrf, nil); r.StatusCode != 409 {
		t.Fatal("expired")
	}
}
func TestWindowsMaintenanceSeriesAPINamedReadAndOriginalIdentity(t *testing.T) {
	named, _ := namedOperatorFixture(t)
	_, f := installCapacityFixture(t, named)
	_, login := named.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	view := readMaintenanceSeries(t, named)
	if r, _ := named.call(t, "POST", maintenanceSeriesPath+"/review", seriesReviewBody(view.Targets[0].Key, 0, f.now, 2), login["csrfToken"].(string), nil); r.StatusCode != 403 {
		t.Fatal("named write")
	}
	for _, change := range []string{"replacement", "revocation", "session"} {
		t.Run(change, func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			m, f := installCapacityFixture(t, o)
			_, login := o.login(t)
			csrf := login["csrfToken"].(string)
			key := readMaintenanceSeries(t, o).Targets[0].Key
			r, review := o.call(t, "POST", maintenanceSeriesPath+"/review", seriesReviewBody(key, 0, f.now, 2), csrf, nil)
			if r.StatusCode != 200 {
				t.Fatal(r.StatusCode, review)
			}
			switch change {
			case "replacement":
				f.inputs[0].CertificateHash = strings.Repeat("e", 64)
			case "revocation":
				f.inputs[0].Authorized = false
			case "session":
				_, next := o.login(t)
				csrf = next["csrfToken"].(string)
			}
			if r, v := o.call(t, "POST", maintenanceSeriesPath+"/commit", seriesCommitBody(review), csrf, nil); r.StatusCode == 200 {
				t.Fatal("changed authority", v)
			}
			states, e := m.store.WindowsMaintenanceSeries(context.Background(), m.source.Now)
			if e != nil || len(states) != 0 {
				t.Fatal("unauthorized commit", e)
			}
		})
	}
}

func TestWindowsMaintenanceSeriesAPIActiveEndAndExpiredReviewReceipt(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	_, f := installCapacityFixture(t, o)
	f.inputs[0].AuthorityUntil = f.now.Add(3 * time.Hour)
	_, login := o.login(t)
	csrf := login["csrfToken"].(string)
	key := readMaintenanceSeries(t, o).Targets[0].Key
	body := seriesReviewBody(key, 0, f.now.Add(-55*time.Minute), 2)
	r, review := o.call(t, "POST", maintenanceSeriesPath+"/review", body, csrf, nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, review)
	}
	r, receipt := o.call(t, "POST", maintenanceSeriesPath+"/commit", seriesCommitBody(review), csrf, nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, receipt)
	}
	f.now = f.now.Add(6 * time.Minute)
	r, ending := o.call(t, "POST", maintenanceSeriesPath+"/end/review", map[string]any{"key": key, "revision": 1, "occurrenceId": 1}, csrf, nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, ending)
	}
	if r, v := o.call(t, "POST", maintenanceSeriesPath+"/commit", seriesCommitBody(ending), csrf, nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode, v)
	}
	view := readMaintenanceSeries(t, o)
	for _, w := range view.Targets[0].Occurrences {
		if (w.ID == 1) != (w.EndedAt != nil) {
			t.Fatal("wrong end sibling", w)
		}
	}
	r, readback := o.call(t, "GET", maintenanceSeriesPath+"/receipts/"+review["operationId"].(string), nil, "", nil)
	if r.StatusCode != 200 || !reflect.DeepEqual(receipt, readback) {
		t.Fatal("original receipt changed after another action", r.StatusCode, readback)
	}
}
func TestWindowsMaintenanceSeriesAPIAuthorityAndClockFinalGuards(t *testing.T) {
	for _, change := range []string{"revoked", "replacement", "expired"} {
		t.Run(change, func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			m, f := installCapacityFixture(t, o)
			_, login := o.login(t)
			csrf := login["csrfToken"].(string)
			key := readMaintenanceSeries(t, o).Targets[0].Key
			r, review := o.call(t, "POST", maintenanceSeriesPath+"/review", seriesReviewBody(key, 0, f.now, 2), csrf, nil)
			if r.StatusCode != 200 {
				t.Fatal(r.StatusCode, review)
			}
			f.reads = 0
			f.onRead = func(n int) {
				if n != 2 {
					return
				}
				switch change {
				case "revoked":
					f.inputs[0].Authorized = false
				case "replacement":
					f.inputs[0].CertificateHash = strings.Repeat("b", 64)
				case "expired":
					f.inputs[0].AuthorityUntil = f.now
				}
			}
			if r, v := o.call(t, "POST", maintenanceSeriesPath+"/commit", seriesCommitBody(review), csrf, nil); r.StatusCode == 200 {
				t.Fatal("authority changed during request", v)
			}
			states, e := m.store.WindowsMaintenanceSeries(context.Background(), m.source.Now)
			if e != nil || len(states) != 0 {
				t.Fatal("invalid authority committed", e)
			}
		})
	}
	o := newOperatorFixture(t, time.Hour)
	m, f := installCapacityFixture(t, o)
	_, _ = o.login(t)
	base := f.now
	expires := base.Add(time.Second)
	f.inputs[0].AuthorityUntil = expires
	clock := &capacityBoundaryClock{fixtureWindowsCapacitySource: f}
	clock.transition = func(n int) time.Time {
		if n >= 5 {
			return expires
		}
		return base
	}
	m.source = clock
	if r, _ := o.call(t, "GET", maintenanceSeriesPath, nil, "", nil); r.StatusCode == 200 {
		t.Fatal("expired response released")
	}
}

func readMaintenanceSeriesLegacy(t *testing.T, o operatorFixture) windowsMaintenanceSeriesLegacyView {
	t.Helper()
	r, value := o.call(t, "GET", maintenanceSeriesPath+"/legacy", nil, "", nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode, value)
	}
	raw, _ := json.Marshal(value)
	var view windowsMaintenanceSeriesLegacyView
	if json.Unmarshal(raw, &view) != nil {
		t.Fatal("decode aware legacy")
	}
	return view
}
func TestWindowsMaintenanceSeriesLegacyUnrelatedControlsAndDomainIndependence(t *testing.T) {
	for _, sameDevice := range []bool{false, true} {
		name := "other_device"
		if sameDevice {
			name = "independent_domain"
		}
		t.Run(name, func(t *testing.T) {
			o := newOperatorFixture(t, time.Hour)
			_, f := installCapacityFixture(t, o)
			a := f.inputs[0].DeviceID
			b := a
			seriesDomain, legacyDomain := "all", "all"
			if sameDevice {
				seriesDomain, legacyDomain = "cpu", "disk"
			} else {
				other := capacityFixtureInput(f.now)
				other.DeviceID = "agent_" + strings.Repeat("d", 32)
				other.InvitationID = "invite_" + strings.Repeat("e", 32)
				other.CertificateHash = strings.Repeat("f", 64)
				f.inputs = append(f.inputs, other)
				b = other.DeviceID
			}
			_, login := o.login(t)
			csrf := login["csrfToken"].(string)
			initial := readMaintenanceSeriesLegacy(t, o)
			var seriesKey, legacyKey string
			for _, row := range initial.Legacy.Targets {
				if row.DeviceID == a && row.Domain == seriesDomain {
					seriesKey = row.Key
				}
				if row.DeviceID == b && row.Domain == legacyDomain {
					legacyKey = row.Key
				}
			}
			r, review := o.call(t, "POST", maintenanceSeriesPath+"/review", seriesReviewBody(seriesKey, 0, f.now, 4), csrf, nil)
			if r.StatusCode != 200 {
				t.Fatal(r.StatusCode, review)
			}
			if r, v := o.call(t, "POST", maintenanceSeriesPath+"/commit", seriesCommitBody(review), csrf, nil); r.StatusCode != 200 {
				t.Fatal(r.StatusCode, v)
			}
			if r, _ := o.call(t, "GET", maintenanceSchedulePath, nil, "", nil); r.StatusCode != 409 {
				t.Fatal("legacy GET must refuse incomplete fleet")
			}
			aware := readMaintenanceSeriesLegacy(t, o)
			if len(aware.Reservations) != len(aware.Legacy.Targets) {
				t.Fatal("incomplete reservations")
			}
			for i, reservation := range aware.Reservations {
				row := aware.Legacy.Targets[i]
				if reservation.Key != row.Key {
					t.Fatal("wrong target binding")
				}
				wantReserved := row.DeviceID == a && (seriesDomain == "all" || row.Domain == "all" || row.Domain == seriesDomain)
				if reservation.SeriesReserved != wantReserved {
					t.Fatal("wrong original domain reservation", row, reservation)
				}
				if row.Key == seriesKey && (row.RemainingSlots != 16 || reservation.RemainingSlots != 12) {
					t.Fatal("v1 modified or combined capacity lost", row, reservation)
				}
			}
			schedule := map[string]any{"key": legacyKey, "revision": 0, "startsAt": f.now.Add(5 * time.Minute).Format(time.RFC3339Nano), "endsAt": f.now.Add(10 * time.Minute).Format(time.RFC3339Nano), "intent": "planned-work"}
			if r, v := o.call(t, "POST", maintenanceSchedulePath+"/schedule", schedule, csrf, nil); r.StatusCode != 200 {
				t.Fatal("unrelated schedule blocked", r.StatusCode, v)
			}
			overlapping := map[string]any{}
			for key, value := range schedule {
				overlapping[key] = value
			}
			overlapping["key"] = seriesKey
			if r, v := o.call(t, "POST", maintenanceSchedulePath+"/schedule", overlapping, csrf, nil); r.StatusCode != 409 {
				t.Fatal("series overlap admitted", r.StatusCode, v)
			}
			aware = readMaintenanceSeriesLegacy(t, o)
			found := false
			for _, row := range aware.Legacy.Targets {
				if row.Key == legacyKey {
					found = len(row.Windows) == 1 && row.Windows[0].Pending(f.now)
				}
			}
			if !found {
				t.Fatal("unrelated pending hidden")
			}
			cancel := map[string]any{"key": legacyKey, "revision": 1, "windowId": 1}
			if r, v := o.call(t, "POST", maintenanceSchedulePath+"/cancel", cancel, csrf, nil); r.StatusCode != 200 {
				t.Fatal("unrelated cancel blocked", r.StatusCode, v)
			}
			schedule["revision"] = 2
			if r, v := o.call(t, "POST", maintenanceSchedulePath+"/schedule", schedule, csrf, nil); r.StatusCode != 200 {
				t.Fatal(r.StatusCode, v)
			}
			f.now = f.now.Add(6 * time.Minute)
			aware = readMaintenanceSeriesLegacy(t, o)
			found = false
			for _, row := range aware.Legacy.Targets {
				if row.Key == legacyKey {
					found = row.Windows[0].Active(f.now)
				}
			}
			if !found {
				t.Fatal("unrelated active hidden")
			}
			ending := map[string]any{"key": legacyKey, "revision": 3, "windowId": 3}
			if r, v := o.call(t, "POST", maintenanceSchedulePath+"/end", ending, csrf, nil); r.StatusCode != 200 {
				t.Fatal("unrelated end blocked", r.StatusCode, v)
			}
			aware = readMaintenanceSeriesLegacy(t, o)
			for i, row := range aware.Legacy.Targets {
				if row.Key == legacyKey && (row.Windows[0].EndedAt == nil || aware.Reservations[i].SeriesReserved) {
					t.Fatal("unrelated terminal or independence lost", row)
				}
			}
		})
	}
}
func TestWindowsMaintenanceSeriesLegacyNamedReadAndClosedRoute(t *testing.T) {
	named, _ := namedOperatorFixture(t)
	_, _ = installCapacityFixture(t, named)
	_, _ = named.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	view := readMaintenanceSeriesLegacy(t, named)
	if len(view.Legacy.Targets) != 6 || len(view.Reservations) != 6 {
		t.Fatal(view)
	}
	for _, path := range []string{maintenanceSeriesPath + "/legacy?", maintenanceSeriesPath + "/legacy?x=y"} {
		if r, _ := named.call(t, "GET", path, nil, "", nil); r.StatusCode != 400 {
			t.Fatal("query accepted")
		}
	}
	if r, _ := named.call(t, "POST", maintenanceSeriesPath+"/legacy", nil, "", nil); r.StatusCode == 200 {
		t.Fatal("write endpoint")
	}
}
