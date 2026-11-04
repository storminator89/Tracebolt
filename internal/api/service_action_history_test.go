package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/actionhelper"
	"localrmm/internal/actionjob"
	"localrmm/internal/actionstate"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/operatorauth"
)

type serviceHistoryFixture struct {
	record           actionjob.Record
	at               time.Time
	views, mutations int
	view             func(context.Context, string) (actionjob.Record, time.Time, error)
}

func (f *serviceHistoryFixture) ViewAt(ctx context.Context, device string) (actionjob.Record, time.Time, error) {
	f.views++
	if f.view != nil {
		return f.view(ctx, device)
	}
	return f.record, f.at, nil
}
func (f *serviceHistoryFixture) Preview(context.Context, string, string, string) (actionjob.Record, error) {
	f.mutations++
	return actionjob.Record{}, actionjob.ErrUnavailable
}
func (f *serviceHistoryFixture) Approve(context.Context, string, string, string, string) (actionjob.Record, error) {
	f.mutations++
	return actionjob.Record{}, actionjob.ErrUnavailable
}
func (*serviceHistoryFixture) TransportProfile() string { return actionhelper.ProductionTLS }
func (*serviceHistoryFixture) Available() bool          { return true }

func seedServiceHistory(t *testing.T, count int, lastState string) *serviceHistoryFixture {
	t.Helper()
	r, sign, _ := actionAPIRecord(t)
	at := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
	r.Preview = nil
	r.ClockFloor = at
	r.Capabilities.CapturedAt = at.Unix()
	r.CapabilitiesReceivedAt = &at
	f := &serviceHistoryFixture{record: r, at: at}
	for n := 0; n < count; n++ {
		now := at.Add(time.Duration(n) * 65 * time.Second)
		capability := *f.record.Capabilities
		capability.CapturedAt = now.Unix()
		if err := f.record.Report(capability, now); err != nil {
			t.Fatal(err)
		}
		p, err := f.record.MakePreview(fmt.Sprintf("action_%032x", n+1), namedActorID, "fixture.service", actionhelper.ProductionTLS, now)
		if err != nil {
			t.Fatal(err)
		}
		j, err := f.record.Approve(p.ID, p.Digest, p.ActorID, p.TransportProfile, now.Add(time.Second), sign)
		if err != nil {
			t.Fatal(err)
		}
		state := actionstate.OperationCompleted
		if n%2 != 0 {
			state = actionstate.Expired
		}
		if n == count-1 && lastState != "" {
			state = lastState
		}
		f.at = now.Add(8 * time.Second)
		if state == actionjob.Approved {
			continue
		}
		if state == actionstate.Expired {
			f.at = j.Deadline()
			f.record.ObserveExpiry(f.at)
			continue
		}
		if _, err = f.record.Claim(j.Identity(), p.TransportProfile, now.Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
		if state == actionjob.Claimed {
			continue
		}
		x := actionhelper.Result{JobID: j.Preview.ID, Sequence: j.Preview.Sequence, EnvelopeDigest: j.Identity().EnvelopeDigest, Phase: actionstate.Admitted, ConsumedAt: now.Add(2 * time.Second).UnixMicro(), TransitionAt: now.Add(2 * time.Second).UnixMicro()}
		if err = f.record.Accept(x, now.Add(3*time.Second)); err != nil {
			t.Fatal(err)
		}
		if state == actionstate.NotStarted {
			x.Phase, x.Reason, x.TransitionAt = state, actionstate.ReasonPreflight, now.Add(4*time.Second).UnixMicro()
			if err = f.record.Accept(x, now.Add(5*time.Second)); err != nil {
				t.Fatal(err)
			}
			continue
		}
		x.Phase, x.DispatchAt = actionstate.Dispatching, now.Add(4*time.Second).UnixMicro()
		x.TransitionAt = x.DispatchAt
		if err = f.record.Accept(x, now.Add(5*time.Second)); err != nil {
			t.Fatal(err)
		}
		x.Phase, x.Outcome, x.ObservedState = state, actionstate.OutcomeCompleted, actionstate.ObservedActive
		if state == actionstate.NeedsIntervention {
			x.Outcome, x.ObservedState = actionstate.OutcomeUnknown, actionstate.ObservedUnknown
		}
		x.TransitionAt = now.Add(6 * time.Second).UnixMicro()
		if err = f.record.Accept(x, now.Add(7*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if err := actionjob.Validate(f.record); err != nil {
		t.Fatal(err)
	}
	return f
}

func serviceHistoryOperator(t *testing.T, f *serviceHistoryFixture) operatorFixture {
	t.Helper()
	o, _ := namedOperatorFixture(t)
	o.server.Config.Handler.(*operatorHandler).actions = f
	r, _ := o.call(t, http.MethodPost, "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
	if r.StatusCode != http.StatusOK {
		t.Fatal("fixture login failed", r.StatusCode)
	}
	return o
}

func TestServiceActionHistoryBoundedProjectionAndOriginalReceipts(t *testing.T) {
	for _, count := range []int{0, actionjob.MaxJobs} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			f := seedServiceHistory(t, count, "")
			o := serviceHistoryOperator(t, f)
			before, _ := json.Marshal(f.record)
			path := "/api/devices/" + namedDeviceID + "/service-actions/history"
			for read := 0; read < 2; read++ {
				r, value := o.call(t, http.MethodGet, path, nil, "", func(r *http.Request) {
					if r.Header.Get("Origin") != "" || r.Header.Get("X-CSRF-Token") != "" || r.Header.Get("Content-Type") != "" {
						t.Fatal("read accidentally supplied mutation headers")
					}
				})
				if r.StatusCode != http.StatusOK || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Content-Type") != "application/json" {
					t.Fatal("normal status GET failed", r.StatusCode, value)
				}
				raw, _ := json.Marshal(value)
				if len(raw) > serviceActionHistoryBytes {
					t.Fatal("history exceeded bounded response")
				}
				for _, forbidden := range []string{`"envelope"`, `"signature"`, `"publicKey"`, `"preview"`, `"permit"`, `"plan"`, `"rootPolicyDigest"`, `"capabilities"`, `"consumedAt"`, `"transitionAt"`, `"dispatchAt"`} {
					if bytes.Contains(raw, []byte(forbidden)) {
						t.Fatal("history leaked excluded authority or raw result", forbidden)
					}
				}
				var history serviceActionHistoryView
				if err := json.Unmarshal(raw, &history); err != nil {
					t.Fatal(err)
				}
				if history.SchemaVersion != "tracebolt.service-action-history.v1" || history.DeviceID != namedDeviceID || !history.ServerNow.Equal(f.at) || history.IncarnationDigest != f.record.IncarnationDigest || history.KeyID != f.record.Capabilities.KeyID || history.Limit != actionjob.MaxJobs || history.Jobs == nil || len(history.Jobs) != count {
					t.Fatal("incorrect history binding/count/time", history)
				}
				for i, row := range history.Jobs {
					original := f.record.Jobs[count-i-1]
					if row.Sequence != original.Preview.Sequence || row.Job.ID != original.Preview.ID || row.Job.Unit != original.Preview.Plan.Unit || row.Job.ActorID != original.Preview.ActorID || !row.Job.ApprovedAt.Equal(original.Approval.ApprovedAt) || !row.Job.StartDeadline.Equal(original.Deadline()) || row.Job.State != original.State(f.at) || row.Job.EnvelopeDigest != original.Identity().EnvelopeDigest || len(row.Reports) != len(original.Results) || row.Reports == nil {
						t.Fatal("saved job changed or out of order", row.Sequence)
					}
					if (row.ClaimedAt == nil) != (original.ClaimedAt == nil) || row.ClaimedAt != nil && !row.ClaimedAt.Equal(*original.ClaimedAt) {
						t.Fatal("original claim time changed")
					}
					for k, receipt := range row.Reports {
						x := original.Results[k]
						if !receipt.ReceivedAt.Equal(original.ResultReceivedAt[k]) || receipt.Result != (serviceActionResult{x.Phase, x.Reason, x.Outcome, x.ObservedState}) || k == len(row.Reports)-1 && (row.Job.Result == nil || *row.Job.Result != receipt.Result) {
							t.Fatal("original manager receipt or result changed")
						}
					}
					if len(row.Reports) == 0 && row.Job.Result != nil {
						t.Fatal("missing result became completion")
					}
				}
			}
			after, _ := json.Marshal(f.record)
			if !bytes.Equal(before, after) || f.mutations != 0 || f.views != 2 {
				t.Fatal("projection mutated fixture or bypassed current view")
			}
		})
	}
}

func TestServiceActionHistoryKeepsAllPendingAndTerminalStates(t *testing.T) {
	for _, state := range []string{actionjob.Approved, actionjob.Claimed, actionstate.Expired, actionstate.NotStarted, actionstate.OperationCompleted, actionstate.NeedsIntervention} {
		t.Run(state, func(t *testing.T) {
			f := seedServiceHistory(t, 1, state)
			o := serviceHistoryOperator(t, f)
			r, value := o.call(t, http.MethodGet, "/api/devices/"+namedDeviceID+"/service-actions/history", nil, "", nil)
			raw, _ := json.Marshal(value)
			var history serviceActionHistoryView
			if r.StatusCode != http.StatusOK || json.Unmarshal(raw, &history) != nil || len(history.Jobs) != 1 || history.Jobs[0].Job.State != state {
				t.Fatal("state lost or falsely completed", r.StatusCode, value)
			}
		})
	}
}

func TestServiceActionHistoryPreservesAgentExpiredReportWithinClockSkew(t *testing.T) {
	f := seedServiceHistory(t, 1, actionjob.Claimed)
	j := f.record.Jobs[0]
	// Existing agent/manager clock skew allows the helper's expiry transition to
	// arrive just before the manager deadline. Preserve that report as evidence;
	// do not replace it with derived manager expiry or invent a dispatch.
	f.at = j.Deadline().Add(-time.Second)
	x := actionhelper.Result{JobID: j.Preview.ID, Sequence: j.Preview.Sequence, EnvelopeDigest: j.Identity().EnvelopeDigest, Phase: actionstate.Expired, ConsumedAt: j.Deadline().UnixMicro(), TransitionAt: j.Deadline().UnixMicro()}
	if err := f.record.Accept(x, f.at); err != nil {
		t.Fatal(err)
	}
	if err := actionjob.Validate(f.record); err != nil {
		t.Fatal(err)
	}
	o := serviceHistoryOperator(t, f)
	r, value := o.call(t, http.MethodGet, "/api/devices/"+namedDeviceID+"/service-actions/history", nil, "", nil)
	raw, _ := json.Marshal(value)
	var history serviceActionHistoryView
	if r.StatusCode != http.StatusOK || json.Unmarshal(raw, &history) != nil || len(history.Jobs) != 1 {
		t.Fatal("valid skewed expiry report was rejected", r.StatusCode, value)
	}
	row := history.Jobs[0]
	if row.ClaimedAt == nil || row.Job.State != actionstate.Expired || row.Job.Result == nil || row.Job.Result.Phase != actionstate.Expired || len(row.Reports) != 1 || !row.Reports[0].ReceivedAt.Equal(f.at) || !row.Job.StartDeadline.After(history.ServerNow) {
		t.Fatal("agent expiry report was restamped or lost", row)
	}
}

func TestServiceActionHistoryExactReadRouteAndCapability(t *testing.T) {
	f := seedServiceHistory(t, 0, "")
	path := "/api/devices/" + namedDeviceID + "/service-actions/history"
	o := serviceHistoryOperator(t, f)
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, path, 405}, {http.MethodPut, path, 405}, {http.MethodDelete, path, 405}, {http.MethodHead, path, 405},
		{http.MethodGet, path + "?next=1", 400}, {http.MethodGet, path + "?", 400},
		{http.MethodGet, strings.Replace(path, "history", "%68istory", 1), 400},
		{http.MethodGet, path + "/extra", 404}, {http.MethodGet, path + "/", 404},
	} {
		r, _ := o.call(t, tc.method, tc.path, nil, "", nil)
		if r.StatusCode != tc.want {
			t.Fatalf("%s %s: got %d, want %d", tc.method, tc.path, r.StatusCode, tc.want)
		}
	}
	if f.views != 0 || f.mutations != 0 {
		t.Fatal("invalid history route reached action manager")
	}
	for _, capabilities := range [][]operatorauth.Capability{nil, {operatorauth.Read}, {operatorauth.Read, operatorauth.PlanUpdates}} {
		reader := newOperatorFixture(t, 0)
		h := reader.server.Config.Handler.(*operatorHandler)
		h.actions = f
		if capabilities != nil {
			auth, err := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: capabilities}}})
			if err != nil {
				t.Fatal(err)
			}
			h.auth = auth
			reader.call(t, http.MethodPost, "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
		} else {
			if r, _ := reader.call(t, http.MethodGet, path, nil, "", nil); r.StatusCode != 401 {
				t.Fatal("anonymous history readable")
			}
			reader.login(t)
		}
		if r, _ := reader.call(t, http.MethodGet, path, nil, "", nil); r.StatusCode != 403 {
			t.Fatal("unrelated/shared grant read history", capabilities, r.StatusCode)
		}
	}
	if f.views != 0 || f.mutations != 0 {
		t.Fatal("denied account read source data")
	}
	for _, bad := range []string{path + "/extra", path + "/", path + "/action_" + strings.Repeat("1", 32)} {
		if _, _, ok := serviceActionRoute(httptest.NewRequest(http.MethodGet, bad, nil)); ok {
			t.Fatal("history accepted a broad route", bad)
		}
	}
}

func TestServiceActionHistoryFailsClosedOnAuthorityAndInvalidRecords(t *testing.T) {
	f := seedServiceHistory(t, 1, actionstate.OperationCompleted)
	o := serviceHistoryOperator(t, f)
	path := "/api/devices/" + namedDeviceID + "/service-actions/history"
	for _, err := range []error{enrollmentstate.ErrExpired, enrollmentstate.ErrProof, enrollmentstate.ErrNotFound, actionjob.ErrUnavailable} {
		f.view = func(context.Context, string) (actionjob.Record, time.Time, error) { return f.record, f.at, err }
		r, value := o.call(t, http.MethodGet, path, nil, "", nil)
		if r.StatusCode == 200 || value["jobs"] != nil || value["incarnationDigest"] != nil {
			t.Fatal("history disclosed failed current authority", r.StatusCode, value)
		}
	}
	for _, kind := range []string{"device", "incarnation", "sequence", "result", "floor", "time"} {
		t.Run(kind, func(t *testing.T) {
			raw, _ := json.Marshal(f.record)
			var record actionjob.Record
			_ = json.Unmarshal(raw, &record)
			at := f.at
			switch kind {
			case "device":
				record.DeviceID = "agent_" + strings.Repeat("f", 32)
			case "incarnation":
				record.IncarnationDigest = "sha256:" + strings.Repeat("f", 64)
			case "sequence":
				record.Jobs[0].Preview.Sequence++
			case "result":
				record.Jobs[0].Results[2].Outcome = actionstate.OutcomeUnknown
			case "floor":
				at = record.ClockFloor.Add(-time.Nanosecond)
			case "time":
				at = time.Time{}
			}
			f.view = func(context.Context, string) (actionjob.Record, time.Time, error) { return record, at, nil }
			r, value := o.call(t, http.MethodGet, path, nil, "", nil)
			if r.StatusCode == 200 || value["jobs"] != nil || value["incarnationDigest"] != nil {
				t.Fatal("history disclosed inconsistent binding/record/time", r.StatusCode, value)
			}
		})
	}
}

func TestServiceActionHistoryRechecksSessionAfterSourceRead(t *testing.T) {
	for _, mode := range []string{"expiry", "revocation"} {
		t.Run(mode, func(t *testing.T) {
			f := seedServiceHistory(t, 1, actionstate.OperationCompleted)
			o := newOperatorFixture(t, 0)
			h := o.server.Config.Handler.(*operatorHandler)
			h.actions = f
			var ticks atomic.Int64
			ticks.Store(time.Now().UTC().UnixNano())
			auth, err := operatorauth.New(operatorauth.Config{Now: func() time.Time { return time.Unix(0, ticks.Load()).UTC() }, TTL: time.Minute, Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.RestartService}}}})
			if err != nil {
				t.Fatal(err)
			}
			h.auth = auth
			session, err := auth.LoginNamed(context.Background(), "127.0.0.1", "reader", operatorFixturePassword)
			if err != nil {
				t.Fatal(err)
			}
			f.view = func(context.Context, string) (actionjob.Record, time.Time, error) {
				if mode == "expiry" {
					ticks.Store(session.ExpiresAt.UnixNano())
				} else {
					auth.Logout(session.Token)
				}
				return f.record, f.at, nil
			}
			r, value := o.call(t, http.MethodGet, "/api/devices/"+namedDeviceID+"/service-actions/history", nil, "", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: h.cookieName, Value: session.Token}) })
			if r.StatusCode != 401 || value["jobs"] != nil || value["incarnationDigest"] != nil || f.views != 1 || f.mutations != 0 {
				t.Fatal("after-read session loss disclosed history", r.StatusCode, value)
			}
		})
	}
}
