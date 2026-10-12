package windowsmanagedmsimanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	msi "localrmm/internal/windowsmanagedmsi"
	"strings"
	"testing"
)

// Inert signed metadata and the existing protected synthetic spool only.
func fleetScheduleWorklistFixture(t *testing.T) (*Registry, *worklistMemoryStore, WorklistView, WorklistSession, *int64) {
	t.Helper()
	a, base, _, actor, now, q, _ := scheduledManagerFixture(t)
	s := &worklistMemoryStore{fleetMemoryStore: base, journal: msi.WorklistJournal{Version: msi.WorklistVersion, ManagerID: a.binding.ManagerID, KeyID: a.binding.KeyID, Revision: 1, ClockFloor: *now, Worklists: []msi.Worklist{}}}
	a.store = s
	a.artifact.store = s
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{71}, 32))
	g := base.members[a.binding.DeviceID].r.Grant
	g.Binding.DeviceID = "agent_88888888888888888888888888888888"
	g.Binding.ExecutorID = "executor_99999999999999999999999999999999"
	g.Binding.ExecutorKeyID = msi.Digest(key.Public().(ed25519.PublicKey))
	g.Binding.DeliveryGrantID = "grant_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	g.Binding.InstallGrantID = "grant_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	rec, e := msi.NewRecord(g, a.key.Public().(ed25519.PublicKey), key.Public().(ed25519.PublicKey), *now)
	if e != nil {
		t.Fatal(e)
	}
	current := base.members[a.binding.DeviceID].current
	current.Binding = g.Binding
	s.members[g.Binding.DeviceID] = &memoryStore{r: rec, current: current, now: now}
	b, e := open(context.Background(), s, g.Binding, bytes.Clone(a.key), a.spool, a.now, a.configurationCheck, a.artifact)
	if e != nil {
		t.Fatal(e)
	}
	if e = b.ConfigureOperatorPolicy(a.deliveryAllowed, a.installAllowed); e != nil {
		t.Fatal(e)
	}
	if e = b.ConfigureSchedulePolicy(context.Background(), a.schedulePolicy); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	if e = b.DeliverArtifact(ctx, actor, "transfer_"+strings.Repeat("8", 32), true, q.ArtifactID, msi.BindingDigest(b.binding)); e != nil {
		t.Fatal(e)
	}
	poll, e := b.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	reusableManagerReport(t, b, key, poll.Permit, "delivery", *now)
	if e = b.Review(ctx, actor, true, true, true, true); e != nil {
		t.Fatal(e)
	}
	poll, e = b.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	reusableManagerReport(t, b, key, poll.Permit, "readiness", *now)
	r, e := NewRegistry([]*Manager{a, b})
	if e != nil {
		t.Fatal(e)
	}
	w, e := r.SaveWorklist(ctx, actor, SaveWorklistRequest{Name: "Exact selected fleet", ArtifactID: q.ArtifactID, ArtifactRetiredCount: "0", Targets: []SaveWorklistTarget{{DeviceID: a.binding.DeviceID, BindingDigest: msi.BindingDigest(a.binding), Name: "Device A"}, {DeviceID: b.binding.DeviceID, BindingDigest: msi.BindingDigest(b.binding), Name: "Device B"}}})
	if e != nil {
		t.Fatal(e)
	}
	return r, s, w, WorklistSession{ActorID: actor, Digest: msi.Digest([]byte("original fleet session")), ExpiresAt: *now + 300}, now
}
func fleetScheduleAcks() msi.WorklistAcknowledgements {
	return msi.WorklistAcknowledgements{PackageReviewAccepted: true, TermsAccepted: true, SynchronousReviewAccepted: true, ServiceRiskAccepted: true, ScheduleAccepted: true}
}
func fleetScheduleConfirm(t *testing.T, r *Registry, w WorklistView, sess WorklistSession, now int64) WorklistView {
	t.Helper()
	p, e := r.PreviewWorklistSchedule(context.Background(), sess.ActorID, w.ID, w.Revision, now+120, now+300)
	if e != nil || len(p.Items) != 2 {
		t.Fatal("preview", e, p)
	}
	v, e := r.ConfirmWorklist(context.Background(), sess, w.ID, ConfirmWorklistBatch{Revision: w.Revision, Kind: "schedule", Items: p.Items, Acknowledgements: fleetScheduleAcks()})
	if e != nil {
		t.Fatal("confirm", e)
	}
	return v
}
func fleetScheduleDispatch(r *Registry, sess WorklistSession, w WorklistView, index int) error {
	b := w.Batches[len(w.Batches)-1]
	q := b.Items[index].Request
	ctx, e := r.BatchDispatchContext(context.Background(), sess, &msi.WorklistDispatchReference{WorklistID: w.ID, BatchID: b.ID, Item: index}, q, b.Acknowledgements)
	if e != nil {
		return e
	}
	schedule, e := q.ScheduleRequest(b.Acknowledgements)
	if e != nil {
		return e
	}
	return r.Manager(q.DeviceID).Schedule(ctx, sess.ActorID, schedule)
}
func TestFleetScheduledMSIExactIndependentIntentsAndStop(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(map[bool]string{false: "both", true: "stop-after-first"}[stop], func(t *testing.T) {
			r, s, w, sess, now := fleetScheduleWorklistFixture(t)
			w = fleetScheduleConfirm(t, r, w, sess, *now)
			for _, m := range s.members {
				if m.r.Schedule != nil || len(m.r.InstallPermit) != 0 {
					t.Fatal("confirmation dispatched")
				}
			}
			if e := fleetScheduleDispatch(r, sess, w, 1); e == nil {
				t.Fatal("out of order")
			}
			if e := fleetScheduleDispatch(r, sess, w, 0); e != nil {
				t.Fatal(e)
			}
			first := s.members[w.Targets[0].Binding.DeviceID].r
			if first.Schedule == nil || first.Schedule.Approval.Request.StartAt != *now+120 || len(first.InstallPermit) != 0 {
				t.Fatal("intent/permit distinction")
			}
			if e := fleetScheduleDispatch(r, sess, w, 0); e == nil {
				t.Fatal("replay")
			}
			if stop {
				v, e := r.Worklist(context.Background(), sess.ActorID, w.ID)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = r.CloseWorklistBatch(context.Background(), sess.ActorID, w.ID, v.Revision, w.Batches[0].ID); e != nil {
					t.Fatal(e)
				}
				if e = fleetScheduleDispatch(r, sess, w, 1); e == nil {
					t.Fatal("stopped batch resumed")
				}
			} else if e := fleetScheduleDispatch(r, sess, w, 1); e != nil {
				t.Fatal(e)
			}
			v, e := r.Worklist(context.Background(), sess.ActorID, w.ID)
			if e != nil {
				t.Fatal(e)
			}
			item := v.Batches[0].Items[0]
			if item.State != "scheduled" || item.PermitDigest != "" || item.ScheduleDigest != first.Schedule.Approval.Digest || v.Batches[0].ClosedAt == 0 {
				t.Fatal("lost intent journal", v.Batches)
			}
			raw, _ := json.Marshal(s.journal)
			if _, e = msi.DecodeWorklistJournal(raw); e != nil {
				t.Fatal("reopen", e)
			}
			if msi.WorklistBatchReconciled(v.Worklist, v.Batches[0], map[string]msi.Record{first.Grant.Binding.DeviceID: first}) {
				t.Fatal("unretired intent compacted")
			}
			if e = r.Manager(first.Grant.Binding.DeviceID).CancelSchedule(context.Background(), sess.ActorID, item.ScheduleDigest); e != nil {
				t.Fatal(e)
			}
			second := s.members[w.Targets[1].Binding.DeviceID].r
			if stop && second.Schedule != nil || !stop && (second.Schedule == nil || second.Schedule.State != "scheduled") {
				t.Fatal("cross-device cancellation/stop")
			}
		})
	}
}
func TestFleetScheduledMSIMixedEligibilityAndExactReview(t *testing.T) {
	for _, name := range []string{"capability", "old-local-grant", "window", "renewed-leaf", "expired", "different-window", "readiness", "occurrence", "unchecked", "wrong-session", "changed-leaf-final", "deadline-final"} {
		t.Run(name, func(t *testing.T) {
			r, s, w, sess, now := fleetScheduleWorklistFixture(t)
			ctx := context.Background()
			b := r.ordered[1]
			switch name {
			case "capability":
				b.schedulePolicy = func(string) bool { return false }
			case "old-local-grant":
				b.scheduledProfile = false
				g := s.members[b.binding.DeviceID].r.Grant
				g.Version = msi.ReusableGrantVersion
				g.ScheduledEnabled = false
				g.ScheduledAcknowledged = false
				s.members[b.binding.DeviceID].r.Grant = g
			case "renewed-leaf":
				s.members[b.binding.DeviceID].current.LeafDigest = msi.Digest([]byte("renewed current leaf"))
			case "window":
				s.members[b.binding.DeviceID].current.LeafNotAfter = *now + 200
			}
			p, e := r.PreviewWorklistSchedule(ctx, sess.ActorID, w.ID, w.Revision, *now+120, *now+300)
			if e != nil {
				t.Fatal(e)
			}
			if name == "capability" || name == "old-local-grant" || name == "window" || name == "renewed-leaf" {
				if len(p.Items) != 1 || len(p.Excluded) != 1 || p.Excluded[0].DeviceID != b.binding.DeviceID {
					t.Fatal("mixed eligibility", p)
				}
				return
			}
			a := fleetScheduleAcks()
			switch name {
			case "expired":
				*now += 60
			case "different-window":
				p.Items[1].EndAt++
			case "readiness":
				p.Items[1].ReadinessDigest = msi.Digest([]byte("changed"))
			case "occurrence":
				p.Items[1].ArtifactRetiredCount = "1"
			case "unchecked":
				a.ScheduleAccepted = false
			}
			if name == "wrong-session" {
				v := fleetScheduleConfirm(t, r, w, sess, *now)
				sess.Digest = msi.Digest([]byte("replacement"))
				if e = fleetScheduleDispatch(r, sess, v, 0); e == nil {
					t.Fatal("session substitution")
				}
				return
			}
			if name == "changed-leaf-final" || name == "deadline-final" {
				v := fleetScheduleConfirm(t, r, w, sess, *now)
				batch := v.Batches[0]
				records := map[string]msi.Record{}
				currents := map[string]msi.Current{}
				for id, m := range s.members {
					records[id] = m.r
					currents[id] = m.current
				}
				if e = msi.CheckWorklistScheduleAuthority(batch, records, currents, *now); e != nil {
					t.Fatal(e)
				}
				if name == "changed-leaf-final" {
					c := currents[b.binding.DeviceID]
					c.LeafDigest = msi.Digest([]byte("renewed"))
					currents[b.binding.DeviceID] = c
				} else {
					*now += 60
				}
				if e = msi.CheckWorklistScheduleAuthority(batch, records, currents, *now); e == nil {
					t.Fatal("final authority changed")
				}
				return
			}
			if _, e = r.ConfirmWorklist(ctx, sess, w.ID, ConfirmWorklistBatch{Revision: w.Revision, Kind: "schedule", Items: p.Items, Acknowledgements: a}); e == nil {
				t.Fatal("changed review admitted")
			}
			for _, m := range s.members {
				if m.r.Schedule != nil {
					t.Fatal("rejected confirmation scheduled")
				}
			}
		})
	}
}
func TestFleetScheduledMSIPerDeviceRevocationBeforeDispatch(t *testing.T) {
	r, s, w, sess, now := fleetScheduleWorklistFixture(t)
	w = fleetScheduleConfirm(t, r, w, sess, *now)
	if e := fleetScheduleDispatch(r, sess, w, 0); e != nil {
		t.Fatal(e)
	}
	r.ordered[1].schedulePolicy = func(string) bool { return false }
	if e := fleetScheduleDispatch(r, sess, w, 1); !errors.Is(e, msi.ErrAuthority) {
		t.Fatal("removed capability", e)
	}
	if s.members[w.Targets[1].Binding.DeviceID].r.Schedule != nil || s.members[w.Targets[0].Binding.DeviceID].r.Schedule == nil {
		t.Fatal("partial outcome lost")
	}
}
