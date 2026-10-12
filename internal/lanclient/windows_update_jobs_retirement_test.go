//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	job "localrmm/internal/windowsupdatejob"
)

type retirementRelayClient struct {
	windowsUpdateExecutorClient
	status      job.ExecutorStatus
	proof       []byte
	permit      []byte
	retireCalls int
	outboxCalls int
	loseReply   bool
}

func (c *retirementRelayClient) Status(context.Context) (job.ExecutorStatus, error) {
	return c.status, nil
}
func (c *retirementRelayClient) Retire(_ context.Context, b []byte) ([]byte, error) {
	c.retireCalls++
	if !bytes.Equal(c.permit, b) {
		return nil, job.ErrInvalid
	}
	r, _ := job.VerifyRetirementReport(c.proof, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{212}, 32)).Public().(ed25519.PublicKey))
	c.status.RetirementPending = false
	c.status.InterventionRequired = false
	c.status.Retirements = []job.EvidenceStatus{{Kind: "retired", JobID: r.JobID, ReferenceDigest: r.ReferenceDigest, Selection: r.Selection, Sequence: r.Occurrence, Deadline: r.ExpiresAt, ClaimedAt: r.IssuedAt, Attempted: true, ReportState: "available", ReportIssuedAt: r.IssuedAt, ReportExpiresAt: r.ExpiresAt}}
	if c.loseReply {
		c.loseReply = false
		return nil, errors.New("inert lost metadata response")
	}
	return bytes.Clone(c.proof), nil
}
func (c *retirementRelayClient) Outbox(_ context.Context, kind, id, d string) ([]byte, error) {
	c.outboxCalls++
	if kind != "retired" {
		return nil, job.ErrInvalid
	}
	return bytes.Clone(c.proof), nil
}
func TestWindowsUpdateRetirementRelayLostClaimAndResponseReconcileWithoutSubmit(t *testing.T) {
	for _, lost := range []string{"claim", "retire", "report"} {
		t.Run(lost, func(t *testing.T) {
			f := newUpdateRelayFixture(t)
			n := f.sender.now().Unix()
			q := job.RetirementPermit{Version: job.RetirementVersion, Binding: f.grant.Binding, JobID: f.id, Selection: f.adapter.readiness.Selection, Occurrence: 1, EnvelopeDigest: actionpermit.Digest([]byte("exact install")), ResultDigest: actionpermit.Digest([]byte("exact signed result")), ActorID: f.actor, IssuedAt: n, ExpiresAt: n + 120}
			permit, e := job.SignRetirement(q, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{211}, 32)))
			if e != nil {
				t.Fatal(e)
			}
			ack, e := job.SignRetirementReport(job.RetirementReport{Version: job.RetirementVersion, Binding: q.Binding, JobID: q.JobID, Selection: q.Selection, Occurrence: q.Occurrence, ReferenceDigest: actionpermit.Digest(permit), EnvelopeDigest: q.EnvelopeDigest, ResultDigest: q.ResultDigest, ReleaseDigest: actionpermit.Digest([]byte("exact private release")), IssuedAt: n, ExpiresAt: n + 120}, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{212}, 32)))
			if e != nil {
				t.Fatal(e)
			}
			c := &retirementRelayClient{windowsUpdateExecutorClient: f.bridge, status: job.ExecutorStatus{Reusable: true, ObservedAt: n, Attempts: []job.EvidenceStatus{}, InstallCapacityRemaining: 1}, permit: permit, proof: ack, loseReply: lost == "retire"}
			f.sender.executor = c
			claims, reports, polls := 0, 0, 0
			acknowledged := false
			order := []string{}
			f.sender.exchange = func(_ context.Context, path string, body []byte) ([]byte, int, error) {
				order = append(order, path)
				switch path {
				case windowsUpdateJobsRelayPrefix + "poll":
					polls++
					if acknowledged {
						return []byte("null"), http.StatusOK, nil
					}
					return []byte(`{"jobId":"` + f.id + `","kind":"retire","deadline":` + fmt.Sprint(q.ExpiresAt) + `}`), http.StatusOK, nil
				case windowsUpdateJobsRelayPrefix + "retire-claim":
					claims++
					if lost == "claim" && claims == 1 {
						return nil, 0, errors.New("inert lost claim")
					}
					return bytes.Clone(permit), http.StatusOK, nil
				case windowsUpdateJobsRelayPrefix + "report":
					reports++
					if !bytes.Equal(body, ack) {
						t.Fatal("nonexact retirement ack")
					}
					acknowledged = true
					if lost == "report" && reports == 1 {
						return nil, 0, errors.New("inert lost report ack")
					}
					return []byte("{}"), http.StatusOK, nil
				}
				t.Fatal("unexpected install or readiness route", path)
				return nil, 0, nil
			}
			if got := f.sender.Run(context.Background()); got != "outcome_unknown" {
				t.Fatal("loss not surfaced", got)
			}
			got := f.sender.Run(context.Background())
			if lost == "claim" {
				if got != "reported" {
					t.Fatal(got)
				}
			} else if got != "idle" {
				t.Fatal("saved retirement starved next poll", got)
			}
			if c.retireCalls != 1 || f.bridge.submits != 0 || f.bridge.readiness != 0 || f.adapter.installs != 0 {
				t.Fatal("metadata recovery dispatched work", c.retireCalls, f.bridge.submits)
			}
			if lost != "claim" && claims != 1 {
				t.Fatal("lost endpoint/report response reclaimed retirement", claims)
			}
			// A newly started relay must reconcile saved ack before polling, yet must
			// continue polling after manager idempotently accepts the exact old ack.
			acknowledged = true
			f.sender.delivered = nil
			order = nil
			if got = f.sender.Run(context.Background()); got != "idle" {
				t.Fatal(got)
			}
			if len(order) != 2 || order[0] != windowsUpdateJobsRelayPrefix+"report" || order[1] != windowsUpdateJobsRelayPrefix+"poll" {
				t.Fatal("ack reconciliation order", order, polls, reports)
			}
		})
	}
}
func TestWindowsUpdateRetirementStatusRejectsLegacyAndCapacityPromotion(t *testing.T) {
	n := time.Now().UTC()
	base := job.ExecutorStatus{ObservedAt: n.Unix(), Attempts: []job.EvidenceStatus{}, InstallCapacityRemaining: job.MaxJobs}
	if !validWindowsUpdateRelayStatus(base, n) {
		t.Fatal("legacy status rejected")
	}
	base.RetirementPending = true
	if validWindowsUpdateRelayStatus(base, n) {
		t.Fatal("legacy pending retirement promoted")
	}
	base.Reusable = true
	base.InterventionRequired = true
	if validWindowsUpdateRelayStatus(base, n) {
		t.Fatal("legacy capacity promoted")
	}
	base.InstallCapacityRemaining = 1
	if !validWindowsUpdateRelayStatus(base, n) {
		t.Fatal("fresh bounded pending status rejected")
	}
}
