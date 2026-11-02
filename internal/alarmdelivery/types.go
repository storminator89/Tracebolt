// Package alarmdelivery defines the bounded, default-off external alarm contract.
// Provider acceptance never proves receipt by a person.
package alarmdelivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/operatorauth"
	"regexp"
	"sync"
	"time"
)

const (
	MaxPending      = 500
	MaxRecords      = 1000
	MaxAttempts     = 5
	MaxPayloadBytes = 2048
	MaxQueueAge     = 24 * time.Hour
	OpeningCooldown = 10 * time.Minute
	SendInterval    = 2 * time.Second
)

var ErrInvalid = errors.New("alarm_delivery_invalid")
var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)

type Binding struct {
	ManagerInstanceID string `json:"managerInstanceId"`
	Profile           string `json:"profile"`
	DestinationID     string `json:"destinationId"`
	Generation        string `json:"generation"`
	Fingerprint       string `json:"fingerprint"`
}

func (b Binding) Valid() bool {
	_, e := hex.DecodeString(b.Fingerprint)
	return identifier.MatchString(b.ManagerInstanceID) && (b.Profile == "tls" || b.Profile == "http-test") && identifier.MatchString(b.DestinationID) && identifier.MatchString(b.Generation) && len(b.Fingerprint) == 64 && e == nil
}
func (b Binding) Key() string {
	raw, _ := json.Marshal(b)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

type Payload struct {
	SchemaVersion string    `json:"schemaVersion"`
	EventID       string    `json:"eventId"`
	DeviceID      string    `json:"deviceId"`
	IncidentID    string    `json:"incidentId"`
	Rule          string    `json:"rule"`
	Target        string    `json:"target"`
	Severity      string    `json:"severity"`
	Transition    string    `json:"transition"`
	State         string    `json:"state"`
	Reason        string    `json:"reason"`
	ObservedAt    time.Time `json:"observedAt"`
	TransitionAt  time.Time `json:"transitionAt"`
}
type Outcome string

const (
	Accepted  Outcome = "provider_accepted"
	Retryable Outcome = "retryable"
	Failed    Outcome = "failed"
	Uncertain Outcome = "uncertain"
)

type Result struct {
	Outcome Outcome
	Code    string
}
type Transport interface {
	Send(context.Context, Payload) Result
}
type Attempt struct {
	Payload Payload
	Number  int
	// TestActor/AuthorityEpoch are protected outbox metadata, never external payload.
	OperatorTest   bool
	TestActor      string
	AuthorityEpoch uint64
}
type Queue interface {
	ClaimAlarm(context.Context, Binding, time.Time) (*Attempt, error)
	CompleteAlarm(context.Context, Binding, Attempt, Result, time.Time) error
}

// Worker serializes claims, never holds a storage transaction across transport.
// A crash after claiming leaves an uncertain record; startup never replays it.
type Worker struct {
	mu               sync.Mutex
	queue            Queue
	binding          Binding
	transport        Transport
	now              func() time.Time
	accountAdmission operatorauth.ActorAdmission
}

func NewWorker(q Queue, b Binding, t Transport, now func() time.Time) (*Worker, error) {
	if q == nil || t == nil || !b.Valid() {
		return nil, ErrInvalid
	}
	if now == nil {
		now = time.Now
	}
	return &Worker{queue: q, binding: b, transport: t, now: now}, nil
}

// ConfigureAccountAuthority is startup-only and cannot change a running policy.
func (w *Worker) ConfigureAccountAuthority(admission operatorauth.ActorAdmission) error {
	if w == nil || admission == nil {
		return ErrInvalid
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.accountAdmission != nil {
		return ErrInvalid
	}
	w.accountAdmission = admission
	return nil
}
func (w *Worker) Step(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	a, e := w.queue.ClaimAlarm(ctx, w.binding, w.now().UTC())
	if e != nil || a == nil {
		return e
	}
	step, cancel := context.WithTimeout(ctx, 10*time.Second)
	result := Result{Outcome: Failed, Code: "operator_authority_revoked"}
	release := func() {}
	admitted := true
	// Tests are a separate fixed payload class. Never infer routine monitoring
	// authority from absent test metadata or retrofit an actor onto committed rules.
	if a.OperatorTest || a.Payload.Rule == TestRule || a.Payload.SchemaVersion == TestSchemaVersion {
		if !IsTestPayload(a.Payload) {
			admitted = false
			result.Code = "invalid_payload"
		} else if w.accountAdmission != nil {
			var err error
			step, release, err = w.accountAdmission(step, a.TestActor, a.AuthorityEpoch, operatorauth.ManageAlarms)
			admitted = err == nil
			if !admitted {
				release = func() {}
			}
		} else if a.AuthorityEpoch != 0 {
			// A live-mode receipt cannot be dispatched after startup loses its policy.
			admitted = false
		}
	}
	if admitted {
		result = w.transport.Send(step, a.Payload)
	}
	release()
	cancel()
	// Persist an ambiguous shutdown result even when the request context expired.
	save, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	return w.queue.CompleteAlarm(save, w.binding, *a, result, w.now().UTC())
}
func (w *Worker) Run(ctx context.Context, warn func()) error {
	ticker := time.NewTicker(SendInterval)
	defer ticker.Stop()
	var last time.Time
	for {
		e := w.Step(ctx)
		if ctx.Err() != nil {
			return nil
		}
		now := w.now()
		if e != nil && warn != nil && (last.IsZero() || now.Sub(last) >= time.Minute) {
			warn()
			last = now
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
