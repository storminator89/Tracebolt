package macosservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

var ErrUnavailable = errors.New("native macOS create-only lifecycle adapter unavailable")
var ErrCollision = errors.New("macOS service ownership or service collision")
var ErrIndeterminate = errors.New("macOS service transition requires read-only reconciliation; do not retry or reset")

// Presence has no permissive zero value. Absence must be positively established
// by the adapter; command failure, missing permissions and parser errors are not
// absence. Override includes either enabled or disabled retained native overrides.
type Presence string

const (
	Absent  Presence = "absent"
	Present Presence = "present"
)

// Ownership binds selected bytes and the already activated scope. The enrollment
// anchor covers immutable original intent, issuer, key, ready binding and any
// original inventory consent/grant. It excludes mutable sender counters and the
// same-key current-leaf manifest, which must still validate on EVERY Inspect.
// No secret bytes, credentials or raw enrollment ledger belong in this record.
type Ownership struct {
	SchemaVersion          string `json:"schemaVersion"`
	Label                  string `json:"label"`
	ServiceIdentity        string `json:"serviceIdentity"`
	CollectionProfile      string `json:"collectionProfile"`
	AgentPath              string `json:"agentPath"`
	AgentSHA256            string `json:"agentSHA256"`
	SourceArchive          string `json:"sourceArchive"`
	SourceSHA256           string `json:"sourceSHA256"`
	ConfigPath             string `json:"configPath"`
	ConfigSHA256           string `json:"configSHA256"`
	EnrollmentAnchorSHA256 string `json:"enrollmentAnchorSHA256"`
	PlistPath              string `json:"plistPath"`
	PlistSHA256            string `json:"plistSHA256"`
}

func digest(raw []byte) string     { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func (o Ownership) SHA256() string { raw, _ := json.Marshal(o); return digest(raw) }
func (o Ownership) valid() bool {
	r := Request{ServiceIdentity: o.ServiceIdentity, Profile: o.CollectionProfile, AgentSHA256: o.AgentSHA256, SourceArchive: o.SourceArchive, SourceSHA256: o.SourceSHA256}
	p, err := Plan(r)
	return err == nil && o.CollectionProfile == selectedProfile(r) && o.SchemaVersion == "tracebolt.macos-service-owner.v1" && o.Label == Label && o.AgentPath == AgentPath && o.ConfigPath == ConfigPath && o.PlistPath == PlistPath && o.PlistSHA256 == p.PlistSHA256 && validDigest(o.ConfigSHA256) && validDigest(o.EnrollmentAnchorSHA256)
}

// DecodeOwnership requires exact canonical bytes, rejecting duplicate/unknown
// fields as well as alternate encodings. Protected storage is an adapter duty.
func DecodeOwnership(raw []byte) (Ownership, error) {
	var o Ownership
	if len(raw) == 0 || len(raw) > 8192 || json.Unmarshal(raw, &o) != nil || !o.valid() {
		return Ownership{}, ErrCollision
	}
	canonical, _ := json.Marshal(o)
	if !bytes.Equal(raw, canonical) {
		return Ownership{}, ErrCollision
	}
	return o, nil
}

type Receipt struct {
	SchemaVersion   string `json:"schemaVersion"`
	OwnershipSHA256 string `json:"ownershipSHA256"`
	Sequence        int    `json:"sequence"`
	Phase           string `json:"phase"`
	Status          string `json:"status"`
}

// RemovalReceipt is a separate one-attempt terminalization ledger. It never
// resets installation receipts or grants permission to install again.
type RemovalReceipt struct {
	SchemaVersion   string `json:"schemaVersion"`
	OwnershipSHA256 string `json:"ownershipSHA256"`
	Sequence        int    `json:"sequence"`
	Phase           string `json:"phase"`
	Status          string `json:"status"`
}

func expectedRemovalReceipts(o Ownership) []RemovalReceipt {
	return []RemovalReceipt{
		{"tracebolt.macos-service-removal.v1", o.SHA256(), 1, "bootout", "started"},
		{"tracebolt.macos-service-removal.v1", o.SHA256(), 2, "bootout", "completed"},
		{"tracebolt.macos-service-removal.v1", o.SHA256(), 3, "remove-plist", "started"},
		{"tracebolt.macos-service-removal.v1", o.SHA256(), 4, "remove-plist", "completed"},
	}
}

func DecodeRemovalReceipt(raw []byte, owner Ownership) (RemovalReceipt, error) {
	var r RemovalReceipt
	if !owner.valid() || len(raw) == 0 || len(raw) > 1024 || json.Unmarshal(raw, &r) != nil || r.Sequence < 1 || r.Sequence > 4 || r != expectedRemovalReceipts(owner)[r.Sequence-1] {
		return RemovalReceipt{}, ErrCollision
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(raw, canonical) {
		return RemovalReceipt{}, ErrCollision
	}
	return r, nil
}

func expectedReceipts(o Ownership) []Receipt {
	return []Receipt{
		{"tracebolt.macos-service-phase.v1", o.SHA256(), 1, "publish-plist", "started"},
		{"tracebolt.macos-service-phase.v1", o.SHA256(), 2, "publish-plist", "completed"},
		{"tracebolt.macos-service-phase.v1", o.SHA256(), 3, "bootstrap", "started"},
		{"tracebolt.macos-service-phase.v1", o.SHA256(), 4, "bootstrap", "completed"},
	}
}
func DecodeReceipt(raw []byte, owner Ownership) (Receipt, error) {
	var r Receipt
	if !owner.valid() || len(raw) == 0 || len(raw) > 1024 || json.Unmarshal(raw, &r) != nil || r.Sequence < 1 || r.Sequence > 4 || r != expectedReceipts(owner)[r.Sequence-1] {
		return Receipt{}, ErrCollision
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(raw, canonical) {
		return Receipt{}, ErrCollision
	}
	return r, nil
}

// InstallSnapshot is trusted evidence from a protected, locked adapter, NOT
// caller-supplied JSON or prior preflight output. Inspect rechecks exact selected
// account/artifacts/paths without initialization, collection, network, permission
// changes or repair. Before bootstrap it validates the existing activated
// handoff/current leaf and used sender state under the dedicated-user lock.
// Once the exact owned job is positively registered after a durable bootstrap-
// start receipt, that foreground process may hold the sender lock for life.
// Inspection then rechecks immutable originals/current TLS material without
// reacquiring mutable sender locks. This never proves lock ownership, mutable
// sender correctness or reporting. Custody covers BOTH used fence and owner: partial,
// missing-used, foreign, duplicate or uncertain storage must return an error.
// A present JobOwnershipSHA256 may be asserted only after verifying the exact
// system-domain job's registration path, type, program and arguments plus the
// protected plist bytes. It does not prove launchd honored UserName/GroupName,
// runtime identity, process health or reporting. The agent independently rejects
// mismatched numeric identities before private reads. Native credential isolation
// remains a separate acceptance gate.
type InstallSnapshot struct {
	PrerequisitesVerified  bool
	Config                 []byte
	EnrollmentAnchorSHA256 string
	Custody                Presence
	Owner                  *Ownership
	Receipts               []Receipt
	RemovalReceipts        []RemovalReceipt
	Plist                  Presence
	PlistSHA256            string
	Job                    Presence
	JobOwnershipSHA256     string
	Override               Presence
}

type InstallBackend interface {
	// Open(false) must be read-only, including no lock-file or directory creation.
	// Open(true) holds exclusive lifecycle custody across the operation. The
	// dedicated-identity child acquires and releases enrollment/sender read locks
	// on each inspection; operators must stop any other sender before install.
	// Opening must not claim/adopt/create durable state. Close never rolls back.
	Open(context.Context, Request, bool) (InstallSession, error)
}

type InstallSession interface {
	Inspect(context.Context) (InstallSnapshot, error)
	// Claim first durably writes an independent used fence, then the immutable
	// owner, both no-replace. Any partial write/error stays fenced. Never recover
	// missing used state or adopt an existing owner, even if its bytes match.
	Claim(context.Context, Ownership) error
	// AppendReceipt persists only the next exact no-replace receipt with full
	// flush/directory durability. Existing slots, gaps and uncertain writes fail.
	AppendReceipt(context.Context, Receipt) error
	// Publish creates only the fixed root-owned protected plist, no replacement.
	// These mutators recheck held descriptors, exact selection and all collision
	// evidence atomically as far as the native interface permits. No foreign state
	// may be stopped, unloaded, enabled, deleted, changed or adopted.
	Publish(context.Context, Ownership, string) error
	Bootstrap(context.Context, Ownership) error
	Close() error
}

// RemovalSession is optional for fake-backed tests and native ownership-only
// removal. No method deletes credentials, account, agent, source or used fences.
type RemovalSession interface {
	InstallSession
	AppendRemovalReceipt(context.Context, RemovalReceipt) error
	Bootout(context.Context, Ownership) error
	RemoveOwnedPlist(context.Context, Ownership) error
}

type InstallRequest struct {
	Selection Request
	Apply     bool
}
type InstallResult struct {
	SchemaVersion            string          `json:"schemaVersion"`
	ReadOnly                 bool            `json:"readOnly"`
	AdapterAvailable         bool            `json:"adapterAvailable"`
	Status                   string          `json:"status"`
	OwnershipSHA256          string          `json:"ownershipSHA256,omitempty"`
	LastReceipt              *Receipt        `json:"lastReceipt,omitempty"`
	LastRemovalReceipt       *RemovalReceipt `json:"lastRemovalReceipt,omitempty"`
	ObservedPlist            Presence        `json:"observedPlist"`
	ObservedJob              Presence        `json:"observedJob"`
	MutationAttempted        bool            `json:"mutationAttempted"`
	NativeAcceptanceVerified bool            `json:"nativeAcceptanceVerified"`
}

func ownershipFor(r Request, p Result, s InstallSnapshot) (Ownership, error) {
	if !s.PrerequisitesVerified || validateSelectedConfig(s.Config, selectedProfile(r)) != nil || !validDigest(s.EnrollmentAnchorSHA256) {
		return Ownership{}, ErrPreflight
	}
	return Ownership{"tracebolt.macos-service-owner.v1", Label, r.ServiceIdentity, selectedProfile(r), AgentPath, r.AgentSHA256, r.SourceArchive, r.SourceSHA256, ConfigPath, digest(s.Config), s.EnrollmentAnchorSHA256, PlistPath, p.PlistSHA256}, nil
}
func receiptPrefix(o Ownership, receipts []Receipt) bool {
	want := expectedReceipts(o)
	if len(receipts) > len(want) {
		return false
	}
	for i, r := range receipts {
		if r != want[i] {
			return false
		}
	}
	return true
}
func runtimeMatches(s InstallSnapshot, o Ownership, plist, job Presence) bool {
	if s.Override != Absent || s.Plist != plist || s.Job != job {
		return false
	}
	if plist == Absent && s.PlistSHA256 != "" || plist == Present && s.PlistSHA256 != o.PlistSHA256 {
		return false
	}
	if job == Absent && s.JobOwnershipSHA256 != "" || job == Present && s.JobOwnershipSHA256 != o.SHA256() {
		return false
	}
	return true
}

// allowRegisteredHandoff is the sole admission to the nonroot no-sender-lock
// check after launchd may start the foreground agent. It requires a completed
// pre-bootstrap ownership/receipt prefix and positive exact registration; a
// foreign or unknown lock, by itself, can never select this branch. It does
// not authenticate who owns a lock or establish that the agent is running.
func allowRegisteredHandoff(r Request, s InstallSnapshot) bool {
	if s.Custody != Present || s.Owner == nil || !s.Owner.valid() || s.Owner.ServiceIdentity != r.ServiceIdentity || s.Owner.CollectionProfile != selectedProfile(r) || s.Owner.AgentSHA256 != r.AgentSHA256 || s.Owner.SourceArchive != r.SourceArchive || s.Owner.SourceSHA256 != r.SourceSHA256 {
		return false
	}
	p, err := Plan(r)
	if err != nil || s.Owner.PlistSHA256 != p.PlistSHA256 || len(s.Receipts) < 3 || len(s.Receipts) > 4 || !receiptPrefix(*s.Owner, s.Receipts) || len(s.RemovalReceipts) > 1 {
		return false
	}
	if len(s.RemovalReceipts) == 1 && s.RemovalReceipts[0] != expectedRemovalReceipts(*s.Owner)[0] {
		return false
	}
	return runtimeMatches(s, *s.Owner, Present, Present)
}

// Install is create-only. Default preflight and all repeat invocations are
// read-only. An interrupted attempt is NEVER retried, completed, rolled back or
// reset, even if current native state appears absent. Inspection can report the
// original receipts and current state; it cannot prove an unrecorded outcome.
// The Darwin adapter is source-only pending native acceptance.
func Install(ctx context.Context, r InstallRequest, backend InstallBackend) (result InstallResult, resultErr error) {
	result = InstallResult{SchemaVersion: "tracebolt.macos-service-install.v1", ReadOnly: !r.Apply, Status: "blocked"}
	p, err := Plan(r.Selection)
	if err != nil || ctx == nil || r.Selection.RenderOnly {
		return result, ErrRequest
	}
	if ctx.Err() != nil {
		return result, ErrPreflight
	}
	if backend == nil {
		result.Status = "unavailable"
		return result, ErrUnavailable
	}
	result.AdapterAvailable = true
	session, err := backend.Open(ctx, r.Selection, r.Apply)
	if err != nil || session == nil {
		return result, ErrPreflight
	}
	defer func() {
		if session.Close() != nil {
			result.Status = "blocked"
			resultErr = ErrPreflight
			if result.MutationAttempted {
				result.Status = "indeterminate"
				resultErr = ErrIndeterminate
			}
		}
	}()
	inspect := func() (InstallSnapshot, error) {
		if ctx.Err() != nil {
			return InstallSnapshot{}, ErrPreflight
		}
		snapshot, e := session.Inspect(ctx)
		if e != nil || ctx.Err() != nil {
			return InstallSnapshot{}, ErrPreflight
		}
		result.ObservedPlist, result.ObservedJob = snapshot.Plist, snapshot.Job
		return snapshot, nil
	}
	snapshot, err := inspect()
	if err != nil {
		return result, ErrPreflight
	}
	owner, err := ownershipFor(r.Selection, p, snapshot)
	if err != nil {
		return result, err
	}
	result.OwnershipSHA256 = owner.SHA256()
	if snapshot.Custody == Present {
		if snapshot.Owner == nil || *snapshot.Owner != owner || !receiptPrefix(owner, snapshot.Receipts) || len(snapshot.RemovalReceipts) != 0 {
			return result, ErrCollision
		}
		if len(snapshot.Receipts) > 0 {
			last := snapshot.Receipts[len(snapshot.Receipts)-1]
			result.LastReceipt = &last
		}
		result.ReadOnly = true
		if len(snapshot.Receipts) == 4 && runtimeMatches(snapshot, owner, Present, Present) {
			result.Status = "registration-confirmed"
			return result, nil
		}
		result.Status = "indeterminate"
		return result, ErrIndeterminate
	}
	if snapshot.Custody != Absent || snapshot.Owner != nil || len(snapshot.Receipts) != 0 || !runtimeMatches(snapshot, owner, Absent, Absent) {
		return result, ErrCollision
	}
	result.Status = "preflight-passed"
	if !r.Apply {
		return result, nil
	}
	// Re-inspect under the held exclusive session immediately before ownership.
	check := func(receipts []Receipt, custody, plist, job Presence) error {
		now, e := inspect()
		if e != nil {
			return e
		}
		bound, e := ownershipFor(r.Selection, p, now)
		if e != nil || bound != owner || now.Custody != custody || !runtimeMatches(now, owner, plist, job) || len(now.Receipts) != len(receipts) {
			return ErrIndeterminate
		}
		if custody == Present && (now.Owner == nil || *now.Owner != owner) || custody == Absent && now.Owner != nil {
			return ErrIndeterminate
		}
		for i := range receipts {
			if now.Receipts[i] != receipts[i] {
				return ErrIndeterminate
			}
		}
		if len(receipts) > 0 {
			last := receipts[len(receipts)-1]
			result.LastReceipt = &last
		}
		return nil
	}
	if check(nil, Absent, Absent, Absent) != nil {
		result.Status = "blocked"
		return result, ErrPreflight
	}
	result.MutationAttempted = true
	result.Status = "indeterminate"
	if session.Claim(ctx, owner) != nil || check(nil, Present, Absent, Absent) != nil {
		return result, ErrIndeterminate
	}
	receipts := expectedReceipts(owner)
	for i, receipt := range receipts {
		// A durable started receipt precedes each external effect. A completed
		// receipt follows its separately re-inspected exact postcondition.
		if ctx.Err() != nil || session.AppendReceipt(ctx, receipt) != nil {
			return result, ErrIndeterminate
		}
		plist, job := Absent, Absent
		if i >= 1 {
			plist = Present
		}
		if i == 3 {
			job = Present
		}
		if check(receipts[:i+1], Present, plist, job) != nil {
			return result, ErrIndeterminate
		}
		switch i {
		case 0:
			if ctx.Err() != nil || session.Publish(ctx, owner, p.Plist) != nil || check(receipts[:i+1], Present, Present, Absent) != nil {
				return result, ErrIndeterminate
			}
		case 2:
			if ctx.Err() != nil || session.Bootstrap(ctx, owner) != nil || check(receipts[:i+1], Present, Present, Present) != nil {
				return result, ErrIndeterminate
			}
		}
	}
	result.Status = "registration-confirmed"
	return result, nil
}
