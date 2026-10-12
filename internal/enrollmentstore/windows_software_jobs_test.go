package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowssoftwarejob"
	"localrmm/internal/windowsupdatejob"
)

type windowsSoftwareStoreFixture struct {
	fixture       fixture
	store         *Store
	path          string
	snapshot      enrollmentstate.Snapshot
	anchor        enrollmentcrypto.VerifiedCertificate
	key, executor ed25519.PrivateKey
	consent       windowssoftwarejob.Consent
	at            time.Time
}

func newWindowsSoftwareStoreFixture(t *testing.T, setup bool) windowsSoftwareStoreFixture {
	t.Helper()
	f, s, path, snap, cert := activeWindowsStore(t, "tls")
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{107}, ed25519.SeedSize))
	executor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{108}, ed25519.SeedSize))
	b := windowssoftwarejob.Binding{ManagerID: snap.Binding.InstanceID, DeviceID: snap.Approval.DeviceID, IncarnationDigest: "sha256:" + cert.CertificateHash(), ExecutorID: id("executor", 4), ExecutorKeyID: actionpermit.Digest(executor.Public().(ed25519.PublicKey)), GrantID: id("grant", 5), KeyID: actionpermit.Digest(key.Public().(ed25519.PublicKey))}
	consent := windowssoftwarejob.Consent{Package: preparedMSITestSelection(), NativeAcceptanceDigest: actionpermit.Digest([]byte("native acceptance")), PackageReviewAccepted: true, Version: windowssoftwarejob.ConsentVersion, Scope: windowssoftwarejob.Scope, Binding: b, Enabled: true, Acknowledged: true, ExpiresAt: snap.Intent.NotAfter + 86400}
	out := windowsSoftwareStoreFixture{f, s, path, snap, cert, key, executor, consent, time.Unix(testNow+10, 0).UTC()}
	if setup {
		if err := out.setup(); err != nil {
			t.Fatal("setup", err)
		}
	}
	return out
}
func (f windowsSoftwareStoreFixture) setup() error {
	return f.store.SetupWindowsSoftwareJobsCreateOnly(context.Background(), f.key.Public().(ed25519.PublicKey), f.executor.Public().(ed25519.PublicKey), f.consent, f.at)
}
func (f windowsSoftwareStoreFixture) record(t *testing.T) ([]byte, windowssoftwarejob.Record, int64) {
	t.Helper()
	var raw []byte
	var rejected int64
	if err := f.store.db.QueryRow(`SELECT body,rejected_clock_floor FROM enrollment_windows_software_job_records WHERE invitation_id=?`, f.snapshot.InvitationID).Scan(&raw, &rejected); err != nil {
		t.Fatal(err)
	}
	r, err := windowssoftwarejob.DecodeRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, r, rejected
}
func (f windowsSoftwareStoreFixture) transaction(ctx context.Context, at time.Time, fn func(*windowssoftwarejob.Record, windowssoftwarejob.Current, time.Time) error) (windowssoftwarejob.Record, time.Time, error) {
	return f.store.WindowsSoftwareJobTransaction(ctx, f.consent.Binding, f.key.Public().(ed25519.PublicKey), at, fn)
}
func softwareStoreNoop(*windowssoftwarejob.Record, windowssoftwarejob.Current, time.Time) error {
	return nil
}

func TestWindowsSoftwareJobSetupIsFreshExplicitAndPreservesLegacyBytes(t *testing.T) {
	f := newWindowsSoftwareStoreFixture(t, false)
	ctx := context.Background()
	var before []byte
	if err := f.store.db.QueryRow(`SELECT body FROM enrollment_credentials WHERE invitation_id=?`, f.snapshot.InvitationID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := f.store.OpenWindowsSoftwareJobs(ctx, f.key.Public().(ed25519.PublicKey)); !errors.Is(err, windowssoftwarejob.ErrUnavailable) {
		t.Fatal("open initialized missing scope", err)
	}
	if _, _, err := f.transaction(ctx, f.at, softwareStoreNoop); !errors.Is(err, windowssoftwarejob.ErrUnavailable) {
		t.Fatal("transaction initialized missing scope", err)
	}
	var after []byte
	if err := f.store.db.QueryRow(`SELECT body FROM enrollment_credentials WHERE invitation_id=?`, f.snapshot.InvitationID).Scan(&after); err != nil || !bytes.Equal(before, after) {
		t.Fatal("absent access rewrote old credential", err)
	}
	if err := f.setup(); err != nil {
		t.Fatal(err)
	}
	if err := f.setup(); !errors.Is(err, windowssoftwarejob.ErrConflict) {
		t.Fatal("repeated setup adopted used state", err)
	}
	if err := f.store.db.QueryRow(`SELECT body FROM enrollment_credentials WHERE invitation_id=?`, f.snapshot.InvitationID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	var c credential
	if json.Unmarshal(after, &c) != nil || c.WindowsSoftwareJobSetup == nil {
		t.Fatal("no reciprocal marker")
	}
	c.WindowsSoftwareJobSetup = nil
	legacy, _ := json.Marshal(c)
	if !bytes.Equal(before, legacy) {
		t.Fatal("setup changed legacy receipt/credential bytes")
	}
	_, r, rejected := f.record(t)
	if r.Consent != f.consent || !bytes.Equal(r.ExecutorPublicKey, f.executor.Public().(ed25519.PublicKey)) || r.Sequence != 0 || len(r.Jobs) != 0 || rejected != 0 {
		t.Fatal("incorrect fresh record")
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(f.path, f.fixture.config, f.fixture.issuerDER)
	if err != nil {
		t.Fatal("reopen", err)
	}
	defer reopened.Close()
	if err = reopened.OpenWindowsSoftwareJobs(ctx, f.key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsSoftwareJobSetupRejectsImplicitConsentAndKeyReuse(t *testing.T) {
	for _, kind := range []string{"disabled", "unchecked", "observer-key", "issuer-key", "executor-is-manager", "wrong-anchor", "past-consent"} {
		t.Run(kind, func(t *testing.T) {
			f := newWindowsSoftwareStoreFixture(t, false)
			key, executor, c := f.key.Public().(ed25519.PublicKey), f.executor.Public().(ed25519.PublicKey), f.consent
			switch kind {
			case "disabled":
				c.Enabled = false
			case "unchecked":
				c.Acknowledged = false
			case "observer-key":
				key = f.fixture.key.Public().(ed25519.PublicKey)
				c.Binding.KeyID = actionpermit.Digest(key)
			case "issuer-key":
				key = f.fixture.issuerKey.Public().(ed25519.PublicKey)
				c.Binding.KeyID = actionpermit.Digest(key)
			case "executor-is-manager":
				executor = key
				c.Binding.ExecutorKeyID = c.Binding.KeyID
			case "wrong-anchor":
				c.Binding.IncarnationDigest = actionpermit.Digest([]byte("other certificate"))
			case "past-consent":
				c.ExpiresAt = f.at.Unix()
			}
			if err := f.store.SetupWindowsSoftwareJobsCreateOnly(context.Background(), key, executor, c, f.at); err == nil {
				t.Fatal("invalid setup accepted")
			}
			if err := f.store.OpenWindowsSoftwareJobs(context.Background(), f.key.Public().(ed25519.PublicKey)); !errors.Is(err, windowssoftwarejob.ErrUnavailable) {
				t.Fatal("failed setup left grant", err)
			}
		})
	}
}

func TestWindowsSoftwareJobBusinessRejectionOnlyPersistsTime(t *testing.T) {
	for _, rejection := range []error{windowssoftwarejob.ErrExpired, windowssoftwarejob.ErrAuthority, windowssoftwarejob.ErrConflict, windowssoftwarejob.ErrInvalid} {
		t.Run(rejection.Error(), func(t *testing.T) {
			f := newWindowsSoftwareStoreFixture(t, true)
			before, _, _ := f.record(t)
			observed := f.at.Add(time.Minute)
			out, at, err := f.transaction(context.Background(), observed, func(r *windowssoftwarejob.Record, c windowssoftwarejob.Current, now time.Time) error {
				if c.Binding != f.consent.Binding || c.LeafGeneration != 1 || c.LeafDigest != f.consent.Binding.IncarnationDigest || c.LeafNotAfter != f.snapshot.Intent.NotAfter || c.Revoked || !c.Enabled || !now.Equal(observed) {
					t.Fatal("wrong live authority")
				}
				r.Consent.Enabled = false
				return rejection
			})
			if !errors.Is(err, rejection) || out.Version != "" || !at.Equal(observed) {
				t.Fatal("rejection escaped", err)
			}
			after, _, floor := f.record(t)
			if !bytes.Equal(before, after) || floor != observed.Unix() {
				t.Fatal("rejection changed job bytes or lost floor")
			}
			if _, _, err := f.transaction(context.Background(), f.at, func(*windowssoftwarejob.Record, windowssoftwarejob.Current, time.Time) error {
				t.Fatal("rollback called callback")
				return nil
			}); !errors.Is(err, windowssoftwarejob.ErrExpired) {
				t.Fatal("floor rolled back", err)
			}
			if err = f.store.OpenWindowsSoftwareJobs(context.Background(), f.key.Public().(ed25519.PublicKey)); err != nil {
				t.Fatal("rejection made store unreadable", err)
			}
		})
	}
}

func TestWindowsSoftwareJobFinalAuthorityExpiryAndClockRollback(t *testing.T) {
	for _, kind := range []string{"leaf-expiry", "challenge-expiry", "clock-rollback", "invalid-clock"} {
		t.Run(kind, func(t *testing.T) {
			f := newWindowsSoftwareStoreFixture(t, true)
			initial := f.at.Add(time.Second)
			m, err := windowssoftwarejob.OpenTransactional(context.Background(), f.store, f.consent.Binding, f.key, func() time.Time { return initial })
			if err != nil {
				t.Fatal(err)
			}
			before, _, _ := f.record(t)
			final := initial.Add(121 * time.Second)
			switch kind {
			case "leaf-expiry":
				final = time.Unix(f.snapshot.Intent.NotAfter, 0).UTC()
			case "clock-rollback":
				final = initial.Add(-time.Second)
			case "invalid-clock":
				final = time.Time{}
			}
			calls := 0
			ctx := WithOverviewClock(context.Background(), func() time.Time {
				calls++
				if calls == 1 {
					return initial
				}
				return final
			})
			err = m.Request(ctx, f.consent.Binding.DeviceID, id("operator", 4), id("software", 4), preparedMSITestSelection())
			if err == nil || calls < 2 {
				t.Fatal("final rejection bypassed", err, calls)
			}
			after, r, floor := f.record(t)
			observed := initial.Unix()
			if final.Unix() > observed {
				observed = final.Unix()
			}
			if !bytes.Equal(before, after) || len(r.Jobs) != 0 || floor != observed {
				t.Fatal("final rejection consumed work or lost observation")
			}
			if err = f.store.OpenWindowsSoftwareJobs(context.Background(), f.key.Public().(ed25519.PublicKey)); err != nil {
				t.Fatal("rejection corrupted history", err)
			}
			if _, _, err = f.transaction(context.Background(), f.at, softwareStoreNoop); !errors.Is(err, windowssoftwarejob.ErrExpired) {
				t.Fatal("rejected future revived", err)
			}
		})
	}
}

func TestWindowsSoftwareJobMissingUsedStateNeverReconstructed(t *testing.T) {
	for _, kind := range []string{"row", "meta", "marker", "tables"} {
		t.Run(kind, func(t *testing.T) {
			f := newWindowsSoftwareStoreFixture(t, true)
			switch kind {
			case "row":
				_, _ = f.store.db.Exec(`DELETE FROM enrollment_windows_software_job_records`)
			case "meta":
				_, _ = f.store.db.Exec(`DELETE FROM enrollment_windows_software_job_meta`)
			case "tables":
				_, _ = f.store.db.Exec(`DROP TABLE enrollment_windows_software_job_records`)
				_, _ = f.store.db.Exec(`DROP TABLE enrollment_windows_software_job_meta`)
			case "marker":
				var raw []byte
				if err := f.store.db.QueryRow(`SELECT body FROM enrollment_credentials WHERE invitation_id=?`, f.snapshot.InvitationID).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var c credential
				if json.Unmarshal(raw, &c) != nil {
					t.Fatal("decode")
				}
				c.WindowsSoftwareJobSetup = nil
				raw, _ = json.Marshal(c)
				if _, err := f.store.db.Exec(`UPDATE enrollment_credentials SET body=? WHERE invitation_id=?`, raw, f.snapshot.InvitationID); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.store.OpenWindowsSoftwareJobs(context.Background(), f.key.Public().(ed25519.PublicKey)); err == nil {
				t.Fatal("opened damaged used state")
			}
			if err := f.setup(); err == nil {
				t.Fatal("setup reconstructed used state")
			}
			if err := f.store.RegisterWindowsSoftwareDeviceCreateOnly(context.Background(), f.key.Public().(ed25519.PublicKey), f.executor.Public().(ed25519.PublicKey), f.consent, f.at); err == nil {
				t.Fatal("additional registration reconstructed missing used state")
			}
			if out, _, err := f.transaction(context.Background(), f.at, func(*windowssoftwarejob.Record, windowssoftwarejob.Current, time.Time) error {
				t.Fatal("damaged state called callback")
				return nil
			}); !errors.Is(err, windowssoftwarejob.ErrUncertain) || out.Version != "" {
				t.Fatal("damage not fail-closed", err)
			}
		})
	}
}

func TestWindowsSoftwareJobMarkerImmutable(t *testing.T) {
	f := newWindowsSoftwareStoreFixture(t, true)
	for _, remove := range []bool{false, true} {
		err := f.store.transact(context.Background(), func(tx *transaction) error {
			c := tx.credentials[f.snapshot.InvitationID]
			if remove {
				c.WindowsSoftwareJobSetup = nil
			} else {
				c.WindowsSoftwareJobSetup.Consent.ExpiresAt++
			}
			tx.credentials[f.snapshot.InvitationID] = c
			return nil
		})
		if err == nil {
			t.Fatal("immutable marker changed")
		}
	}
	if err := f.store.OpenWindowsSoftwareJobs(context.Background(), f.key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsSoftwareJobCurrentLeafRetirementKeepsAnchor(t *testing.T) {
	f := newWindowsSoftwareStoreFixture(t, true)
	intent := f.anchor.Intent()
	intent.IntentID, intent.RequestID, intent.SerialHex = id("intent", 203), id("request", 203), "000000000000000000000000000000cb"
	intent.NotAfter += 86400
	current := f.fixture.issue(t, intent)
	stop := errors.New("authority-only rollback")
	err := f.store.transact(context.Background(), func(tx *transaction) error {
		c := tx.credentials[f.snapshot.InvitationID]
		c.Renewal = &renewalRecord{Current: renewalLeaf{Intent: current.Intent(), DER: current.DER(), CertificateHash: current.CertificateHash(), Generation: 2, ActivatedAt: f.at.Unix(), RequestID: intent.RequestID}, UpdatedAt: f.at.Unix()}
		tx.credentials[f.snapshot.InvitationID] = c
		authority, err := f.store.windowsSoftwareJobCurrent(tx, f.snapshot.InvitationID, f.consent.Binding, f.consent, f.at)
		if err != nil || authority.Binding.IncarnationDigest != f.consent.Binding.IncarnationDigest || authority.LeafDigest != "sha256:"+current.CertificateHash() || authority.LeafGeneration != 2 {
			t.Fatal("anchor/current conflated", err)
		}
		tx.ctx = WithAuthenticatedCertificate(context.Background(), f.snapshot.Issuance.CertificateHash)
		if _, err = f.store.windowsSoftwareJobCurrent(tx, f.snapshot.InvitationID, f.consent.Binding, f.consent, f.at); !errors.Is(err, windowssoftwarejob.ErrAuthority) {
			t.Fatal("retired transport accepted", err)
		}
		tx.ctx = WithAuthenticatedCertificate(context.Background(), current.CertificateHash())
		if _, err = f.store.windowsSoftwareJobCurrent(tx, f.snapshot.InvitationID, f.consent.Binding, f.consent, time.Unix(f.snapshot.Intent.NotAfter+1, 0)); err != nil {
			t.Fatal("renewed current denied at anchor expiry", err)
		}
		if _, err = f.store.windowsSoftwareJobCurrent(tx, f.snapshot.InvitationID, f.consent.Binding, f.consent, time.Unix(intent.NotAfter, 0)); !errors.Is(err, windowssoftwarejob.ErrExpired) {
			t.Fatal("current expiry bypassed", err)
		}
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatal(err)
	}
}

func windowsSoftwareStoreApproved(t *testing.T, f windowsSoftwareStoreFixture) (*windowssoftwarejob.Manager, string) {
	t.Helper()
	ctx := context.Background()
	m, err := windowssoftwarejob.OpenTransactional(ctx, f.store, f.consent.Binding, f.key, func() time.Time { return f.at })
	if err != nil {
		t.Fatal(err)
	}
	job, actor := id("software", 9), id("operator", 9)
	if err = m.ConfigureOperatorPolicy(func(candidate string) bool { return candidate == actor }); err != nil {
		t.Fatal("operator policy", err)
	}
	selection := preparedMSITestSelection()
	if err = m.Request(ctx, f.consent.Binding.DeviceID, actor, job, selection); err != nil {
		t.Fatal("request", err)
	}
	challengeRaw, err := m.ClaimReadiness(ctx, job)
	if err != nil {
		t.Fatal("readiness claim", err)
	}
	challenge, err := windowssoftwarejob.VerifyChallenge(challengeRaw, f.key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	readiness := windowssoftwarejob.Readiness{Selection: selection, CapturedAt: f.at.Unix(), PackageVerified: windowssoftwarejob.Yes, MachineAbsent: windowssoftwarejob.Yes, InstallerBusy: windowssoftwarejob.No, NativeAcceptance: windowssoftwarejob.Yes, PackageReviewAccepted: windowssoftwarejob.Yes, MaintenanceWindowEnd: f.at.Unix() + 600}
	statement := windowssoftwarejob.Statement{Version: windowssoftwarejob.RelayVersion, Kind: "readiness", Binding: f.consent.Binding, JobID: job, ReferenceDigest: actionpermit.Digest(challengeRaw), Deadline: challenge.Deadline, IssuedAt: f.at.Unix(), ExpiresAt: f.at.Unix() + 60, Readiness: &readiness}
	raw, err := windowssoftwarejob.SignStatement(statement, f.executor)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Report(ctx, raw); err != nil {
		t.Fatal("readiness report", err)
	}
	view, err := m.View(ctx, f.consent.Binding.DeviceID, actor)
	if err != nil || view.Job == nil || view.Job.Preview == nil {
		t.Fatal("preview", err)
	}
	if err = m.Approve(ctx, f.consent.Binding.DeviceID, actor, job, view.Job.Preview.Digest, true); err != nil {
		t.Fatal("approval", err)
	}
	return m, job
}

func TestWindowsSoftwareJobSignedLifecycleConsumeOnceAndHistoryPreserved(t *testing.T) {
	f := newWindowsSoftwareStoreFixture(t, true)
	m, job := windowsSoftwareStoreApproved(t, f)
	ctx := context.Background()
	permitRaw, err := m.Claim(ctx, job)
	if err != nil || len(permitRaw) == 0 {
		t.Fatal("claim", err)
	}
	if again, err := m.Claim(ctx, job); !errors.Is(err, windowssoftwarejob.ErrConsumed) || len(again) != 0 {
		t.Fatal("claim redelivered", err)
	}
	permit, err := windowssoftwarejob.Verify(permitRaw, f.key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	result := windowssoftwarejob.Result{JobID: job, EnvelopeDigest: actionpermit.Digest(permitRaw), Attempted: true, Outcome: "succeeded", ReturnCode: 0, ReturnCodeKnown: true, RegistrationVerified: windowssoftwarejob.Yes, CompletedAt: f.at.Unix()}
	if err = m.Submit(ctx, result); !errors.Is(err, windowssoftwarejob.ErrAuthority) {
		t.Fatal("unsigned transactional result accepted", err)
	}
	statement := windowssoftwarejob.Statement{Version: windowssoftwarejob.RelayVersion, Kind: "result", Binding: f.consent.Binding, JobID: job, ReferenceDigest: result.EnvelopeDigest, Deadline: permit.Preview.ExpiresAt, IssuedAt: f.at.Unix(), ExpiresAt: f.at.Unix() + 60, Result: &result}
	raw, err := windowssoftwarejob.SignStatement(statement, f.executor)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Report(ctx, raw); err != nil {
		t.Fatal("result", err)
	}
	if err = m.Report(ctx, raw); err != nil {
		t.Fatal("exact result retry", err)
	}
	before, saved, _ := f.record(t)
	if len(saved.Jobs) != 1 || saved.Jobs[0].State != "complete" || !bytes.Equal(saved.Jobs[0].Envelope, permitRaw) || !bytes.Equal(saved.Jobs[0].ResultReport, raw) {
		t.Fatal("signed history changed")
	}
	if _, _, err = f.transaction(ctx, f.at.Add(time.Second), func(r *windowssoftwarejob.Record, _ windowssoftwarejob.Current, _ time.Time) error {
		r.Jobs = []windowssoftwarejob.Job{}
		r.Sequence = 0
		return nil
	}); err == nil {
		t.Fatal("callback pruned used signed history")
	}
	after, _, floor := f.record(t)
	if !bytes.Equal(before, after) || floor != f.at.Unix()+1 {
		t.Fatal("rejected pruning changed history/floor")
	}
	if err = f.store.Close(); err != nil {
		t.Fatal(err)
	}
	f.store, err = Open(f.path, f.fixture.config, f.fixture.issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	defer f.store.Close()
	m, err = windowssoftwarejob.OpenTransactional(ctx, f.store, f.consent.Binding, f.key, func() time.Time { return f.at.Add(time.Second) })
	if err != nil {
		t.Fatal("reopen", err)
	}
	if err = m.ConfigureOperatorPolicy(func(candidate string) bool { return candidate == id("operator", 9) }); err != nil {
		t.Fatal("reopen operator policy", err)
	}
	if again, err := m.Claim(ctx, job); !errors.Is(err, windowssoftwarejob.ErrConsumed) || len(again) != 0 {
		t.Fatal("restart redelivered", err)
	}
}

func TestWindowsSoftwareJobFinalClaimExpiryPreservesExactApproval(t *testing.T) {
	f := newWindowsSoftwareStoreFixture(t, true)
	m, job := windowsSoftwareStoreApproved(t, f)
	before, saved, _ := f.record(t)
	final := time.Unix(saved.Jobs[0].Preview.ExpiresAt, 0).UTC()
	calls := 0
	ctx := WithOverviewClock(context.Background(), func() time.Time {
		calls++
		if calls == 1 {
			return f.at
		}
		return final
	})
	if raw, err := m.Claim(ctx, job); !errors.Is(err, windowssoftwarejob.ErrExpired) || len(raw) != 0 {
		t.Fatal("expired final claim escaped", err)
	}
	after, r, rejected := f.record(t)
	if !bytes.Equal(before, after) || r.Jobs[0].ClaimedAt != 0 || r.Jobs[0].State != "approved" || rejected != final.Unix() {
		t.Fatal("final rejection consumed or changed approval")
	}
	if raw, err := m.Claim(context.Background(), job); !errors.Is(err, windowssoftwarejob.ErrExpired) || len(raw) != 0 {
		t.Fatal("expired claim revived", err)
	}
}

func TestWindowsSoftwareJobRevocationOnlyAdvancesRejectionFloor(t *testing.T) {
	f := newWindowsSoftwareStoreFixture(t, true)
	before, _, _ := f.record(t)
	control := f.fixture.control(f.snapshot, 204)
	control.Now = f.at.Unix() + 1
	if _, err := f.store.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: control, State: enrollmentstate.Revoked}); err != nil {
		t.Fatal("revocation", err)
	}
	observed := f.at.Add(2 * time.Second)
	if out, _, err := f.transaction(context.Background(), observed, func(*windowssoftwarejob.Record, windowssoftwarejob.Current, time.Time) error {
		t.Fatal("revoked callback called")
		return nil
	}); !errors.Is(err, windowssoftwarejob.ErrAuthority) || out.Version != "" {
		t.Fatal("revoked authority accepted", err)
	}
	after, _, rejected := f.record(t)
	if !bytes.Equal(before, after) || rejected != observed.Unix() {
		t.Fatal("revocation rejection modified jobs/lost floor")
	}
	if err := f.store.OpenWindowsSoftwareJobs(context.Background(), f.key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal("revocation lost history", err)
	}
}

func TestWindowsSoftwareJobServiceActionKeyDomainIsSeparate(t *testing.T) {
	s, serviceKey, serviceBinding, at, _, _ := windowsActionFixture(t)
	key := ed25519.PrivateKey(serviceKey).Public().(ed25519.PublicKey)
	executor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{117}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	binding := windowssoftwarejob.Binding{ManagerID: serviceBinding.ManagerID, DeviceID: serviceBinding.EndpointID, IncarnationDigest: serviceBinding.IncarnationDigest, ExecutorID: id("executor", 7), ExecutorKeyID: actionpermit.Digest(executor), GrantID: id("grant", 7), KeyID: actionpermit.Digest(key)}
	consent := windowssoftwarejob.Consent{Package: preparedMSITestSelection(), NativeAcceptanceDigest: actionpermit.Digest([]byte("native acceptance")), PackageReviewAccepted: true, Version: windowssoftwarejob.ConsentVersion, Scope: windowssoftwarejob.Scope, Binding: binding, Enabled: true, Acknowledged: true, ExpiresAt: at.Unix() + 3600}
	if err := s.SetupWindowsSoftwareJobsCreateOnly(context.Background(), key, executor, consent, at); !errors.Is(err, windowssoftwarejob.ErrAuthority) {
		t.Fatal("service action key promoted", err)
	}
	if err := s.OpenWindowsSoftwareJobs(context.Background(), key); !errors.Is(err, windowssoftwarejob.ErrUnavailable) {
		t.Fatal("service actions implied update grant", err)
	}
}

func TestWindowsSoftwareJobSuccessfulFinalClockAndConsentStayFixed(t *testing.T) {
	f := newWindowsSoftwareStoreFixture(t, true)
	initial, final := f.at.Add(time.Second), f.at.Add(2*time.Second)
	calls := 0
	ctx := WithOverviewClock(context.Background(), func() time.Time {
		calls++
		if calls == 1 {
			return initial
		}
		return final
	})
	out, at, err := f.transaction(ctx, initial, softwareStoreNoop)
	if err != nil || out.ClockFloor != final.Unix() || !at.Equal(final) || out.Consent != f.consent {
		t.Fatal("final success clock/consent", err)
	}
	_, saved, rejected := f.record(t)
	if saved.ClockFloor != final.Unix() || rejected != 0 {
		t.Fatal("success floor not durable")
	}
	if _, _, err = f.transaction(context.Background(), initial, softwareStoreNoop); !errors.Is(err, windowssoftwarejob.ErrExpired) {
		t.Fatal("successful final floor rolled back", err)
	}
}

func TestWindowsSoftwareJobRestoredApprovalRequiresOriginalOperator(t *testing.T) {
	f := newWindowsSoftwareStoreFixture(t, true)
	_, job := windowsSoftwareStoreApproved(t, f)
	before, _, _ := f.record(t)
	m, err := windowssoftwarejob.OpenTransactional(context.Background(), f.store, f.consent.Binding, f.key, func() time.Time { return f.at })
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := m.Claim(context.Background(), job); !errors.Is(err, windowssoftwarejob.ErrAuthority) || len(raw) != 0 {
		t.Fatal("missing current operator policy accepted", err)
	}
	if err = m.ConfigureOperatorPolicy(func(candidate string) bool { return candidate == id("operator", 10) }); err != nil {
		t.Fatal(err)
	}
	if raw, err := m.Claim(context.Background(), job); !errors.Is(err, windowssoftwarejob.ErrAuthority) || len(raw) != 0 {
		t.Fatal("replacement operator policy adopted approval", err)
	}
	after, r, _ := f.record(t)
	if !bytes.Equal(before, after) || r.Jobs[0].State != "approved" || r.Jobs[0].ClaimedAt != 0 {
		t.Fatal("denied operator consumed approval")
	}
}

func TestWindowsSoftwareJobDynamicAuthorityLossAtFinalCommit(t *testing.T) {
	for _, kind := range []string{"operator", "configuration"} {
		t.Run(kind, func(t *testing.T) {
			f := newWindowsSoftwareStoreFixture(t, true)
			_, job := windowsSoftwareStoreApproved(t, f)
			allowed := true
			configCheck := func() error {
				if kind == "configuration" && !allowed {
					return windowssoftwarejob.ErrAuthority
				}
				return nil
			}
			m, err := windowssoftwarejob.OpenTransactional(context.Background(), f.store, f.consent.Binding, f.key, func() time.Time { return f.at }, configCheck)
			if err != nil {
				t.Fatal(err)
			}
			if err = m.ConfigureOperatorPolicy(func(actor string) bool { return actor == id("operator", 9) && (kind != "operator" || allowed) }); err != nil {
				t.Fatal(err)
			}
			before, _, _ := f.record(t)
			calls := 0
			ctx := WithOverviewClock(context.Background(), func() time.Time {
				calls++
				if calls >= 2 {
					allowed = false
				}
				return f.at
			})
			raw, err := m.Claim(ctx, job)
			if !errors.Is(err, windowssoftwarejob.ErrAuthority) || len(raw) != 0 {
				t.Fatal("final dynamic authority loss released a permit", kind, err)
			}
			after, saved, rejected := f.record(t)
			if !bytes.Equal(before, after) || saved.Jobs[0].State != "approved" || saved.Jobs[0].ClaimedAt != 0 || rejected != f.at.Unix() {
				t.Fatal("final denial changed signed job or lost rejection floor")
			}
		})
	}
}

func TestWindowsSoftwareJobReadinessSequenceCannotRollbackOrReuse(t *testing.T) {
	f := newWindowsSoftwareStoreFixture(t, true)
	_, before, _ := f.record(t)
	challenge := windowssoftwarejob.Challenge{Version: windowssoftwarejob.RelayVersion, Binding: f.consent.Binding, JobID: id("software", 7), Selection: preparedMSITestSelection(), IssuedAt: f.at.Unix(), Deadline: f.at.Unix() + 120, Sequence: 1}
	raw, err := windowssoftwarejob.SignChallenge(challenge, f.key)
	if err != nil {
		t.Fatal(err)
	}
	after := before
	after.ReadinessSequence = 1
	after.Jobs = []windowssoftwarejob.Job{{Challenge: raw}}
	if err = windowsSoftwareJobTransition(before, after, f.at.Unix()); err != nil {
		t.Fatal("fresh sequence rejected", err)
	}
	before = after
	after.ReadinessSequence = 0
	if err = windowsSoftwareJobTransition(before, after, f.at.Unix()); err == nil {
		t.Fatal("readiness floor rolled back")
	}
	after.ReadinessSequence = 1
	challenge.JobID = id("software", 8)
	raw, _ = windowssoftwarejob.SignChallenge(challenge, f.key)
	after.Jobs = []windowssoftwarejob.Job{{Challenge: raw}}
	if err = windowsSoftwareJobTransition(before, after, f.at.Unix()); err == nil {
		t.Fatal("replacement reused signed sequence")
	}
	challenge.Sequence = 2
	raw, _ = windowssoftwarejob.SignChallenge(challenge, f.key)
	after.ReadinessSequence = 2
	after.Jobs = []windowssoftwarejob.Job{{Challenge: raw}}
	if err = windowsSoftwareJobTransition(before, after, f.at.Unix()); err != nil {
		t.Fatal("same-second newer sequence rejected", err)
	}
}

func preparedMSITestSelection() windowssoftwarejob.Selection {
	return windowssoftwarejob.Selection{SHA256: actionpermit.Digest([]byte("fixture")), Size: 1024, ProductCode: "{11111111-2222-3333-4444-555555555555}", PackageCode: "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", Version: "1.2.3", Architecture: "amd64", Name: "Fixture package", TermsReviewDigest: actionpermit.Digest([]byte("terms")), ReviewReference: "Fixture review"}
}

func TestWindowsSoftwareAndWUAManagerExecutorKeysNeverCrossDomains(t *testing.T) {
	for _, first := range []string{"software", "wua"} {
		for _, reuse := range []string{"manager", "executor"} {
			t.Run(first+"_"+reuse, func(t *testing.T) {
				if first == "software" {
					f := newWindowsSoftwareStoreFixture(t, true)
					manager := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{115}, 32)).Public().(ed25519.PublicKey)
					executor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{116}, 32)).Public().(ed25519.PublicKey)
					if reuse == "manager" {
						manager = f.key.Public().(ed25519.PublicKey)
					} else {
						executor = f.executor.Public().(ed25519.PublicKey)
					}
					b := windowsupdatejob.Binding(f.consent.Binding)
					b.KeyID = actionpermit.Digest(manager)
					b.ExecutorKeyID = actionpermit.Digest(executor)
					c := windowsupdatejob.Consent{Version: windowsupdatejob.ConsentVersion, Scope: windowsupdatejob.Scope, Binding: b, Enabled: true, Acknowledged: true, ExpiresAt: f.consent.ExpiresAt}
					if e := f.store.SetupWindowsUpdateJobsCreateOnly(context.Background(), manager, executor, c, f.at); e == nil {
						t.Fatal("MSI key reused by WUA")
					}
				} else {
					f := newWindowsUpdateStoreFixture(t, true)
					manager := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{115}, 32)).Public().(ed25519.PublicKey)
					executor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{116}, 32)).Public().(ed25519.PublicKey)
					if reuse == "manager" {
						manager = f.key.Public().(ed25519.PublicKey)
					} else {
						executor = f.executor.Public().(ed25519.PublicKey)
					}
					b := windowssoftwarejob.Binding(f.consent.Binding)
					b.KeyID = actionpermit.Digest(manager)
					b.ExecutorKeyID = actionpermit.Digest(executor)
					c := windowssoftwarejob.Consent{Package: preparedMSITestSelection(), NativeAcceptanceDigest: actionpermit.Digest([]byte("native acceptance")), PackageReviewAccepted: true, Version: windowssoftwarejob.ConsentVersion, Scope: windowssoftwarejob.Scope, Binding: b, Enabled: true, Acknowledged: true, ExpiresAt: f.consent.ExpiresAt}
					if e := f.store.SetupWindowsSoftwareJobsCreateOnly(context.Background(), manager, executor, c, f.at); e == nil {
						t.Fatal("WUA key reused by MSI")
					}
				}
			})
		}
	}
}
