package enrollmentclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/lanclient"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type Options struct {
	// ClaimOnly returns only after a fresh bound-key status confirms commitment.
	// ResumeOnly opens an existing service-bound identity and never claims/prompts.
	ClaimOnly, ResumeOnly    bool
	StateDirectory           string
	InsecureHTTPAcknowledged bool
	// WindowsInventoryAcknowledged is required for fresh Windows inventory setup.
	// ResumeOnly validates an existing service-bound identity without changing scope.
	WindowsInventoryAcknowledged bool
	Display                      func(TrustDisplay) error
	// Secret returns fresh invitation bytes in memory, only after Display succeeds.
	// The client clears the returned slice; the callback must not log or save it.
	Secret       func(context.Context) ([]byte, error)
	Notify       func(Progress) error
	PollInterval time.Duration // default 5s; supported 2s–30s
	Timeout      time.Duration // default 15m; at most 30m
}
type Progress struct {
	Phase          string
	KeyFingerprint string
	ComparisonCode string
	HTTPTest       bool
}
type Result struct {
	Pending        bool // A saved committed claim, not approval, activation or reporting.
	Config         lanclient.Config
	ConfigPath     string
	KeyFingerprint string
	ComparisonCode string
	// False for HTTP-test even after a response says activation succeeded.
	ServerAuthenticated bool
}

type ledger struct{ *ledgerData }

type ledgerData struct {
	Version                     string                  `json:"version"`
	Bootstrap                   Bootstrap               `json:"bootstrap"`
	Seed                        string                  `json:"seed"`
	CSR                         string                  `json:"csr"`
	ClaimID                     string                  `json:"claimId"`
	ClaimRequestID              string                  `json:"claimRequestId"`
	StatusRequestID             string                  `json:"statusRequestId"`
	CredentialRequestID         string                  `json:"credentialRequestId"`
	ActivationRequestID         string                  `json:"activationRequestId"`
	ClaimHash                   string                  `json:"claimHash"`
	ClaimDefinitelyRejected     bool                    `json:"claimDefinitelyRejected"`
	AmbiguousClaimHash          string                  `json:"ambiguousClaimHash"`
	ClaimConfirmed              bool                    `json:"claimConfirmed"`
	LastRevision                uint64                  `json:"lastRevision"`
	Intent                      enrollmentcrypto.Intent `json:"intent"`
	CertificateDER              string                  `json:"certificateDer"`
	ActivationAttempted         bool                    `json:"activationAttempted"`
	Activated                   bool                    `json:"activated"`
	HandoffPrepared             bool                    `json:"handoffPrepared"`
	SenderInitializationStarted bool                    `json:"senderInitializationStarted"`
}

const ledgerVersion = "tracebolt.enrollment-client-state.v2"

type session struct{ *sessionData }

type sessionData struct {
	store                     *localStore
	l                         ledger
	opts                      Options
	key                       ed25519.PrivateKey
	publicDER, csr, issuerDER []byte
	trust                     TrustDisplay
	wire                      *wireClient
	service                   *serviceEnrollment
}

// Run resumes the same locally bound operation after interruption. It never
// resets keys/state or installs anything. Uncertain network outcomes reconcile
// with a fresh bound-key status proof; only uncommitted claims ask for the secret.
func Run(ctx context.Context, b Bootstrap, o Options) (Result, error) {
	if o.ClaimOnly && o.ResumeOnly || o.ResumeOnly && o.Secret != nil || !o.ResumeOnly && (b.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory) != o.WindowsInventoryAcknowledged {
		return Result{}, ErrBootstrap
	}
	if ctx == nil || validatePlatformBootstrap(b, runtime.GOOS) != nil || o.Display == nil || !filepath.IsAbs(o.StateDirectory) || filepath.Clean(o.StateDirectory) != o.StateDirectory {
		return Result{}, ErrBootstrap
	}
	if (b.Profile == "http-test") != o.InsecureHTTPAcknowledged {
		return Result{}, ErrBootstrap
	}
	if o.Timeout == 0 {
		o.Timeout = 15 * time.Minute
	}
	if o.PollInterval == 0 {
		o.PollInterval = 5 * time.Second
	}
	if o.Timeout < time.Second || o.Timeout > 30*time.Minute || o.PollInterval < 2*time.Second || o.PollInterval > 30*time.Second {
		return Result{}, ErrBootstrap
	}
	trust, err := validateBootstrap(b, time.Now())
	if err != nil {
		return Result{}, err
	}
	var st *localStore
	if o.ResumeOnly {
		st, err = openExistingStore(o.StateDirectory)
	} else {
		st, err = openStore(o.StateDirectory)
	}
	if err != nil {
		return Result{}, err
	}
	defer st.Close()
	s := &session{&sessionData{store: st, opts: o, trust: trust}}
	defer func() { clear(s.key) }()
	if err = s.load(b); err != nil {
		return Result{}, err
	}
	s.trust.KeyFingerprint = fingerprint(s.publicDER)
	s.trust.ComparisonCode, err = enrollmentcrypto.ComparisonCode(b.ManagerInstanceID, b.InvitationID, s.l.ClaimID, s.trust.KeyFingerprint)
	if err != nil {
		return Result{}, ErrState
	}
	if err = s.loadService(o.ResumeOnly); err != nil {
		return Result{}, err
	}
	if err = s.enforceServiceDeadline(time.Now()); err != nil {
		return Result{}, err
	}
	// No socket is opened until public trust and locally generated identity display.
	if o.Display(s.trust) != nil {
		return Result{}, ErrInput
	}
	c, err := lanclient.NewBootstrapHTTPClient(b.EnrollmentOrigin, b.Profile, []byte(b.ServerCAPEM))
	if err != nil {
		return Result{}, ErrBootstrap
	}
	defer c.CloseIdleConnections()
	s.wire = &wireClient{client: c, origin: b.EnrollmentOrigin, collectionProfile: b.CollectionProfile}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	if s.service != nil && !s.l.Activated {
		var stopDeadline context.CancelFunc
		ctx, stopDeadline = context.WithDeadline(ctx, time.Unix(s.service.DeadlineAt, 0))
		defer stopDeadline()
	}
	delay := o.PollInterval
	for {
		if err = ctx.Err(); err != nil {
			return Result{}, s.deadlineError(err)
		}
		if err = s.enforceServiceDeadline(time.Now()); err != nil {
			return Result{}, s.deadlineError(err)
		}
		snapshot, e := s.status(ctx)
		if e != nil {
			if err = s.enforceServiceDeadline(time.Now()); err != nil {
				return Result{}, err
			}
			var failure *httpFailure
			if errors.As(e, &failure) && (failure.status == 401 || failure.status == 409) && !o.ResumeOnly && !s.l.ClaimConfirmed && s.l.CertificateDER == "" {
				if e = s.claim(ctx); e == nil {
					delay = o.PollInterval
					continue
				}
			}
			if !retryable(e) {
				return Result{}, e
			}
			if err = s.notify("reconciling"); err != nil {
				return Result{}, s.deadlineError(err)
			}
			if err = pause(ctx, retryDelay(e, delay)); err != nil {
				return Result{}, s.deadlineError(err)
			}
			delay = grow(delay)
			continue
		}
		// A response arriving after the immutable local pending deadline cannot
		// promote a previously unacknowledged activation in the background.
		if o.ClaimOnly || s.service != nil {
			if err = s.enforceServiceDeadline(time.Now()); err != nil {
				return Result{}, s.deadlineError(err)
			}
			if !s.l.Activated && (time.Now().Unix() >= snapshot.DeadlineAt || snapshot.Intent.NotAfter != 0 && time.Now().Unix() >= snapshot.Intent.NotAfter) {
				return Result{}, ErrServiceDeadline
			}
		}
		delay = o.PollInterval
		if err = s.acceptSnapshot(snapshot); err != nil {
			return Result{}, s.deadlineError(err)
		}
		if o.ClaimOnly || s.service != nil {
			if err = s.recordServiceSnapshot(snapshot, o.ClaimOnly); err != nil {
				return Result{}, s.deadlineError(err)
			}
		}
		if o.ClaimOnly && !serviceTerminal(snapshot.State) {
			return Result{Pending: true, KeyFingerprint: s.trust.KeyFingerprint, ComparisonCode: s.trust.ComparisonCode, ServerAuthenticated: b.Profile == "tls"}, nil
		}
		switch snapshot.State {
		case enrollmentstate.Expired, enrollmentstate.Canceled, enrollmentstate.Rejected, enrollmentstate.Revoked:
			return Result{}, ErrTerminal
		case enrollmentstate.ClaimedPending, enrollmentstate.Approved, enrollmentstate.IssuanceIntent:
			if err = s.notify("pending_approval"); err != nil {
				return Result{}, s.deadlineError(err)
			}
			if err = pause(ctx, delay); err != nil {
				return Result{}, s.deadlineError(err)
			}
		case enrollmentstate.Issued, enrollmentstate.Activated:
			if s.l.CertificateDER == "" {
				if err = s.enforceServiceDeadline(time.Now()); err != nil {
					return Result{}, s.deadlineError(err)
				}
				if err = s.credential(ctx, snapshot); err != nil {
					if !retryable(err) {
						return Result{}, s.deadlineError(err)
					}
					if err = pause(ctx, retryDelay(err, delay)); err != nil {
						return Result{}, s.deadlineError(err)
					}
					continue
				}
			}
			if err = s.enforceServiceDeadline(time.Now()); err != nil {
				return Result{}, s.deadlineError(err)
			}
			if err = s.matchIssuedSnapshot(snapshot); err != nil {
				return Result{}, s.deadlineError(err)
			}
			if snapshot.State == enrollmentstate.Activated {
				if !s.l.ActivationAttempted || snapshot.Activation.RequestID != s.l.ActivationRequestID {
					return Result{}, ErrResponse
				}
				if err = s.enforceServiceDeadline(time.Now()); err != nil {
					return Result{}, s.deadlineError(err)
				}
				s.l.Activated = true
				if err = s.save(); err != nil {
					return Result{}, s.deadlineError(err)
				}
				return s.publish()
			}
			if err = s.enforceServiceDeadline(time.Now()); err != nil {
				return Result{}, s.deadlineError(err)
			}
			if err = s.activate(ctx); err != nil {
				if !retryable(err) {
					return Result{}, s.deadlineError(err)
				}
				if err = pause(ctx, retryDelay(err, delay)); err != nil {
					return Result{}, s.deadlineError(err)
				}
			}
			if err = s.enforceServiceDeadline(time.Now()); err != nil {
				return Result{}, s.deadlineError(err)
			}
		default:
			return Result{}, ErrResponse
		}
	}
}
func randomID(prefix string) (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil || b == [16]byte{} {
		return "", ErrState
	}
	return prefix + hex.EncodeToString(b[:]), nil
}
func (s *session) load(b Bootstrap) error {
	raw, err := s.store.Read("ledger.json")
	if errors.Is(err, os.ErrNotExist) {
		if s.opts.ResumeOnly {
			return ErrState
		}
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return ErrState
		}
		defer clear(key)
		csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		if e != nil {
			return ErrState
		}
		seed := key.Seed()
		defer clear(seed)
		s.l = ledger{&ledgerData{Version: ledgerVersion, Bootstrap: b, Seed: base64.RawStdEncoding.EncodeToString(seed), CSR: base64.RawStdEncoding.EncodeToString(csr)}}
		for _, p := range []struct {
			dst    *string
			prefix string
		}{{&s.l.ClaimID, "claim_"}, {&s.l.ClaimRequestID, "request_"}, {&s.l.StatusRequestID, "request_"}, {&s.l.CredentialRequestID, "request_"}, {&s.l.ActivationRequestID, "request_"}} {
			*p.dst, e = randomID(p.prefix)
			if e != nil {
				return e
			}
		}
		if err = s.save(); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		defer clear(raw)
		if strictJSON(raw, &s.l) != nil {
			return ErrState
		}
	}
	if s.l.Version != ledgerVersion || s.l.Bootstrap != b {
		return ErrState
	}
	seen := map[string]bool{}
	for _, p := range [][2]string{{s.l.ClaimID, "claim_"}, {s.l.ClaimRequestID, "request_"}, {s.l.StatusRequestID, "request_"}, {s.l.CredentialRequestID, "request_"}, {s.l.ActivationRequestID, "request_"}} {
		if !enrollmentcrypto.ValidID(p[0], p[1]) || seen[p[0]] {
			return ErrState
		}
		seen[p[0]] = true
	}
	seed, e := decode64(s.l.Seed, 32)
	if e != nil || len(seed) != 32 {
		return ErrState
	}
	s.key = ed25519.NewKeyFromSeed(seed)
	clear(seed)
	if !keyvalidation.Ed25519(s.key.Public().(ed25519.PublicKey)) {
		return ErrState
	}
	s.publicDER, e = x509.MarshalPKIXPublicKey(s.key.Public())
	if e != nil {
		return ErrState
	}
	s.csr, e = decode64(s.l.CSR, enrollmentcrypto.MaxCSRBytes)
	if e != nil {
		return ErrState
	}
	csr, e := x509.ParseCertificateRequest(s.csr)
	if e != nil || csr.CheckSignature() != nil || csr.SignatureAlgorithm != x509.PureEd25519 || !bytes.Equal(csr.RawSubjectPublicKeyInfo, s.publicDER) {
		return ErrState
	}
	issuers, e := publicCertificates(b.IssuerPEM)
	if e != nil {
		return ErrState
	}
	s.issuerDER = issuers[0].Raw
	if s.l.ClaimDefinitelyRejected && (s.l.Bootstrap.Profile != "tls" || s.l.ClaimHash == "" || s.l.ClaimConfirmed || s.l.AmbiguousClaimHash != "") {
		return ErrState
	}
	if s.l.AmbiguousClaimHash != "" && (s.l.AmbiguousClaimHash != s.l.ClaimHash || !enrollmentcrypto.ValidHash(s.l.AmbiguousClaimHash) || s.l.ClaimConfirmed) {
		return ErrState
	}
	if s.l.ClaimHash != "" && !enrollmentcrypto.ValidHash(s.l.ClaimHash) || s.l.ClaimConfirmed && (s.l.ClaimHash == "" || s.l.LastRevision == 0) || !s.l.ClaimConfirmed && s.l.LastRevision != 0 {
		return ErrState
	}
	if s.l.CertificateDER != "" {
		if !s.l.ClaimConfirmed || s.verifyLocalIntent(s.l.Intent) != nil {
			return ErrState
		}
		der, e := decode64(s.l.CertificateDER, enrollmentcrypto.MaxCertificateBytes)
		if e != nil {
			return ErrState
		}
		if _, e = enrollmentcrypto.VerifyIssued(der, s.issuerDER, s.l.Intent, time.Now()); e != nil {
			return ErrState
		}
	} else if s.l.Intent != (enrollmentcrypto.Intent{}) || s.l.ActivationAttempted || s.l.Activated {
		return ErrState
	}
	if s.l.Activated && !s.l.ActivationAttempted || s.l.SenderInitializationStarted && !s.l.Activated || s.l.HandoffPrepared && !s.l.SenderInitializationStarted {
		return ErrState
	}
	return s.validateArtifacts()
}
func (s *session) save() error {
	raw, e := json.Marshal(ledgerDisk(*s.l.ledgerData))
	if e != nil {
		return ErrState
	}
	defer clear(raw)
	return s.store.Write("ledger.json", raw)
}
func decode64(raw string, max int) ([]byte, error) {
	if len(raw) > base64.RawStdEncoding.EncodedLen(max) {
		return nil, ErrResponse
	}
	b, e := base64.RawStdEncoding.Strict().DecodeString(raw)
	if e != nil || len(b) == 0 || len(b) > max || base64.RawStdEncoding.EncodeToString(b) != raw {
		return nil, ErrResponse
	}
	return b, nil
}
func (s *session) notify(phase string) error {
	if s.opts.Notify != nil && s.opts.Notify(Progress{Phase: phase, KeyFingerprint: s.trust.KeyFingerprint, ComparisonCode: s.trust.ComparisonCode, HTTPTest: s.trust.HTTPTest}) != nil {
		return ErrInput
	}
	return nil
}
func pause(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
func grow(d time.Duration) time.Duration {
	d *= 2
	if d > 30*time.Second {
		return 30 * time.Second
	}
	return d
}
