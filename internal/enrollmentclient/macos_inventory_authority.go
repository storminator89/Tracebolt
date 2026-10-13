package enrollmentclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanclient"
	sender "localrmm/internal/macosinventorysender"
	"localrmm/internal/renewalidentity"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// macOSInventoryAuthority holds the real enrollment lock across the whole
// admitted cycle. Other processes and renewal activation cannot cut over its
// credential until all synchronous collection/transport work has returned.
type macOSInventoryAuthority struct{ path string }
type macOSInventoryActive struct {
	s        *session
	ctx      context.Context
	leaf     []byte
	exchange *lanclient.MacOSInventoryExchange
}

func (*macOSInventoryAuthority) String() string {
	return "protected macOS enrollment authority (redacted)"
}
func (*macOSInventoryActive) String() string { return "active macOS enrollment authority (redacted)" }

func openMacOSInventoryEnrollment(path string) (*session, error) {
	if runtime.GOOS != "darwin" || os.Geteuid() <= 0 || !filepath.IsAbs(path) || filepath.Base(path) != "agent.json" || filepath.Clean(path) != path {
		return nil, ErrState
	}
	st, e := openEnrollmentStore(filepath.Dir(path), true, true)
	if e != nil {
		return nil, e
	}
	fail := func() (*session, error) { _ = st.Close(); return nil, ErrState }
	raw, e := st.Read("ledger.json")
	if e != nil {
		return fail()
	}
	defer clear(raw)
	var l ledger
	if strictJSON(raw, &l) != nil || l.MacOSInventory == nil || !l.Activated || !l.HandoffPrepared || !l.SenderInitializationStarted || l.Bootstrap.RenewalPolicy != "" && !l.RenewalReadyPublished {
		return fail()
	}
	s := &session{&sessionData{store: st, opts: Options{StateDirectory: filepath.Dir(path), ResumeOnly: true, inventoryEnrollment: true, inventoryAuthorityReading: true}}}
	if e = s.load(l.Bootstrap); e != nil {
		clear(s.key)
		return fail()
	}
	// Reauthenticate the immutable approved root/intermediate and initial issuance;
	// historical time is only for provenance. Check requires a live current leaf.
	if e = s.initializeMacOSInventoryTrust(); e != nil {
		clear(s.key)
		return fail()
	}
	cfg, e := st.Read("agent.json")
	if e != nil {
		clear(s.key)
		return fail()
	}
	if _, e = lanclient.ParseMacOSInventoryConfig(cfg, path); e != nil {
		clear(s.key)
		return fail()
	}
	return s, nil
}
func closeMacOSInventoryEnrollment(s *session) error {
	if s == nil {
		return nil
	}
	clear(s.key)
	return s.store.Close()
}
func (a *macOSInventoryAuthority) WithCurrent(ctx context.Context, run func(sender.ActiveAuthority) error) (result error) {
	if a == nil || ctx == nil || ctx.Err() != nil || run == nil {
		return sender.ErrAuthority
	}
	s, e := openMacOSInventoryEnrollment(a.path)
	if e != nil {
		return e
	}
	defer func() {
		if e := closeMacOSInventoryEnrollment(s); e != nil {
			result = ErrState
		}
	}()
	active := &macOSInventoryActive{s: s, ctx: ctx}
	evidence, e := active.Check(time.Now().UTC())
	if e != nil {
		return e
	}
	active.leaf = bytes.Clone(evidence.CurrentDER)
	// An authenticated bound-key status is checked before this cycle's source
	// reads. Final report/control admission repeats manager-side revocation.
	client, e := newEnrollmentHTTPClient(s.l.Bootstrap)
	if e != nil {
		return e
	}
	defer client.CloseIdleConnections()
	s.wire = &wireClient{client: client, origin: s.l.Bootstrap.EnrollmentOrigin, collectionProfile: s.l.Bootstrap.CollectionProfile}
	if e = s.checkMacOSInventoryRemote(ctx); e != nil {
		return e
	}
	if _, e = active.Check(time.Now().UTC()); e != nil {
		return e
	}
	cert, e := s.store.Read("agent-cert.pem")
	if e != nil {
		return ErrState
	}
	key, e := s.store.Read("agent-key.pem")
	if e != nil {
		return ErrState
	}
	defer clear(key)
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil || len(pair.Certificate) != 2 {
		return ErrState
	}
	pair.Certificate[0] = bytes.Clone(evidence.CurrentDER)
	pair.Leaf, e = x509.ParseCertificate(evidence.CurrentDER)
	if e != nil {
		return ErrState
	}
	ca, e := s.store.Read("server-ca.pem")
	if e != nil {
		return ErrState
	}
	x, e := lanclient.NewMacOSInventoryExchange(evidence.ManagerOrigin, pair, ca, active.leaf)
	if e != nil {
		return e
	}
	defer x.Close()
	active.exchange = x
	return run(active)
}
func (s *session) checkMacOSInventoryRemote(ctx context.Context) error {
	if s.l.Bootstrap.RenewalPolicy == "" {
		snap, e := s.status(ctx)
		if e != nil {
			return e
		}
		if snap.State != enrollmentstate.Activated || snap.Activation.RequestID != s.l.ActivationRequestID {
			return ErrTerminal
		}
		return s.acceptSnapshot(snap)
	}
	m, e := s.loadRenewalManifest()
	if e != nil {
		return e
	}
	tx, e := s.loadRenewalTransaction(m)
	if e != nil {
		return e
	}
	v, e := s.renewalRequest(ctx, m, &tx, manifestCredential(m), "status", enrollmentcrypto.PurposeRenewalStatus, s.l.StatusRequestID)
	if e != nil {
		return e
	}
	if !sameCredential(v.Current, manifestCredential(m)) || v.Status == "revoked" || v.Status == "expired" {
		return ErrTerminal
	}
	// Disabling future renewal does not invalidate the currently live leaf.
	return nil
}
func (a *macOSInventoryActive) Check(now time.Time) (sender.Evidence, error) {
	var zero sender.Evidence
	if a == nil || a.s == nil || a.ctx == nil || a.ctx.Err() != nil || now.IsZero() || now.Location() != time.UTC {
		return zero, sender.ErrAuthority
	}
	s := a.s
	raw, e := s.store.Read("ledger.json")
	if e != nil {
		return zero, ErrState
	}
	defer clear(raw)
	expected, e := json.Marshal(ledgerDisk(*s.l.ledgerData))
	if e != nil {
		return zero, ErrState
	}
	defer clear(expected)
	if !bytes.Equal(raw, expected) || !s.l.Activated || !s.l.SenderInitializationStarted || !s.l.HandoffPrepared || s.validateArtifacts() != nil {
		return zero, ErrState
	}
	c, consent, original, e := s.macOSInventoryOriginal()
	if e != nil {
		return zero, e
	}
	if _, e = validateBootstrap(s.l.Bootstrap, now); e != nil {
		return zero, sender.ErrAuthority
	}
	anchor, e := decode64(s.l.CertificateDER, enrollmentcrypto.MaxCertificateBytes)
	if e != nil {
		return zero, ErrState
	}
	current := bytes.Clone(anchor)
	generation := uint64(1)
	if s.l.Bootstrap.RenewalPolicy != "" {
		m, e := s.loadRenewalManifest()
		if e != nil {
			return zero, sender.ErrAuthority
		}
		tx, e := s.loadRenewalTransaction(m)
		if e != nil || tx.State == "revoked" || now.Unix() < tx.LastServerNow {
			return zero, sender.ErrAuthority
		}
		current = bytes.Clone(m.CertificateDER)
		generation = m.CredentialGeneration
	} else if _, e = enrollmentcrypto.VerifyIssued(anchor, s.issuerDER, s.l.Intent, now); e != nil {
		return zero, sender.ErrAuthority
	}
	if len(a.leaf) != 0 && !bytes.Equal(current, a.leaf) {
		return zero, sender.ErrAuthority
	}
	return sender.Evidence{ManagerOrigin: c.ManagerOrigin, OriginalEnable: original, Consent: consent, AnchorDER: anchor, CurrentDER: current, IssuerDER: bytes.Clone(s.issuerDER), CredentialGeneration: generation}, nil
}
func (a *macOSInventoryActive) Exchange(ctx context.Context, path string, body []byte) ([]byte, error) {
	if a == nil || a.exchange == nil || ctx == nil || a.ctx.Err() != nil || ctx.Err() != nil {
		return nil, sender.ErrAuthority
	}
	if _, e := a.Check(time.Now().UTC()); e != nil {
		return nil, e
	}
	raw, e := a.exchange.Exchange(ctx, path, body)
	if e != nil {
		return nil, e
	}
	if _, e = a.Check(time.Now().UTC()); e != nil {
		return nil, e
	}
	return raw, nil
}

var _ sender.Authority = (*macOSInventoryAuthority)(nil)
var _ sender.ActiveAuthority = (*macOSInventoryActive)(nil)

// An exhausted historical authority still owns retention. This predicate never
// classifies malformed/missing state as mere expiry and never creates authority.
func macOSInventoryAuthorityExhausted(path string, now time.Time) bool {
	s, e := openMacOSInventoryEnrollment(path)
	if e != nil {
		return false
	}
	defer closeMacOSInventoryEnrollment(s)
	if s.l.Bootstrap.RenewalPolicy == "" {
		return false
	}
	raw, e := s.store.Read(renewalidentity.ManifestName)
	if e != nil {
		return false
	}
	m, e := renewalidentity.Parse(raw)
	if e != nil {
		return false
	}
	if !s.macOSInventoryManifestExhausted(m, now) {
		return false
	}
	if _, e = s.loadRenewalTransaction(m); e != nil {
		return false
	}
	return true
}

func (s *session) initializeMacOSInventoryTrust() error {
	var e error
	s.trust, e = validateBootstrap(s.l.Bootstrap, time.Unix(s.l.Intent.NotBefore, 0))
	if e != nil {
		return e
	}
	s.trust.KeyFingerprint = fingerprint(s.publicDER)
	s.trust.ComparisonCode, e = enrollmentcrypto.ComparisonCode(s.l.Bootstrap.ManagerInstanceID, s.l.Bootstrap.InvitationID, s.l.ClaimID, s.trust.KeyFingerprint)
	return e
}
func (s *session) macOSInventoryManifestExhausted(m renewalidentity.Manifest, now time.Time) bool {
	if now.IsZero() || now.Location() != time.UTC || s.l.Bootstrap.CollectionProfile != enrollmentcrypto.CollectionProfileMacOSInventory {
		return false
	}
	if e := s.validateRenewalManifestAt(m, time.Unix(max(m.LastServerNow, m.Intent.NotBefore), 0), false); e != nil {
		return false
	}
	return now.Unix() >= m.AuthorityExpiresAt
}
