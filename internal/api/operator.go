package api

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"localrmm/internal/actionmanager"
	"localrmm/internal/aiconfig"
	"localrmm/internal/alarmdelivery"
	"localrmm/internal/applicationcheck"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lantrust"
	"localrmm/internal/linuxcvefeed"
	"localrmm/internal/linuxcveprogress"
	"localrmm/internal/model"
	"localrmm/internal/offlinecatalog"
	"localrmm/internal/operatorauth"
	"localrmm/internal/packagecontroller"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type LANOperatorConfig struct {
	PackageActions *packagecontroller.Manager
	AISettings     *aiconfig.Settings
	AlarmSettings  *alarmdelivery.Settings
	// ApplicationChecks is an inert, read-only view of the explicit startup worker.
	ApplicationChecks *applicationcheck.Monitor
	// ApplicationCheckSettings supplies the separately authorized managed controller.
	// It cannot be combined with ApplicationChecks. Both constructors are inert.
	ApplicationCheckSettings *applicationcheck.Settings
	ServiceActions           *actionmanager.Manager
	Origin                   string
	Auth                     *operatorauth.Manager
	Registry                 *lantrust.Registry
	Devices                  func() ([]model.Device, error)
	// InsecureHTTPTest is a separate, explicitly opted-in plaintext profile.
	InsecureHTTPTest           bool
	Enrollment                 *enrollmentservice.Service
	EnrollmentBootstrap        EnrollmentBootstrap
	WindowsEnrollment          *enrollmentservice.Service
	WindowsEnrollmentBootstrap EnrollmentBootstrap
	// CVECache contains only explicitly synchronized public advisory records.
	CVECache *linuxcvefeed.Cache
	// CVEProgress is private derived state, separate from public advisory data.
	CVEProgress *linuxcveprogress.Cache
}
type operatorHandler struct {
	packageUpdatesManager    packageUpdateManager
	alarmSettings            *alarmdelivery.Settings
	applicationChecks        *applicationcheck.Monitor
	applicationCheckSettings *applicationcheck.Settings
	actions                  serviceActionManager
	app                      *Server
	origin, authority        string
	auth                     *operatorauth.Manager
	registry                 *lantrust.Registry
	insecureHTTPTest         bool
	cookieName               string
	enrollment               *enrollmentservice.Service
	windowsEnrollment        *operatorHandler
	enrollmentBootstrap      EnrollmentBootstrap
	bootstrapAdmission       bootstrapAdmission
}
type operatorRequestKey struct{}
type operatorRequest struct {
	session operatorauth.Session
	origin  string
	active  func() bool
}

type authView struct {
	LoginMode              string                    `json:"loginMode"`
	ActorID                *string                   `json:"actorId"`
	Capabilities           []operatorauth.Capability `json:"capabilities"`
	Mode                   string                    `json:"mode"`
	Transport              string                    `json:"transport"`
	InsecureTestMode       bool                      `json:"insecureTestMode"`
	TransportWarning       *string                   `json:"transportWarning"`
	AuthenticationRequired bool                      `json:"authenticationRequired"`
	Authenticated          bool                      `json:"authenticated"`
	CSRFToken              *string                   `json:"csrfToken"`
	ServerNow              time.Time                 `json:"serverNow"`
	ExpiresAt              *time.Time                `json:"expiresAt"`
	ExpiresInSeconds       *int                      `json:"expiresInSeconds"`
}

// NewLANOperatorHandler is a separate TLS+session boundary. The underlying
// Server's development ServeHTTP is disabled, not reused as LAN authorization.
func NewLANOperatorHandler(app *Server, c LANOperatorConfig) (http.Handler, error) {
	if app == nil || c.Auth == nil || c.Registry == nil || c.Devices == nil {
		return nil, errors.New("LAN operator authentication, trust registry and device source are required")
	}
	scheme, defaultPort, cookieName := "https", "443", operatorauth.CookieName
	if c.InsecureHTTPTest {
		scheme, defaultPort, cookieName = "http", "80", "tracebolt-http-test-session"
	}
	u, err := url.Parse(c.Origin)
	if err != nil || u.Scheme != scheme || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || c.Origin != scheme+"://"+u.Host || u.Host != strings.ToLower(u.Host) || u.Port() == defaultPort || strings.ContainsAny(c.Origin, "\\%\r\n\t") {
		return nil, errors.New("canonical explicit HTTPS operator origin required")
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != u.Port() {
			return nil, errors.New("invalid operator origin port")
		}
	}
	if strings.HasSuffix(u.Host, ":") || u.Hostname() == "" {
		return nil, errors.New("invalid operator authority")
	}
	if c.Enrollment != nil && (c.Enrollment.Binding().CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory || !validEnrollmentBootstrap(c.Enrollment, c.EnrollmentBootstrap, c.Origin, c.InsecureHTTPTest)) {
		return nil, errors.New("enrollment public bootstrap does not match configured authority")
	}
	if c.WindowsEnrollment != nil {
		if c.Enrollment == nil || c.WindowsEnrollment == c.Enrollment || c.WindowsEnrollment.Binding().CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || c.Enrollment.Binding().CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory || !validEnrollmentBootstrap(c.WindowsEnrollment, c.WindowsEnrollmentBootstrap, c.Origin, c.InsecureHTTPTest) {
			return nil, errors.New("Windows enrollment authority is not separately configured")
		}
		a, b := c.Enrollment.Binding(), c.WindowsEnrollment.Binding()
		if a.InstanceID != b.InstanceID || a.Origin != b.Origin || a.Profile != b.Profile || a.IssuerFingerprint != b.IssuerFingerprint {
			return nil, errors.New("Windows enrollment boundary does not match manager authority")
		}
	}
	profile := "tls"
	if c.InsecureHTTPTest {
		profile = "http-test"
	}
	if c.PackageActions != nil && (c.Enrollment == nil || !c.Auth.Named() || !c.PackageActions.MatchesBinding(c.Enrollment.Binding()) || c.PackageActions.TransportProfile() != actionmanager.Profile(profile)) {
		return nil, errors.New("package action authority does not match enrolled named operator boundary")
	}
	if c.ServiceActions != nil && (c.Enrollment == nil || !c.Auth.Named() || !c.ServiceActions.MatchesBinding(c.Enrollment.Binding()) || c.ServiceActions.TransportProfile() != actionmanager.Profile(profile)) {
		return nil, errors.New("service action authority does not match the named operator enrollment boundary")
	}
	managerID := ""
	if c.Enrollment != nil {
		managerID = c.Enrollment.Binding().InstanceID
	}
	if c.AISettings != nil && (c.Enrollment == nil || c.Enrollment.Binding().CollectionProfile != enrollmentcrypto.CollectionProfileComplete || !c.AISettings.Matches(managerID, profile)) {
		return nil, aiconfig.ErrConfiguration
	}
	if err := app.configurePersistentAI(c.AISettings, !c.InsecureHTTPTest); err != nil {
		return nil, err
	}
	if c.AlarmSettings != nil && (c.Enrollment == nil || c.Enrollment.Binding().CollectionProfile != enrollmentcrypto.CollectionProfileComplete || !c.AlarmSettings.Matches(managerID, profile)) {
		return nil, alarmdelivery.ErrConfiguration
	}
	if c.ApplicationChecks != nil && c.ApplicationCheckSettings != nil || !c.ApplicationChecks.Matches(managerID, c.Origin, profile) || !c.ApplicationCheckSettings.Matches(managerID, c.Origin, profile) {
		return nil, applicationcheck.ErrConfiguration
	}
	app.mu.Lock()
	app.lanOnly = true
	app.guidedEnrollment = c.Enrollment != nil
	app.insecureHTTPTest = c.InsecureHTTPTest
	app.managedPreview = nil
	app.sample = model.Device{}
	app.lanDevices = c.Devices
	app.lanOperational = nil
	app.lanPackages = nil
	app.health = nil
	app.journalAI = nil
	app.linuxCVE = nil
	app.aiCollectionProfile = "basic-readonly-v1"
	app.catalogStore = nil
	app.catalogImports = nil
	app.catalogReviews = nil
	app.reviewComparator = nil
	app.catalogNow = nil
	if c.Enrollment != nil {
		app.lanOperational = func(ctx context.Context, id string, _ time.Time) (enrollmentstore.OperationalView, error) {
			return c.Enrollment.OperationalView(ctx, id, c.Enrollment.Now())
		}
		app.lanPackages = func(ctx context.Context, id string, _ time.Time) (enrollmentstore.PackageView, error) {
			return c.Enrollment.PackageView(ctx, id, c.Enrollment.Now())
		}
		app.aiCollectionProfile = c.Enrollment.Binding().CollectionProfile
		if app.aiCollectionProfile == enrollmentcrypto.CollectionProfileComplete {
			app.health = &healthMonitor{store: app.store, source: c.Enrollment}
			app.journalAI = &journalAIState{source: c.Enrollment, managerID: managerID, transport: profile, results: map[string]*journalAIResult{}}
			app.linuxCVE = newLinuxCVEState(c.Enrollment, c.Enrollment.Now)
			app.linuxCVE.cache = c.CVECache
			app.linuxCVE.progress = c.CVEProgress
			if c.CVECache != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := c.CVECache.Load(ctx, &app.linuxCVE.feeds, c.Enrollment.Now()); err != nil {
					app.linuxCVE.feeds.RecordFailure(c.Enrollment.Now(), "cache_load_failed")
				}
				cancel()
			}
		}
		if enrollmentcrypto.ManagedCollectionProfile(app.aiCollectionProfile) {
			app.catalogStore = offlinecatalog.New()
			app.catalogImports = make(chan struct{}, 1)
			if app.aiCollectionProfile == enrollmentcrypto.CollectionProfilePackages {
				app.catalogReviews = make(chan struct{}, 1)
			}
			app.catalogNow = c.Enrollment.Now
		}
	}
	app.mu.Unlock()
	var actions serviceActionManager
	if c.ServiceActions != nil {
		actions = c.ServiceActions
	}
	var packages packageUpdateManager
	if c.PackageActions != nil {
		packages = c.PackageActions
	}
	h := &operatorHandler{packageUpdatesManager: packages, alarmSettings: c.AlarmSettings, applicationChecks: c.ApplicationChecks, applicationCheckSettings: c.ApplicationCheckSettings, actions: actions, app: app, origin: c.Origin, authority: u.Host, auth: c.Auth, registry: c.Registry, insecureHTTPTest: c.InsecureHTTPTest, cookieName: cookieName, enrollment: c.Enrollment, enrollmentBootstrap: c.EnrollmentBootstrap}
	if c.WindowsEnrollment != nil {
		h.windowsEnrollment = &operatorHandler{app: app, origin: c.Origin, authority: u.Host, auth: c.Auth, registry: c.Registry, insecureHTTPTest: c.InsecureHTTPTest, cookieName: cookieName, enrollment: c.WindowsEnrollment, enrollmentBootstrap: c.WindowsEnrollmentBootstrap}
	}
	return h, nil
}
func (s *Server) developmentAuthView() authView {
	token := s.csrf
	return authView{LoginMode: "shared", Capabilities: []operatorauth.Capability{}, Mode: "development", Transport: "http", CSRFToken: &token, ServerNow: time.Now().UTC()}
}
func (h *operatorHandler) view(session *operatorauth.Session) authView {
	now := h.auth.Now()
	view := authView{LoginMode: "shared", Capabilities: []operatorauth.Capability{}, Mode: "lan", Transport: "https", AuthenticationRequired: true, ServerNow: now.UTC()}
	if h.auth.Named() {
		view.LoginMode = "named"
	}
	if h.insecureHTTPTest {
		warning := "unencrypted_lan_test"
		view.Transport = "http"
		view.InsecureTestMode = true
		view.TransportWarning = &warning
	}
	if session != nil {
		view.Authenticated = true
		view.Capabilities = session.Capabilities()
		if session.Named() {
			actorID := session.ActorID()
			view.ActorID = &actorID
		}
		csrf := session.CSRFToken
		expires := session.ExpiresAt.UTC()
		seconds := int(math.Ceil(session.ExpiresAt.Sub(now).Seconds()))
		if seconds < 0 {
			seconds = 0
		}
		view.CSRFToken = &csrf
		view.ExpiresAt = &expires
		view.ExpiresInSeconds = &seconds
	}
	return view
}
func operatorCookie(r *http.Request) (string, bool) {
	return namedOperatorCookie(r, operatorauth.CookieName)
}
func namedOperatorCookie(r *http.Request, name string) (string, bool) {
	value := ""
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == name {
			value = cookie.Value
			count++
		}
	}
	return value, count == 1
}
func (h *operatorHandler) session(r *http.Request) (operatorauth.Session, error) {
	token, ok := namedOperatorCookie(r, h.cookieName)
	if !ok {
		return operatorauth.Session{}, operatorauth.ErrUnauthenticated
	}
	return h.auth.Lookup(token)
}
func (h *operatorHandler) setCookie(w http.ResponseWriter, s operatorauth.Session) {
	maxAge := int(math.Ceil(s.ExpiresAt.Sub(h.auth.Now()).Seconds()))
	http.SetCookie(w, &http.Cookie{Name: h.cookieName, Value: s.Token, Path: "/", Secure: !h.insecureHTTPTest, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: maxAge, Expires: s.ExpiresAt.UTC()})
}
func clearOperatorCookie(w http.ResponseWriter) {
	clearNamedOperatorCookie(w, operatorauth.CookieName, true)
}
func clearNamedOperatorCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", Secure: secure, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0).UTC()})
}
func operatorContext(r *http.Request) (operatorRequest, bool) {
	value, ok := r.Context().Value(operatorRequestKey{}).(operatorRequest)
	return value, ok
}
func (s *Server) requiredOrigin(r *http.Request) string {
	if operator, ok := operatorContext(r); ok {
		return operator.origin
	}
	return "http://" + r.Host
}
func (s *Server) requiredCSRF(r *http.Request) string {
	if operator, ok := operatorContext(r); ok {
		return operator.session.CSRFToken
	}
	return s.csrf
}
func (s *Server) cancelSessionAnalysis(id string) {
	s.ai.mu.Lock()
	if s.ai.activeOwner == id && s.ai.activeCancel != nil {
		s.ai.activeCancel()
	}
	s.ai.mu.Unlock()
}
func (h *operatorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	headers := w.Header()
	headers.Set("Cache-Control", "no-store")
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("X-Frame-Options", "DENY")
	headers.Set("Referrer-Policy", "no-referrer")
	headers.Set("Cross-Origin-Resource-Policy", "same-origin")
	headers.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if !h.insecureHTTPTest {
		headers.Set("Strict-Transport-Security", "max-age=86400")
	}
	headers.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	if (!h.insecureHTTPTest && (r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || !r.TLS.HandshakeComplete)) || (h.insecureHTTPTest && r.TLS != nil) {
		fail(w, 403, "tls_required", "The operator surface requires authenticated HTTPS transport.")
		return
	}
	if r.Host != h.authority {
		fail(w, 403, "invalid_host", "Unexpected operator authority.")
		return
	}
	cookieCount := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == h.cookieName {
			cookieCount++
		}
	}
	if cookieCount > 1 {
		fail(w, 400, "ambiguous_session_cookie", "Ambiguous session cookies are rejected.")
		return
	}
	origin := r.Header.Get("Origin")
	if len(r.Header.Values("Origin")) > 1 || (origin != "" && origin != h.origin) {
		fail(w, 403, "invalid_origin", "Unexpected operator origin.")
		return
	}
	if len(r.TransferEncoding) > 0 {
		fail(w, 400, "invalid_framing", "Chunked request bodies are not accepted.")
		return
	}
	if strings.Contains(r.URL.Path, "//") || strings.Contains(r.URL.Path, "\\") || strings.Contains(r.URL.EscapedPath(), "%") || (r.URL.Path != "/api/investigations" && !resourceHistoryQueryAllowed(r.URL) && r.URL.RawQuery != "") || r.URL.ForceQuery {
		fail(w, 400, "invalid_path", "Path is not canonical.")
		return
	}
	for _, part := range strings.Split(r.URL.Path, "/") {
		if strings.HasPrefix(part, ".") {
			fail(w, 404, "not_found", "Path is unavailable.")
			return
		}
	}
	if r.URL.Path == socketOwnerCapabilitiesPath {
		if h.enrollment == nil {
			fail(w, 404, "enrollment_unavailable", "Enrollment is not configured.")
			return
		}
		serveSocketOwnerCapabilities(w, r, h.enrollmentBootstrap, &h.bootstrapAdmission)
		return
	}
	if r.URL.Path == journalCapabilitiesPath {
		if h.enrollment == nil {
			fail(w, 404, "enrollment_unavailable", "Enrollment is not configured.")
			return
		}
		serveJournalCapabilities(w, r, h.enrollmentBootstrap, &h.bootstrapAdmission)
		return
	}
	if strings.HasPrefix(r.URL.Path, publicBootstrapPrefix) {
		if h.enrollment == nil {
			fail(w, 404, "enrollment_unavailable", "Enrollment is not configured.")
			return
		}
		servePublicBootstrap(w, r, h.enrollmentBootstrap, &h.bootstrapAdmission)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v2/windows/enrollment/") {
		h.windowsEnrollmentClient(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v2/enrollment/") {
		h.enrollmentClient(w, r)
		return
	}
	apiPath := strings.HasPrefix(r.URL.Path, "/api/")
	if apiPath && r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		fail(w, 403, "cross_site", "Cross-site API requests are not allowed.")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/dev/") {
		fail(w, 404, "not_found", "Developer transport routes are unavailable on this surface.")
		return
	}
	if r.URL.Path == "/api/auth/session" && r.Method == "GET" {
		session, err := h.session(r)
		if err != nil {
			write(w, 200, h.view(nil))
			return
		}
		write(w, 200, h.view(&session))
		return
	}
	if r.URL.Path == "/api/auth/login" && r.Method == "POST" {
		h.login(w, r)
		return
	}
	if !apiPath {
		if r.Method != "GET" && r.Method != "HEAD" {
			fail(w, 405, "method_not_allowed", "Method is unsupported.")
			return
		}
		h.app.static(w, r)
		return
	}
	session, err := h.session(r)
	if err != nil {
		clearNamedOperatorCookie(w, h.cookieName, !h.insecureHTTPTest)
		fail(w, 401, "authentication_required", "Sign in to continue.")
		return
	}
	token, _ := namedOperatorCookie(r, h.cookieName)
	ctx, cancel := context.WithDeadline(r.Context(), session.ExpiresAt)
	defer cancel()
	stopRevocation := context.AfterFunc(session.Lifetime(), cancel)
	defer stopRevocation()
	r = r.WithContext(context.WithValue(ctx, operatorRequestKey{}, operatorRequest{session: session, origin: h.origin, active: func() bool { _, err := h.auth.Lookup(token); return err == nil }}))
	if r.URL.Path == "/api/auth/logout" && r.Method == "POST" {
		if !h.app.authorizeJSONMutation(w, r) {
			return
		}
		var empty struct{}
		if !readObject(w, r, 256, []string{}, &empty) {
			return
		}
		token, _ := namedOperatorCookie(r, h.cookieName)
		h.auth.Logout(token)
		h.app.cancelSessionAnalysis(session.ID)
		clearNamedOperatorCookie(w, h.cookieName, !h.insecureHTTPTest)
		write(w, 200, h.view(nil))
		return
	}
	if _, _, ok := packageUpdateRoute(r); ok {
		h.packageUpdates(w, r)
		return
	}
	if _, _, ok := serviceActionRoute(r); ok {
		h.serviceActions(w, r)
		return
	}
	if r.URL.Path == "/api/alerts/settings" || r.URL.Path == "/api/alerts/test" {
		h.alarmSettingsAPI(w, r)
		return
	}
	if r.URL.Path == "/api/application-checks/settings" {
		h.applicationCheckSettingsAPI(w, r)
		return
	}
	if session.Named() && !namedReadRoute(r) {
		fail(w, 403, "operator_capability_required", "This named account does not have permission for this administrative operation.")
		return
	}
	if r.URL.Path == "/api/ai/journal" || strings.HasPrefix(r.URL.Path, "/api/ai/journal/") {
		h.journalAIAPI(w, r)
		return
	}
	if r.URL.Path == "/api/ai/proactive" {
		h.proactiveAI(w, r)
		return
	}
	if r.URL.Path == "/api/application-checks/status" {
		h.applicationCheckStatus(w, r)
		return
	}
	if r.URL.Path == "/api/alerts/status" {
		h.alarmStatus(w, r)
		return
	}
	if r.URL.Path == "/api/lan/agents" && r.Method == "GET" {
		agents := h.registry.List()
		write(w, 200, map[string]any{"items": agents, "total": len(agents)})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/lan/agents") && r.Method == "POST" {
		h.agentMutation(w, r)
		return
	}
	if r.URL.Path == "/api/auth/login" || r.URL.Path == "/api/auth/logout" || r.URL.Path == "/api/auth/session" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if r.URL.Path == "/api/windows/enrollment" || strings.HasPrefix(r.URL.Path, "/api/windows/enrollment/") {
		h.windowsEnrollmentOperator(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/devices/") && strings.HasSuffix(r.URL.Path, "/windows-inventory") {
		h.windowsInventoryView(w, r)
		return
	}
	if r.URL.Path == "/api/enrollment" || strings.HasPrefix(r.URL.Path, "/api/enrollment/") {
		h.enrollmentOperator(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/devices/") && strings.Contains(r.URL.Path, "/journal") {
		h.journal(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/security/cves") || strings.HasPrefix(r.URL.Path, "/api/devices/") && strings.Contains(r.URL.Path, "/security/cves") {
		h.linuxCVEAPI(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/devices/") && strings.Contains(r.URL.Path, "/inventory/overview") {
		h.completeOverview(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/devices/") && strings.Contains(r.URL.Path, "/inventory/packages") {
		h.completePackages(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/devices/") && strings.Contains(r.URL.Path, "/inventory/complete-updates") {
		h.completeUpdates(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/devices/") && strings.Contains(r.URL.Path, "/inventory/cached-updates") {
		h.cachedUpdates(w, r)
		return
	}
	if r.URL.Path == "/api/investigations" {
		h.investigations(w, r)
		return
	}
	if r.URL.Path == "/api/fleet/endpoint-identities" {
		h.fleetEndpointIdentity(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/devices/") && strings.Contains(r.URL.Path, "/inventory/endpoint-identity") {
		h.endpointIdentity(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/devices/") && strings.Contains(r.URL.Path, "/inventory/system") {
		h.systemInventory(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/devices/") && strings.Contains(r.URL.Path, "/health") {
		h.healthAPI(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/devices/") && strings.Contains(r.URL.Path, "/resource-history") {
		h.resourceHistory(w, r)
		return
	}
	h.app.api(w, r)
}
func (h *operatorHandler) login(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != h.origin {
		fail(w, 403, "origin_required", "Same-origin login is required.")
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		fail(w, 415, "json_required", "JSON is required.")
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	fields := []string{"password"}
	if h.auth.Named() {
		fields = append(fields, "username")
	}
	if !readObject(w, r, 4096, fields, &input) {
		return
	}
	defer func() { input.Password = "" }()
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		fail(w, 401, "invalid_credentials", "Sign-in failed.")
		return
	}
	var session operatorauth.Session
	if h.auth.Named() {
		session, err = h.auth.LoginNamed(r.Context(), peer, input.Username, input.Password)
	} else {
		session, err = h.auth.Login(r.Context(), peer, input.Password)
	}
	if err != nil {
		switch {
		case errors.Is(err, operatorauth.ErrRateLimited):
			w.Header().Set("Retry-After", "60")
			fail(w, 429, "login_rate_limited", "Too many sign-in attempts. Try again later.")
		case errors.Is(err, operatorauth.ErrBusy), errors.Is(err, operatorauth.ErrCapacity):
			fail(w, 503, "authentication_busy", "Sign-in is temporarily unavailable.")
		default:
			fail(w, 401, "invalid_credentials", "Sign-in failed.")
		}
		return
	}
	if oldToken, ok := namedOperatorCookie(r, h.cookieName); ok {
		if old, err := h.auth.Lookup(oldToken); err == nil {
			h.auth.Logout(oldToken)
			h.app.cancelSessionAnalysis(old.ID)
		}
	}
	h.setCookie(w, session)
	write(w, 200, h.view(&session))
}
func (h *operatorHandler) agentMutation(w http.ResponseWriter, r *http.Request) {
	if h.enrollment != nil {
		fail(w, 404, "manual_identity_unavailable", "Manual certificate actions are unavailable in guided enrollment mode.")
		return
	}
	if !h.app.authorizeJSONMutation(w, r) {
		return
	}
	if r.URL.Path == "/api/lan/agents/approve" {
		var input struct {
			CertificatePEM            string `json:"certificatePEM"`
			Label                     string `json:"label"`
			ExpectedFingerprintSHA256 string `json:"expectedFingerprintSHA256"`
		}
		if !readObject(w, r, 64*1024, []string{"certificatePEM", "label", "expectedFingerprintSHA256"}, &input) {
			return
		}
		block, _ := pem.Decode([]byte(input.CertificatePEM))
		if block == nil || block.Type != "CERTIFICATE" {
			fail(w, 400, "invalid_certificate", "A public client certificate chain is required.")
			return
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || len(input.ExpectedFingerprintSHA256) != 64 || subtle.ConstantTimeCompare([]byte(lantrust.Fingerprint(cert)), []byte(input.ExpectedFingerprintSHA256)) != 1 {
			fail(w, 400, "fingerprint_mismatch", "The supplied fingerprint does not match the certificate.")
			return
		}
		if !operatorStillActive(w, r) {
			return
		}
		if h.insecureHTTPTest {
			if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
				fail(w, 400, "unsupported_test_key", "HTTP test requires an Ed25519 client leaf.")
				return
			}
			_, rest := pem.Decode([]byte(input.CertificatePEM))
			if strings.TrimSpace(string(rest)) != "" {
				fail(w, 400, "unsupported_test_chain", "HTTP test requires a directly issued client leaf only.")
				return
			}
		}
		release, ok := beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
		agent, err := h.registry.Approve(r.Context(), []byte(input.CertificatePEM), input.Label)
		release()
		if err != nil {
			h.registryError(w, err)
			return
		}
		release()
		write(w, 201, agent)
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) == 6 && parts[1] == "api" && parts[2] == "lan" && parts[3] == "agents" && validID(parts[4]) && parts[5] == "revoke" {
		var empty struct{}
		if !readObject(w, r, 256, []string{}, &empty) {
			return
		}
		if !operatorStillActive(w, r) {
			return
		}
		release, ok := beginOperatorMutation(w, r)
		if !ok {
			return
		}
		defer release()
		err := h.registry.Revoke(r.Context(), parts[4])
		release()
		if err != nil {
			h.registryError(w, err)
			return
		}
		release()
		write(w, 200, map[string]any{"revoked": true, "id": parts[4]})
		return
	}
	fail(w, 404, "not_found", "Agent action is unavailable.")
}
func (h *operatorHandler) registryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, lantrust.ErrRegistryUnavailable):
		fail(w, 503, "registry_unavailable", "Agent trust is unavailable; no access was granted.")
	case errors.Is(err, lantrust.ErrAlreadyApproved):
		fail(w, 409, "certificate_already_registered", "Certificate already registered; renewal needs a separately approved certificate.")
	case errors.Is(err, lantrust.ErrNotFound):
		fail(w, 404, "not_found", "Agent approval not found.")
	case errors.Is(err, lantrust.ErrCapacity):
		fail(w, 409, "registry_full", "Agent registry capacity reached.")
	default:
		fail(w, 400, "invalid_certificate", "Client certificate or label did not satisfy the trust policy.")
	}
}

func operatorStillActive(w http.ResponseWriter, r *http.Request) bool {
	if operator, ok := operatorContext(r); ok {
		if r.Context().Err() != nil || operator.active == nil || !operator.active() {
			fail(w, 401, "authentication_required", "Operator session expired or was revoked.")
			return false
		}
	}
	return true
}

func beginOperatorMutation(w http.ResponseWriter, r *http.Request) (func(), bool) {
	if !operatorStillActive(w, r) {
		return nil, false
	}
	if operator, ok := operatorContext(r); ok {
		release, err := operator.session.BeginMutation(r.Context())
		if err != nil {
			fail(w, 401, "authentication_required", "Operator session expired or was revoked.")
			return nil, false
		}
		return release, true
	}
	return func() {}, true
}
