//go:build linux

package managersetup

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/lanconfig"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func runtimeCheck(r *Report, options Options) bool {
	if options.ExpectedUID <= 0 || os.Geteuid() != options.ExpectedUID {
		r.add("runtime_uid", "fail", "The selected nonroot runtime UID does not match this process.", "Run this command as the intended manager UID and set --runtime-uid to that UID; do not substitute root or change ownership automatically.")
		return false
	}
	r.add("runtime_uid", "pass", "The explicit nonroot runtime UID matches this process.", "")
	return true
}

func doctor(path string, options Options, now time.Time) Report {
	r := NewReport("doctor")
	if !runtimeCheck(&r, options) {
		return r
	}
	raw, err := lanconfig.ReadProtected(path, false, 16384)
	if err != nil {
		r.add("lan_config_protection", "fail", "The LAN configuration is missing, unreadable or not protected.", "Provide an absolute regular single-link configuration owned by root or the runtime UID, without writable or symlinked ancestors; review permissions locally.")
		return r
	}
	c, err := lanconfig.Parse(raw)
	if err != nil {
		r.add("lan_config", "fail", "The strict LAN configuration, origins or listener addresses are invalid.", "Use the current LAN schema, distinct literal-IP listener addresses and exact canonical HTTPS origins without paths, credentials, trailing slash or default :443 port.")
		return r
	}
	if within(path, c.WebDirectory) {
		r.add("configuration_exposure", "fail", "The LAN configuration is inside the frontend tree.", "Preserve the existing file and have the custodian review its exposure and choose an approved private configuration location outside the served frontend.")
		return r
	}
	inspect(&r, c, options, now, readListeners)
	return r
}

func inspect(r *Report, c lanconfig.Config, options Options, now time.Time, listeners func() ([]listener, error)) {
	if c.Validate() != nil || c.Profile != lanconfig.TLS {
		r.add("tls_origins", "fail", "Guided setup requires valid TLS configuration and exact origins/listeners.", "Provide canonical distinct HTTPS origins, absolute material paths and distinct literal-IP listener addresses; this setup command does not provision HTTP-test profiles.")
		return
	}
	r.add("tls_origins", "pass", "The TLS profile, strict origins and listener shapes are valid.", "")
	if within(c.StateDirectory, c.WebDirectory) || within(c.WebDirectory, c.StateDirectory) {
		r.add("directory_separation", "fail", "The state and frontend directory trees overlap.", "Preserve existing state and select disjoint approved state/frontend locations; private runtime state must never be served as frontend content.")
		return
	}
	if exposedToWeb(c.WebDirectory, c.TLSCertificateFile, c.TLSPrivateKeyFile, c.AgentClientCAFile, c.OperatorAuthFile, options.EnrollmentConfig) {
		r.add("material_exposure", "fail", "Selected configuration or trust/credential material is inside the frontend tree.", "Keep configuration, keys, verifiers and issuer material outside the served frontend; have the authorized custodian review any existing exposure without automatic movement or deletion.")
		return
	}
	if c.MacOSBasicEnabled || c.MacOSInventoryEnabled || c.ServiceActionsConfigFile != "" || c.PackageActionsConfigFile != "" || c.WindowsServiceActionsConfigFile != "" || c.WindowsUpdateJobsConfigFile != "" || c.WindowsSoftwareJobsConfigFile != "" || c.WindowsManagedMSIConfigFile != "" {
		r.add("additional_capabilities", "unknown", "Additional configured capability domains are outside this guided observation-only preflight.", "Review each selected capability's own protected configuration and acceptance contract separately; do not disable or rewrite existing scopes merely to make doctor pass.")
	}
	// This is the configured runtime's fixed policy, not a probe of a running host.
	r.add("tls13_policy", "pass", "The selected TLS profile uses the LAN runtime's fixed TLS 1.3 minimum; no live handshake was performed.", "")
	if now.Unix() <= 0 || now.Unix() > 253402300799 {
		r.add("clock", "fail", "The validation clock is invalid.", "Verify the target's UTC clock without changing it through this tool.")
		return
	}
	files := []struct {
		code, path string
		private    bool
		limit      int64
		next       string
	}{
		{"server_certificate_file", c.TLSCertificateFile, false, 65536, "Provision the approved public server certificate chain as an absolute protected regular single-link file; review ownership and ancestors locally."},
		{"server_key_file", c.TLSPrivateKeyFile, true, 32768, "Have the authorized custodian supply the matching server key in a runtime-owned 0400/0600 regular single-link file; never paste or print the key."},
		{"agent_ca_file", c.AgentClientCAFile, false, 65536, "Supply exactly the approved dedicated client-auth intermediate as protected public PEM; keep the root private key offline."},
		{"operator_auth_file", c.OperatorAuthFile, true, 32768, "Supply preprovisioned operator auth in a runtime-owned 0400/0600 regular single-link file; never print its verifier or password."},
	}
	values := make([][]byte, len(files))
	materialOK := true
	for i, f := range files {
		raw, err := lanconfig.ReadProtected(f.path, f.private, f.limit)
		if err != nil {
			r.add(f.code, "fail", "Required material is missing, unreadable, oversized or has invalid file/ancestor protection.", f.next)
			materialOK = false
		} else {
			values[i] = raw
			r.add(f.code, "pass", "The required bounded protected file is readable by the runtime UID.", "")
		}
	}
	defer clear(values[1])
	defer clear(values[3])
	if values[2] != nil {
		block, rest := pem.Decode(values[2])
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			r.add("client_issuer_certificate", "fail", "Guided ingress requires exactly one public intermediate certificate PEM.", "Supply the same dedicated client-auth intermediate selected by enrollment configuration, not a root, sibling or combined pool.")
			materialOK = false
		} else if cert, err := x509.ParseCertificate(block.Bytes); err != nil {
			r.add("client_issuer_certificate", "fail", "The dedicated client issuer certificate is malformed.", "Have the custodian provide the approved public intermediate certificate; keep root private keys offline.")
			materialOK = false
		} else if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			r.add("issuer_validity", "fail", "The dedicated client issuer certificate is not currently valid.", "Review UTC time and the dedicated issuer lifetime with its custodian; issuer replacement and existing identity recovery require a separately reviewed procedure.")
			materialOK = false
		} else {
			r.add("issuer_validity", "pass", "The selected client issuer certificate is currently valid; complete role/trust matching is checked separately.", "")
		}
	}
	if values[3] != nil {
		if lanconfig.ValidateOperatorAuth(values[3], c.Profile) != nil {
			r.add("operator_auth", "fail", "Operator authentication schema, profile or verifier policy is invalid.", "Have the credential custodian provide the current profile-bound operator-auth schema and accepted Argon2id verifier/capabilities; placeholders are not credentials.")
			materialOK = false
		} else {
			r.add("operator_auth", "pass", "Operator authentication matches the runtime schema and verifier policy; no login was attempted.", "")
		}
	}
	if values[0] != nil && values[1] != nil {
		pair, err := tls.X509KeyPair(values[0], values[1])
		if err != nil || len(pair.Certificate) == 0 {
			r.add("server_key_pair", "fail", "The server certificate and private key do not form a valid pair.", "Ask the custodian to verify the matching approved certificate/key locally; do not expose private material.")
			materialOK = false
		} else {
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				materialOK = false
				r.add("server_certificate", "fail", "The server leaf certificate is malformed.", "Supply the reviewed server certificate chain.")
			} else {
				for _, origin := range []struct{ code, value string }{{"operator_san", c.OperatorOrigin}, {"agent_san", c.AgentOrigin}} {
					u, _ := url.Parse(origin.value)
					if leaf.VerifyHostname(u.Hostname()) != nil {
						r.add(origin.code, "fail", "The server certificate SAN does not cover the configured origin host.", "Have the custodian supply a certificate covering the exact client-visible host, or review the intended origin; never bypass name verification.")
						materialOK = false
					} else {
						r.add(origin.code, "pass", "The certificate SAN covers this configured origin host.", "")
					}
				}
				if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
					r.add("server_validity", "fail", "The server certificate is not currently valid.", "Review the UTC clock and have the custodian renew or replace the certificate through the authorized process.")
					materialOK = false
				} else {
					r.add("server_validity", "pass", "The server certificate is currently valid.", "")
				}
			}
		}
	}
	if options.EnrollmentConfig == "" {
		r.add("issuer_missing", "fail", "No separate guided-enrollment issuer configuration was selected.", "Have the custodian provision a dedicated Ed25519 client-auth pathLen0 intermediate/key, its public root and explicit server trust; supply --enrollment-config. Keep the root private key offline.")
	} else if enrollmentRaw, err := lanconfig.ReadProtected(options.EnrollmentConfig, false, 16384); err != nil {
		r.add("issuer_config_file", "fail", "The separate issuer configuration is missing or not protected.", "Supply an absolute protected tracebolt.enrollment-config.v2 file; inspect its existence, ownership, mode and ancestors locally.")
	} else if materialOK {
		m, err := lanconfig.LoadMaterial(c)
		if err != nil {
			r.add("runtime_material", "fail", "The runtime rejected the selected material.", "Recheck the current material contract locally; do not weaken protection or overwrite existing state.")
		} else if enrollment, err := enrollmentconfig.Load(options.EnrollmentConfig, m, now); err != nil {
			r.add("issuer_trust_validity", "fail", "Issuer key/certificate, fingerprint, lifetime, dedicated ingress anchor or explicit server trust is invalid.", "Verify issuer/root lifetimes, PKCS#8 Ed25519 key match, client-auth-only pathLen0 role, exact SHA-256 fingerprint, matching ingress intermediate and server CA/SAN chain locally; keep the root key offline.")
		} else {
			r.add("issuer_trust_validity", "pass", "The dedicated issuer, key custody, lifetime, ingress anchor and explicit server trust match the runtime contract.", "")
			// The authoritative loader above already checked the strict schema.
			// Decode paths only to enforce the additional non-served-tree boundary.
			var issuerConfig enrollmentconfig.Config
			if json.Unmarshal(enrollmentRaw, &issuerConfig) != nil || exposedToWeb(c.WebDirectory, issuerConfig.IssuerCertificateFile, issuerConfig.IssuerPrivateKeyFile, issuerConfig.IssuerRootFile, issuerConfig.BootstrapServerCAFile) {
				r.add("issuer_material_exposure", "fail", "Selected issuer or server-trust material is inside the frontend tree or its location could not be established.", "Have the custodian select protected issuer/key/public-root/server-CA paths outside the served frontend; preserve existing material and review possible exposure.")
			}
			if c.WindowsInventoryEnabled {
				if _, err := enrollment.WindowsStoreConfig(); err != nil {
					r.add("windows_profile", "fail", "The Windows inventory enrollment profile is incompatible.", "Review the explicit Windows inventory opt-in and current enrollment profile without changing existing identities or scope receipts.")
				} else {
					r.add("windows_profile", "pass", "The explicit Windows inventory enrollment profile can be derived; no endpoint scope or device approval was granted.", "")
				}
			}
		}
	} else {
		r.add("issuer_trust_validity", "unknown", "Issuer/trust validation is blocked by invalid prerequisite material.", "Resolve the material/auth/SAN failures and rerun doctor; no state has been prepared.")
	}
	if options.RequireWindows && !c.WindowsInventoryEnabled {
		r.add("windows_profile", "fail", "Windows inventory enrollment is not explicitly enabled.", "For a fresh separately approved manager, select --windows-inventory during init; do not promote existing identities or rewrite scope receipts.")
	}
	if err := protectedDirectory(c.StateDirectory, true); err != nil {
		r.add("state_directory", "fail", "The state directory is absent or is not private and runtime-owned.", "Have the authorized administrator prepare the dedicated runtime-owned 0700 directory and protected ancestor chain; do not reset, adopt, chmod or chown existing state automatically.")
	} else {
		r.add("state_directory", "pass", "State directory ownership/protection is valid; no database was opened or initialized.", "")
	}
	if err := protectedDirectory(c.WebDirectory, false); err != nil {
		r.add("frontend_directory", "fail", "The selected frontend directory is missing or has an unprotected owner/ancestor chain.", "Build and select the matching reviewed frontend from the same source revision, with protected read-only deployment paths.")
	} else if _, err := lanconfig.ReadProtected(filepath.Join(c.WebDirectory, "index.html"), false, 2<<20); err != nil {
		r.add("frontend_index", "fail", "The bounded protected frontend entry point is missing or unreadable.", "Build the matching frontend and review its deployment ownership; do not mix source pins.")
	} else {
		r.add("frontend_directory", "pass", "The protected frontend entry point exists; exact release provenance and browser behavior remain separate gates.", "")
	}
	inspectPorts(r, c, listeners)
}

// This mirrors the Linux protected-file ancestor rule without creating a marker,
// opening a store, changing mode/owner or following symlinked directories.
func protectedDirectory(path string, private bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return lanconfig.ErrConfiguration
	}
	for current, direct := path, true; ; current, direct = filepath.Dir(current), false {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return lanconfig.ErrConfiguration
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		uid := uint32(os.Geteuid())
		if !ok || (st.Uid != uid && st.Uid != 0) || (info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return lanconfig.ErrConfiguration
		}
		if direct && private && (st.Uid != uid || info.Mode().Perm()&0077 != 0) {
			return lanconfig.ErrConfiguration
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

func initialize(c lanconfig.Config, output string, options Options, now time.Time) Report {
	return initializeWithListeners(c, output, options, now, readListeners)
}

func initializeWithListeners(c lanconfig.Config, output string, options Options, now time.Time, listeners func() ([]listener, error)) Report {
	r := NewReport("init")
	if !runtimeCheck(&r, options) {
		return r
	}
	if !filepath.IsAbs(output) || filepath.Clean(output) != output || protectedDirectory(filepath.Dir(output), true) != nil {
		r.add("output_directory", "fail", "The output must be an absolute new file in an existing private runtime-owned directory.", "Have the administrator prepare the approved runtime-owned 0700 configuration directory; no directory or ownership is changed by init.")
		return r
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		r.add("output_exists", "fail", "The target already exists or its absence could not be established; it was not changed.", "Inspect and preserve the existing target, including partial files; use a separately approved new destination rather than deleting or overwriting it.")
		return r
	}
	if c.Validate() == nil && (within(output, c.StateDirectory) || within(output, c.WebDirectory)) {
		r.add("output_separation", "fail", "The new configuration target is inside the state or frontend tree.", "Choose an approved private configuration location outside both trees; init never inserts configuration into state or potentially served frontend content.")
		return r
	}
	inspect(&r, c, options, now, listeners)
	if !r.OK {
		return r
	}
	if !emptyDirectory(c.StateDirectory) {
		r.add("fresh_state", "fail", "Create-only initialization requires an existing empty protected state directory.", "Preserve all existing state, identities and consumption floors. Select a separately approved fresh empty directory; init performs no migration or reset.")
		return r
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		r.add("configuration_encoding", "fail", "Configuration could not be encoded.", "Review the configuration without exposing private material.")
		return r
	}
	raw = append(raw, '\n')
	// The private parent and trusted ancestor chain exclude cross-account path
	// replacement. O_EXCL rejects symlink/dangling-link/existing/concurrent targets.
	// Same-UID/root compromise is outside this boundary, as for ReadProtected.
	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		r.add("output_create", "fail", "The new configuration could not be created exclusively.", "Inspect the approved destination for an existing or concurrent file; do not retry by overwriting it.")
		return r
	}
	_, writeErr := f.Write(raw)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr == nil && closeErr == nil {
		d, err := os.Open(filepath.Dir(output))
		if err != nil {
			writeErr = err
		} else {
			writeErr = d.Sync()
			if err := d.Close(); writeErr == nil {
				writeErr = err
			}
		}
	}
	if writeErr != nil || closeErr != nil {
		r.add("output_uncertain", "fail", "A new output may be partial or its durability is uncertain; it was preserved unchanged after failure.", "Inspect the retained file locally and stop dependent startup; never delete, overwrite or blindly repeat initialization.")
		return r
	}
	r.Created = true
	r.add("configuration_created", "pass", "A new private LAN configuration was durably created; credentials and state were not changed.", "Start the separately approved LAN manager with this configuration and the exact existing enrollment configuration, then establish authenticated native/browser acceptance.")
	return r
}

func emptyDirectory(path string) bool {
	d, err := os.Open(path)
	if err != nil {
		return false
	}
	// Only one name is needed. Do not allocate an unbounded listing of retained
	// state, and never inspect database contents to determine freshness.
	names, readErr := d.Readdirnames(1)
	closeErr := d.Close()
	return len(names) == 0 && readErr == io.EOF && closeErr == nil
}

func within(path, directory string) bool {
	if !filepath.IsAbs(path) || !filepath.IsAbs(directory) {
		return false
	}
	relative, err := filepath.Rel(directory, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func exposedToWeb(web string, paths ...string) bool {
	for _, path := range paths {
		if within(path, web) {
			return true
		}
	}
	return false
}
