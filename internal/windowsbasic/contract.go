// Package windowsbasic is an inert, proposed Windows Basic contract. It does not
// register a route, admit an enrollment profile, authenticate a credential, or
// change the existing Rust/Go Windows inventory domain. Runtime integration must
// use a fresh identity-bound store and final same-transaction authority checks.
package windowsbasic

const (
	CollectionProfile = "windows-basic-metrics-v1"
	FrameVersion      = "tracebolt.agent-telemetry.windows-basic.v1"
	TelemetryPath     = "/v1/windows/basic/telemetry"
)

// ProfileAllowsRoute is a closed profile/route policy, NOT authentication or an
// enrollment grant. The profile/platform/transport arguments must eventually
// come from immutable server state, never agent version, capability advertising,
// request headers or the body. TLS possession, current credential authorization,
// activation, revocation, expiry and replay checks remain independent requirements.
// Exact equality intentionally denies every present and future expanded route.
func ProfileAllowsRoute(profile, platform, transport, method, path string) bool {
	return profile == CollectionProfile && platform == "windows" && transport == "tls" && method == "POST" && path == TelemetryPath
}
