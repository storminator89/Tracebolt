# Optional AI configuration and analysis: security review

Date: 2026-10-03. Scope: `internal/analysis`, the AI configuration/analyze routes in `internal/api/ai.go`, and `web/src/ai*`. This is an additive local-development review, not production authorization or proof of model accuracy. The managed-agent preview has a separate boundary and is not covered by this document.

## Current result

Source, component, and fake-provider checks pass. No real API key was used and no external model service was called. The new AI browser flow still needs its own exact-source Chromium result; the earlier 25-scenario baseline browser result must not be reused as AI end-to-end evidence.

## Boundaries implemented

- Configuration and keys live in manager process memory only and reset on restart. Public reads return `keyConfigured`, never the key or a fragment. Config/request/provider diagnostic formatting is redacted, including dereferenced provider values. Clearing references is not a guarantee of secure memory erasure or protection from a compromised local process.
- Every configuration save is a complete replacement guarded by an expected revision. There is no silent saved-key reuse for a changed destination. Reading or saving settings performs no provider request or DNS lookup.
- All AI writes retain the manager's exact Host/Origin, CSRF, JSON, path, and loopback boundaries. Config bodies are capped at 8192 bytes; analyze/clear bodies at 1024. Unknown, missing, duplicate, null, or wrong-typed fields are rejected. Analyze receives only a case ID and displayed config revision; the server loads its own evidence.
- Initial local mode accepts literal loopback endpoints. Other destinations require an explicit exact HTTPS origin, a fresh key, and remote-evidence opt-in. LAN/private HTTP is not implemented in this slice. URL credentials, query/fragment ambiguity, unsafe paths, malformed hosts/ports, and mismatched key origins are rejected.
- Public-host DNS answers are all validated before dialing a chosen literal address, removing a second DNS lookup between validation and connection. Private, loopback, link-local, metadata, shared, multicast, reserved/transition and documentation ranges are blocked in public mode, including IPv4-mapped forms and Azure's special platform address. Mixed public/private answers fail closed.
- The transport disables environment proxies, redirects, automatic compression, and keepalive reuse. TLS verification remains enabled with TLS 1.2 minimum. Header, body, connection, response and total-time budgets are bounded. No retries or provider fallback occur. Compatibility with `max_tokens` is an explicit option.
- The provider inserts its configured API key only into the authorization header; it does not insert that configuration field into prompts, results, storage, or ordinary diagnostics. Upstream errors are replaced by static safe messages. Exact and decoded-JSON key echoes are discarded. This is not universal redaction of arbitrary transformed secrets or sensitive evidence.
- The evidence packet selects only bounded case-linked observations and preserves source, time, quality, synthetic labels and IDs. It excludes operator notes, device-name/IP fields, timeline text, and unrelated telemetry. Case title/summary and evidence title/source/detail/value can still contain sensitive content; field selection is not a secret filter.
- The UI shows the selected destination and transmitted field categories, warns that raw evidence is not automatically redacted, and requires confirmation of each manual analysis. Loopback transport is not proof of local inference: a loopback provider may itself forward requests.
- Model output has no tool, shell, URL-fetch, collection, or remediation authority. The service retains the deterministic baseline separately. Responses must meet a bounded strict schema and reference supplied evidence IDs; next steps come only from fixed server-owned read-only runbooks.
- Valid citation IDs do not establish logical support. Root cause remains unconfirmed. Prompt-injection resistance and inference quality are not guaranteed; model text is rendered inertly as suggestions.
- A manager-wide concurrency slot survives config replacement. Replace/clear cancels old work; each request uses an immutable config revision and marks old results superseded. The UI discards canceled/revision-mismatched results and opens citations from the analyzed packet snapshot rather than current same-ID evidence.
- The manager's bounded 35-second write timeout exceeds the 30-second maximum analysis context. Configured state is not represented as a successful provider connection.

## Independent evidence

Executed against the reviewed source:

- `go test -race ./internal/analysis ./internal/api ./tests/security -count=1`: passed.
- `go vet ./internal/analysis ./internal/api ./tests/security`: passed.
- Independent `tests/security/analysis_boundary_test.go`: four test groups passed for dangerous/metadata/ambiguous configuration and key-origin rejection; JSON plus pointer/value diagnostic redaction; redirect refusal with zero target requests; and upstream-key-echo discard.
- Independent `tests/security/run_ai_boundary.py`: six groups passed against a freshly built manager and fake local HTTP providers:
  1. Honest unconfigured baseline.
  2. Guards on config, clear, and analyze.
  3. Atomic malformed/oversized/unsafe-destination rejection.
  4. No save-time request, one explicit analysis, bounded-field exclusions, revision rejection, and secret-free readbacks.
  5. Safe upstream failure without key echo or invented findings.
  6. Global busy rejection and cancel-on-clear with a superseded canceled result.
- Frontend typecheck, build, and all **56 component/unit tests** passed independently. Coverage includes password-field clearing, no app writes of keys to browser storage, explicit destination consent, inert model HTML, stale/canceled result rejection, snapshot citations and strict model/key validation.

All provider test keys are visibly synthetic and test-only. The HTTP harness creates and closes its own loopback mock providers. Do not configure it with a real provider or real key.

## Remaining limits and gates

- Real-provider compatibility, model availability, latency, cost and diagnostic usefulness are untested. A model identifier is configured provenance, not verification of model weights or retention practices.
- The new browser flow requires an exact-source end-to-end result. Component tests alone do not establish browser behavior.
- Before recurring analysis or log scanning, review collection sources, retention, sensitive-text handling, destination approval, cadence/cost limits and failure behavior separately. The manual-case flow does not authorize broader raw-log transmission.
- The localhost guard is still not operator authentication or multi-user isolation. Production use needs authenticated roles/sessions, agent identity/enrollment, protected secrets and audit logs, transport security and an independent deployment review.
