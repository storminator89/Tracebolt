# Evidence-grounded AI diagnostics

## Current scope

The separately approved [proactive health workflow](proactive-ai-diagnostics.md)
now reuses this adapter for typed stored health summaries. It is default-off,
independent of manual case export, and does not search or transmit raw logs.
The separate [one-time network observation review](application-network-checks.md#optional-one-time-ai-review)
requires its own confirmation and does not extend that health scope.

`internal/analysis` provides a replaceable model-provider interface, a pure evidence-packet composer, a deterministic case baseline and an optional OpenAI-compatible Chat Completions adapter. It does not install or download a model, discover services, collect logs, schedule recurring work, execute checks or remediate a device. Tests use in-process fake providers and loopback HTTP servers only. No real model quality, endpoint credentials or customer incidents have been evaluated.

The package is independently usable; manager settings and UI routes are a separate integration. A missing provider is explicitly `not_configured`. An error never produces a fabricated AI result, and existing rule output remains separately labeled. A successful response means its structure and citation identities passed validation, **not that its explanation is correct**.

The complete Linux LAN manager additionally supports explicit
[protected restart-safe provider/scope settings](ai-settings-persistence.md).
Session-only remains the default. Key storage requires a separate choice;
no old configuration is silently migrated or contacted.

Provider identity and generation calls are isolated from provider panics: the
panic value is not exposed, and the attempt reports `unavailable` without a retry.
An admitted background attempt still passes its existing final authority checks
and attempts finalization under its existing scope. If the durable write fails,
the existing running/interrupted handling remains in effect. A provider may
already have received the data; this handling does not establish whether
transmission took place.

## Data flow and composition

1. Load a case and its available evidence from the trusted store. A browser request must not supply an arbitrary prompt, provider URL, model name or replacement evidence.
2. `BuildPacket(case, evidence)` selects only IDs referenced by that case. Identical duplicates are collapsed; conflicting observations with the same ID are rejected. It sorts successfully collected observations before stale/unknown/denied data, then newest first, with ID as a stable tie-breaker. This is deterministic prioritization, not a learned relevance ranking.
3. Preserve each selected observation's ID, title, source, quality, detail, value and synthetic flag. Timestamps are normalized to UTC without changing their instant. Case context includes ID, title, summary, category, rule/runbook identifiers, creation/update times and its synthetic flag.
4. Report missing referenced IDs and stale/unavailable observations as explicit gaps. The observation window is the earliest/latest available timestamp, not evidence of continuous coverage. Missing healthy timestamps and ambiguous/oversize inputs fail closed. No evidence is silently truncated.
5. Keep device names, device IDs/IPs, case notes, timeline entries, unrelated evidence and case-supplied next-step prose out of the packet. Fixed read-only runbooks come from server code.
6. Send a fixed system instruction and a separate JSON-encoded, untrusted user-data message. Strict structured output is requested and independently validated afterward.

This field selection is **not secret redaction**. A password, personal information or sensitive text embedded in a selected title, summary, source, detail or value would still be transmitted. Current collectors avoid many such fields, but that is not a guarantee for future log inputs. Before enabling a remote destination, review the exact packet preview and destination and obtain explicit approval. Raw-log scanning and broader collection need their own bounded source/retention/redaction policy; they must not inherit approval from this slice.

### Hard limits

| Boundary | Limit |
| --- | --- |
| Source observations considered | 128 |
| Case evidence references / selected observations | 32 |
| Serialized evidence packet | 24 KiB |
| Evidence source/detail/value and case summary | 2,048 UTF-8 bytes each |
| Complete provider request | 64 KiB |
| Provider response envelope / headers | 64 KiB / 8 KiB |
| Model's findings JSON | 16 KiB |
| Observed/cited IDs | 32, unique and known |
| Hypotheses / counterevidence | 5 each |
| Missing-data statements | 8 |
| Each model statement | 512 UTF-8 bytes |
| Requested completion limit | 1,024 tokens |
| Provider timeout | 15 seconds by default, at most 30 seconds |
| Concurrency | One call per reused service/provider, no waiting queue |

These are client/request boundaries. A third-party compatible server must honor its token/resource settings; a client deadline cannot prove its inference process stopped. No automatic retries, alternative-model attempts or provider fallback are made. The manager should also enforce one global active analysis across provider/configuration replacements.

## Provider configuration and destination boundary

The primary adapter uses `POST <baseURL>/chat/completions`, normally with a base URL ending in `/v1`. Its wire contract includes `response_format.type = json_schema`, a strict schema, `stream = false`, `store = false`, one completion, and `max_completion_tokens = 1024`. An explicit `UseLegacyMaxTokens` choice substitutes `max_tokens` for compatible servers requiring that field. There is no automatic compatibility downgrade or second call. Providers must support this bounded structured-output subset; compatibility with every OpenAI-like implementation is not asserted.

The constructor performs validation only, with no DNS lookup or connection. Configuration is trusted server-side state:

- `BaseURL` and `Model`: fixed for the lifetime of a provider; never model/log/request-controlled during analysis.
- `APIKey`: process memory only in this package, omitted from JSON and ordinary value/pointer diagnostic formatting. The package never writes a settings file, key, request body or upstream body to logs.
- `APIKeyOrigin`: required with a key and must equal the exact configured scheme/authority. Replacing the destination must not silently retain a previous key. A settings implementation must replace credentials explicitly, return only a `keyConfigured` boolean, and never read the key back to a browser.
- `AllowedHTTPSOrigins`: exact, trusted operator-approved origins. It cannot be populated from an analyze request or model response. Approval should name the destination and transmitted evidence categories.
- `Timeout` and `UseLegacyMaxTokens`: bounded request controls; no per-analysis arbitrary options.

The original local mode accepts only literal `127.0.0.1` or `::1`. HTTP is permitted only there. Public destinations require HTTPS plus explicit exact-origin allowlisting. DNS names are resolved at connection time, **all** returned IPs must pass the public-address policy, and the dialer connects to one vetted literal IP.

An additional, explicitly confirmed LAN mode accepts only an exact RFC1918 IPv4
literal with an explicit port and HTTPS. The manager must trust the server's
certificate through its system trust store and the certificate must include that
exact IP address as an IP subject alternative name. LAN mode does not resolve DNS,
use environment proxies, follow redirects or fall back to another destination.
It is held in manager process memory and is cleared on restart; it is not part of
the protected persistent provider format. Selecting it requires a separate
destination acknowledgement and evidence-sharing approval. Each manual analysis
and the proactive health scope retain their own existing approvals. Configuration
alone does not contact the provider. This source feature does not install a model
server or change trust on a host.

For a private CA, the authenticated HTTPS operator may instead choose the
separate private-CA LAN option. Supply one public, currently valid, self-signed
CA certificate and independently compare its SHA-256 DER fingerprint before
entering and explicitly confirming that value. The manager checks the certificate
and fingerprint itself and trusts only that CA for this provider. Standard TLS
chain, expiry and exact IP-SAN checks still apply; system roots are not a
fallback in this mode. No private key is needed or accepted. The public CA and
provider configuration remain in process memory; the readback exposes only the
fingerprint. To change a provider with a private CA, explicitly remove it first
and then approve the new configuration. This also invalidates the old proactive
scope. Neither importing the CA nor saving a provider contacts the destination.

All modes keep normal TLS validation. Link-local, multicast, unspecified, shared,
transition and known metadata/platform addresses remain blocked, including
IPv4-mapped bypasses. A LAN endpoint, like loopback, does not establish local
inference or prevent a server from forwarding data elsewhere.

URLs containing credentials, query strings, fragments, escapes or traversal paths are rejected. Redirects of every status, proxy-from-environment, compression and connection reuse are disabled. Keys are sent only as an Authorization header to the configured origin. Raw error bodies are discarded. Straightforward and JSON-decoded key echoes are also discarded, but this is not general-purpose detection of arbitrary encodings or sensitive text.

A loopback server may forward data to another system. A local URL does not establish local inference or cloud-free operation. Operators must review the server's own routing, model, egress and retention settings; the result labels it `loopback-server`, not `verified-local-model`. `store = false` is a request, not a retention guarantee for every compatible vendor. For an Ollama-compatible deployment, its documented cloud-disable setting is an additional operator-side control, not something this adapter changes or independently verifies.

## Explicit provider test

After saving a provider, an administrator can review the displayed destination
and model and explicitly start one test. It sends a fixed synthetic case and
observation through the same provider transport and structured-output validation
as a manual analysis. It does not read or send stored cases, device telemetry or
logs, and it neither enables proactive analysis nor runs a device action. An
already configured key, if any, is sent only in the normal authorization header
to that exact provider. The provider can still forward the request or apply its
own resource charges and retention policy.

The result reports only bounded status and is not saved. A pass means that the
synthetic request returned a response accepted by the existing schema and citation
validator; it does not establish model quality, future availability or local-only
inference. Failure, cancellation and an uncertain response are not automatically
retried. Canceling locally cannot recall bytes already sent to the provider. The
test shares the existing global analysis slot and exact configuration revision;
configuration changes or loss of the active operator session observed before
response publication invalidate the result. The final check is a snapshot: a
change immediately afterward can race response delivery, and a returned result
does not prove that the provider remains available or the configuration remains
current. The response includes the tested revision so clients can discard it
when they observe a newer configuration.
No real provider, credentials or customer data are used by the automated fixtures.

Protocol references: [OpenAI Chat Completions](https://developers.openai.com/api/reference/resources/chat) and [structured model outputs](https://developers.openai.com/api/docs/guides/structured-outputs). Ollama's [cloud-disable documentation](https://docs.ollama.com/faq#how-do-i-disable-ollama-cloud-features) explains its server-side local-only control. These informed the wire format and deployment cautions; no external service was invoked to validate interoperability.

## Result contract and interpretation

`NewService(provider).Analyze(ctx, storedCase, availableEvidence)` returns a `Result` or an input-validation error. Reuse the service across calls. `NewService(nil)` returns the baseline plus a not-configured AI state without making a request.

The result includes:

- A random per-attempt `id`, UTC `generatedAt`, the actual bounded evidence packet and its observation window/gaps.
- A stable `fingerprint` derived from the packet and provider/model/prompt/runbook configuration. It is a future deduplication input, not a claim that repeated model output is deterministic or that two events are the same incident.
- `baseline`: the existing case summary, available evidence IDs and fixed rule runbook. It is labeled `method: rules` and does not pretend the rules were rerun on unseen live signals.
- `ai`: a separate status, safe reason, optional findings and server-selected read-only runbook steps. Status is `not_configured`, `completed`, `unavailable`, `timeout`, `canceled`, `busy` or `invalid_response`.
- Provenance on both branches: method, provider, configured model label, prompt/runbook versions, case rule ID, packet SHA-256, destination class and origin. The label does not attest actual model weights or a provider-reported model version.
- `rootCauseConfirmed: false` and explicit interpretation/security limitations. Provider errors/timeouts/cancellation leave `findings: null`.

Findings have exactly these fields:

```json
{
  "observedEvidenceIDs": ["disk-used"],
  "hypotheses": [{"statement": "A tentative explanation requiring review.", "evidenceIDs": ["disk-used"]}],
  "counterevidence": [],
  "missingData": ["A follow-up observation is missing."],
  "nextCheck": "storage"
}
```

Every claim cites at least one known, explicitly observed ID. Unknown fields/IDs, duplicate JSON keys, multiple JSON values, invalid/null/missing arrays, excessive nesting, invalid UTF-8, oversized text and non-enumerated checks are rejected. The only check values are `none`, `service`, `storage`, `network`; their steps are looked up in the existing read-only runbooks. Function/tool calls, refusals and truncated completions are rejected. Free-form commands are never executed.

Prompt separation and schema validation reduce attack surface but cannot guarantee resistance to instructions embedded in logs/evidence. A malicious or mistaken model can still make a false claim with valid citation IDs. Tests explicitly demonstrate that structural validity does not imply entailment. Render all model/evidence strings as inert text; do not interpret them as HTML, links to follow, shell commands, data-access permissions or confirmed causes.

## Manager/UI integration contract

The intended user flow is native case investigation with an explicit analyze action, not an unrestricted chatbot:

1. Configure the base URL/model and, if needed, a newly entered key through a CSRF-protected manager settings flow. Saving configuration must not make a test/inference request automatically. Keep key storage separate from ordinary case SQLite data and browser/local storage; the initial in-memory configuration resets on manager restart. The complete LAN manager can instead retain an explicitly saved protected configuration under the linked persistence contract.
2. For a remote provider, show the exact destination and data-field categories, and obtain explicit consent. Treat an origin change as a fresh approval/key-binding decision.
3. Prepare the exact stored-case packet through the protected preview endpoint below, then explicitly approve that one expiring snapshot and configuration revision. Apply the manager's loopback/Host/Origin/CSRF/body boundary and manager-wide concurrency guard. Cancel active old-config requests when settings change; mark an old response superseded before display.
4. Display deterministic findings and AI suggestions separately. Link citations to the matching packet evidence, surface missing/stale/synthetic context, and keep the uncertainty label visible even after successful validation.
5. Do not auto-run `nextCheck`, store a model statement as an observed fact, resolve a case, or schedule a recurring scan from this response.

## Exact manual case preview (TB-24 bounded slice)

Manual case analysis now requires **Review AI analysis → review the exact packet
and destination → explicitly confirm**. The dialog displays the server-prepared
canonical JSON data message, its SHA-256, saved URL/model and original two-minute
review expiry. Its title and evidence count come from this packet, not the
browser's possibly older case card. Missing evidence, collection quality,
timestamps, synthetic labels and gaps are included without silently truncating
or substituting the source. JSON/evidence/model text is rendered inertly.

- `POST /api/cases/{caseId}/analyze-preview` accepts exactly `{}` under the existing
  administrator, same-origin, CSRF and strict body boundaries. It calls the same
  `BuildPacket` provenance/bounds gates and makes **no provider call**. The response
  contains `schemaVersion: tracebolt.case-analysis-preview.v1`, `caseId`,
  `configRevision`, `baseURL`, `endpointOrigin`, `model`, `packetJSON`,
  `packetSHA256`, `serverNow`, `validUntil` and `previewToken`. The packet remains at most 24 KiB.
- `POST /api/cases/{caseId}/analyze` accepts exactly `configRevision`,
  `previewToken`, `packetSHA256` and `acknowledge: true`. Old revision-only requests
  fail closed. Browsers cannot supply a prompt, destination, model or replacement
  packet. The manager rebuilds the current trusted case packet, compares its hash
  with the preview's server-owned binding, and passes that **same case snapshot**
  to the existing deterministic builder and provider service. If the stored packet
  changed since review, the operator must prepare and approve a new preview.
- A random 256-bit token binds one case, exact packet hash, provider revision and
  operator session. It expires after two minutes or the earlier session deadline.
  There are at most 128 pending previews per manager. Expired entries are pruned
  before admitting another preview; capacity failure never evicts an active
  approval or sends data. Pending records retain **metadata only**, not packet,
  key, log or model prose, and are never persisted. Logout removes that session's
  previews; provider replacement/clear and a detected storage fence clear them.
- An owner-confirmed, well-formed current-revision attempt consumes its token
  before provider admission, including packet/hash/case/expiry mismatch or a busy
  slot. An unknown token or another session never consumes somebody else's token.
  A failure, lost response or local cancellation never automatically retries.
  Preparing a new preview after an uncertain call is a **new explicit attempt**
  and may incur another provider charge; this is not durable incident deduplication.
- A change after admission cannot substitute newer evidence: the call uses the
  already checked trusted snapshot. Config/session cancellation still applies;
  already sent bytes cannot be recalled. Returned results include `previewToken`
  and the same packet hash in provenance. The browser checks token, provider
  revision/destination/model, complete packet values and both provenance hashes,
  and discards late/canceled/superseded results. Case/settings changes and expiry
  clear the dialog/consent. Snapshot/config final checks do not promise that the
  world remains unchanged after response delivery.

This is **not secret redaction**: a secret embedded in an allowed title, summary,
source, detail or value is still present in the preview and would be sent after
approval. Pattern masking from another AI scope must not be inferred here. The
human must review those texts; unrecognized secrets and identifying information
remain a review responsibility. Neither this preview nor a LAN/loopback URL
proves local processing or provider retention behavior. Key readback, protected
plaintext-storage disclosures, credential origin binding, managed-profile export
blocks, prompt/schema separation and the absence of tool/action authority remain
unchanged.

### Path inventory and remaining TB-24 gates

| Path | Existing approval/export boundary | Status in this slice |
| --- | --- | --- |
| Manual stored case (`BuildPacket` / `Analyze`) | Exact bounded packet plus one case/session/provider approval | New exact preview/export binding; no raw log or managed-profile promotion |
| One-time DNS/TCP review (`AnalyzeNetworkReview`) | Own source-generation/current-observation and session-bound one-time review | Unchanged; not a manual-case token |
| Proactive health (`AnalyzeHealth`) | Default-off exact provider/device `health-summary-v1`; typed summary, claim-before-call | Unchanged; category/scope review is not a new per-incident exact-packet preview |
| Proactive service-log (`AnalyzeJournal`) | Separate default-off exact provider/credential/device/service/policy/window/capture/export acknowledgements | Unchanged; best-effort scope-specific masking, bounded memory-only content |
| Explicit provider test (`TestProvider`) | Exact provider revision and fixed synthetic fixture only | Unchanged; never substitutes customer evidence or grants ongoing export |

Synthetic contract fixtures compare the canonical preview against the actual
fake provider user message and returned packet/hash; cover excluded-field markers,
instruction-like text, changed/expired/wrong-session/wrong-case/hash/provider
bindings, replay, strict bodies/CSRF and capacity. They do not establish model
semantic compliance, comprehensive secret masking, real-provider interoperability,
quality improvement or native/deployed acceptance. No real provider, key or user
telemetry is required for these fixtures. A held-out diagnosis comparison with
evidence IDs and a no-model baseline, real destination review and an appropriate
proactive review UX remain separate TB-24 gates; this slice does not close the
whole issue or authorize any new provider/scope/host configuration.

## Evaluation fixture plan and release gates

The unit and fake-server tests are contract/security regressions. They are not a diagnosis benchmark. Before enabling real inference, assemble a separately approved, de-identified fixture set with incident-owner review and an explicit destination policy. Start from the same bounded packets available to the operator; do not expose post-resolution facts to a model or baseline reviewer while judging initial diagnosis.

Each review fixture should contain: a fixture ID and split, incident/category label, bounded case/evidence packet, observation window, source/quality flags, missing-data annotations, allowed runbook set, independent human baseline, later adjudicated cause when actually established, source/consent record, and a reviewer rubric. Keep sensitive originals outside the repository. Synthetic fixtures must remain conspicuously synthetic.

| Fixture family | Required evidence/control | What reviewers judge |
| --- | --- | --- |
| Service stopped | Required-service policy plus observed state; include intentionally stopped services as negative controls | Distinguishes policy violation from a proven cause; does not prescribe a restart as an executed action |
| Capacity pressure | Volume usage and separated observation times; no unnecessary file contents | Explains observed pressure, asks for bounded trend/context, does not invent failing hardware or auto-delete files |
| DNS failures | Failure window, interface state and explicitly missing resolver/dependency information | Maintains alternatives and uncertainty; does not infer Internet reachability from link-up alone |
| Sparse/stale/denied input | Missing IDs, old timestamps, denied or unsupported observations | Abstains appropriately and prioritizes a useful permitted next check |
| Contradictory evidence | Conflicting observations with distinct IDs/sources/times | Surfaces counterevidence instead of silently choosing the convenient source |
| Injection and privacy | Instructions/URLs/tool requests embedded in every free-text input; fixture-only secret markers | Does not gain tools/destinations/authority; reviewers assess semantic compliance beyond schema validity |

Have at least two independent humans review the same initial packets before seeing model suggestions; adjudicate disagreements and preserve unresolved cases. Separate prompt-development fixtures from a held-out incident set, split by incident/device so near-duplicates do not leak across splits. Compare against the deterministic baseline and a human-only workflow using the same available evidence.

Record per-run provider/version configuration, configured model and verified local model digest when available, prompt/runbook versions, packet hash, latency, input/output token usage when reliably reported, resource/cost budget, cancellation behavior and reviewer outcome. Score citation entailment, unsupported causal claims, missed counterevidence, missing-context requests, safe/useful next checks, appropriate abstention and investigation time. Record failure cases as well as successes. Do not publish quality/accuracy/speed claims until the held-out evaluation actually runs and its limitations are documented.

Recurring log review/dashboard alerting remains a later feature. Its prerequisite design must specify approved sources/time windows, sensitive-data handling, per-device and global collection/inference budgets, cadence, overlap/deduplication, cancellation, severity review, retention and alert suppression. The current fingerprint/window/provenance fields support that design but do not implement a scheduler or log collector.

## Reproducible verification

```sh
go test -race ./internal/analysis
go vet ./internal/analysis
```

The suite exercises packet bounds/provenance/deduplication, schema/citation rejection, disabled mode, injection-string data separation, safe error states, timeout/cancellation/single-flight behavior, exact-origin key binding, secret-safe formatting, fake-server success/error/oversize paths, redirects, environment proxy suppression, fixed output-token settings, DNS/IP policy and mapped/metadata address rejection. It does not establish privacy completeness or diagnostic quality.

### One local inference compatibility check

On 2026-10-29, source revision `2f1ce63` was tested on Windows/amd64 using
llama.cpp build `b11978` and Qwen2.5-1.5B-Instruct Q4_K_M. The release archive
SHA-256 was `ad44d0b353d1f260263943b399d932b146e3ecf983218c7c5efd7d782b774c86`;
the model file from revision `91cad51170dc346986eccefdc2dd33a9da36ead9` was
`6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e`.
Both were checked against their published values before use. A foreground CPU server was restricted
to `127.0.0.1`, with web UI and agent mode disabled and no API key configured; it was
stopped after the test. The production `analysis.Service.TestProvider` sent
one synthetic request and returned `passed`, meaning the response passed the
existing schema and citation validation. The server reported about 12.4 seconds
for 733 input and 49 output tokens with two CPU threads; this is one observation,
not a performance guarantee. No real device telemetry or model prose is recorded.

A second, explicitly selected Vulkan run used the same model and synthetic test
with the `b11978` Windows Vulkan archive (SHA-256
`b26bdfe4fa99fc077241d431320035dbd5a1153bf23b9f5cd5119966681bb5d6`).
The server listed an NVIDIA GeForce GTX 1060 6 GB as `Vulkan0`, was configured
to offload layers to that device, and the synthetic test again returned `passed`.
It reported about 4.5 seconds for 733 input and 125 output tokens. Observed GPU
memory usage rose by roughly 1 GiB after loading; per-request GPU utilization was
not measured. This is one synthetic result, not a throughput or quality benchmark.

This check does not establish the quality of a diagnosis, cloud-free execution
under every deployment, GPU utilization during inference, behavior for larger packets, integration
with a running LAN manager, TLS/private-CA routing, autonomous repairs, or a
published artifact. The server's reported time is close to the default 15-second
provider timeout. Repeat acceptance with the actual chosen model, deployment,
permissions and approved data before relying on it.
