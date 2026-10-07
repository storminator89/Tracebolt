# Evidence-grounded AI diagnostics

## Current scope

The separately approved [proactive health workflow](proactive-ai-diagnostics.md)
now reuses this adapter for typed stored health summaries. It is default-off,
independent of manual case export, and does not search or transmit raw logs.

`internal/analysis` provides a replaceable model-provider interface, a pure evidence-packet composer, a deterministic case baseline and an optional OpenAI-compatible Chat Completions adapter. It does not install or download a model, discover services, collect logs, schedule recurring work, execute checks or remediate a device. Tests use in-process fake providers and loopback HTTP servers only. No real model quality, endpoint credentials or customer incidents have been evaluated.

The package is independently usable; manager settings and UI routes are a separate integration. A missing provider is explicitly `not_configured`. An error never produces a fabricated AI result, and existing rule output remains separately labeled. A successful response means its structure and citation identities passed validation, **not that its explanation is correct**.

The complete Linux LAN manager additionally supports explicit
[protected restart-safe provider/scope settings](ai-settings-persistence.md).
Session-only remains the default. Key storage requires a separate choice;
no old configuration is silently migrated or contacted.

## Data flow and composition

1. Load a case and its available evidence from the trusted store. A browser request must not supply an arbitrary prompt, provider URL, model name or replacement evidence.
2. `BuildPacket(case, evidence)` selects only IDs referenced by that case. Identical duplicates are collapsed; conflicting observations with the same ID are rejected. It sorts successfully collected observations before stale/unknown/denied data, then newest first, with ID as a stable tie-breaker. This is deterministic prioritization, not a learned relevance ranking.
3. Preserve each selected observation's ID, title, source, quality, detail, value and synthetic flag. Timestamps are normalized to UTC without changing their instant. Case context includes ID, title, summary, category, rule/runbook identifiers, creation/update times and its synthetic flag.
4. Report missing referenced IDs and stale/unavailable observations as explicit gaps. The observation window is the earliest/latest available timestamp, not evidence of continuous coverage. Missing healthy timestamps and ambiguous/oversize inputs fail closed. No evidence is silently truncated.
5. Keep device names, device IDs/IPs, case notes, timeline entries, unrelated evidence and case-supplied next-step prose out of the packet. Fixed read-only runbooks come from server code.
6. Send a fixed system instruction and a separate JSON-encoded, untrusted user-data message. Strict structured output is requested and independently validated afterward.

This field selection is **not secret redaction**. A password, personal information or sensitive text embedded in a selected title, summary, source, detail or value would still be transmitted. Current collectors avoid many such fields, but that is not a guarantee for future log inputs. Before enabling a remote destination, show exactly these field categories and obtain explicit approval. Raw-log scanning and broader collection need their own bounded source/retention/redaction policy; they must not inherit approval from this slice.

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

Initial local mode accepts only literal `127.0.0.1` or `::1`. HTTP is permitted only there. Non-loopback destinations require HTTPS plus explicit exact-origin allowlisting. Private/LAN, link-local, multicast, unspecified, shared, transition and known metadata/platform addresses are rejected, including IPv4-mapped bypasses; LAN support needs a separately reviewed policy. DNS names are resolved at connection time, **all** returned IPs must pass the policy, and the dialer connects to one vetted literal IP. TLS retains standard hostname/certificate validation. The app does not bypass certificate warnings.

URLs containing credentials, query strings, fragments, escapes or traversal paths are rejected. Redirects of every status, proxy-from-environment, compression and connection reuse are disabled. Keys are sent only as an Authorization header to the configured origin. Raw error bodies are discarded. Straightforward and JSON-decoded key echoes are also discarded, but this is not general-purpose detection of arbitrary encodings or sensitive text.

A loopback server may forward data to another system. A local URL does not establish local inference or cloud-free operation. Operators must review the server's own routing, model, egress and retention settings; the result labels it `loopback-server`, not `verified-local-model`. `store = false` is a request, not a retention guarantee for every compatible vendor. For an Ollama-compatible deployment, its documented cloud-disable setting is an additional operator-side control, not something this adapter changes or independently verifies.

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
3. Analyze only a stored case under a specific configuration revision. Apply the manager's loopback/Host/Origin/CSRF/body boundary and a manager-wide concurrency guard. Cancel active old-config requests when settings change; mark an old response superseded before display.
4. Display deterministic findings and AI suggestions separately. Link citations to the matching packet evidence, surface missing/stale/synthetic context, and keep the uncertainty label visible even after successful validation.
5. Do not auto-run `nextCheck`, store a model statement as an observed fact, resolve a case, or schedule a recurring scan from this response.

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

The suite exercises packet bounds/provenance/deduplication, schema/citation rejection, disabled mode, injection-string data separation, safe error states, timeout/cancellation/single-flight behavior, exact-origin key binding, secret-safe formatting, fake-server success/error/oversize paths, redirects, environment proxy suppression, fixed output-token settings, DNS/IP policy and mapped/metadata address rejection. Public network calls, real credentials, actual local inference, privacy completeness and diagnostic quality are untested by design.
