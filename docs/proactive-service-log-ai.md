# Opt-in service-log AI

The existing `health-summary-v1` approval still excludes logs. An existing local
journal grant also does **not** approve AI export. Service-log AI is a separate,
default-off scope (`service-journal-ai-v1`) for complete Linux enrollment.

## One-time administrator review

1. Configure an OpenAI-compatible provider (a local endpoint is supported) and
   explicitly save it in protected manager storage. Saving a keyed provider
   requires the existing separate key-storage acknowledgement.
2. Open **Service-log AI** below the health-summary settings. Review the exact
   provider URL and model, enrolled device and service, and either 5 or 15 minutes
   before each new service incident. Up to eight device/service pairs are allowed.
3. Read the fresh local journal-policy report. It must explicitly allow the exact
   service. This page cannot install a helper, grant local journal access or
   change the local service allowlist.
4. Separately acknowledge future monitoring/captures and provider export. The
   HTTP-test profile requires an additional acknowledgement of unencrypted
   operator transport. None of these boxes is preselected.

Approval adds these exact services to manager-side health monitoring and records
its original time, manager/transport, saved provider revision and credential
identity, device/service, policy generation and data scope. It survives an
ordinary manager restart only while these bindings still match. Provider or
policy changes require renewed review. Saving approval does not collect logs,
test connectivity or invoke a model. Incidents that predate approval are excluded.
Disabling prevents further AI export immediately; any unfinished exact capture
cancellation is explicitly reported and retried until confirmed or expired.

## Automatic path and bounds

A newly confirmed service incident can schedule one fixed journal query for its
approved service and preceding window, priority warning or higher. An existing
manual capture is never replaced or adopted. Request metadata is claimed before
creation; uncertain creation outcomes are not retried. Original source identity,
policy generation, enrollment authority and expiry are revalidated before use.

The local capture retains at most 500 rows, 512 KiB total and 4 KiB/message,
under the existing helper budget. The manager reads at most two bounded snapshot pages to select the latest ten
rows, with at most 1 KiB of text per row. Source projection and export apply the
same best-effort secret masking. This **cannot guarantee removal of credentials,
personal information or other secrets**. Local model endpoints can forward data.
Provider charges may apply.

At most two new log captures and two log analyses are admitted per hour, with a
30-minute device/service cooldown. Model sends also share the existing six-per-
hour health AI ceiling and 60-second spacing; only one model request runs at a
time. Model context/output and provider timeouts retain the existing bounded
adapter limits. Capture windows and row choices are fixed by code and approval,
never by model text. Logs are untrusted evidence, not instructions. There is no
shell, tool execution, service restart or autonomous remediation path.

Each selected row keeps its original timestamp, source-row index and projected
row hash; the query receipt also cites query/snapshot digests and coverage. A
hypothesis must cite available evidence, stays unconfirmed and includes gaps and
fixed read-only next checks. Empty/partial captures do not prove an absent cause.
Reported hostname/IP labels are operator-only display metadata and are not added
to the AI packet. Log text itself may contain identifying information.

## Retention and readback

Journal-backed evidence and model prose are held only in manager memory until
the **original capture expiry**, at most 15 minutes after capture creation. They
are not written into durable health findings or alarm notifications. SQLite holds
only approval/query/attempt metadata for deduplication and status. If both capture-metadata persistence and source cancellation fail, the manager
reports an unconfirmed local capture stop and blocks AI export. It retries only
cancellation of the exact known capture while that identity remains available;
it never guesses ownership or replays an uncertain capture after restart. A
small content-free tombstone retains the original expiry when it can be saved.
A source request already accepted by the endpoint can still finish before its
original expiry if cancellation cannot be confirmed. No model export may use it.

Restart loses
log-backed findings and interrupts unfinished attempts; it does not replay them.
The original local journal capture retains its existing expiry behavior.
Deleting references at expiry is not a cryptographic secure-memory wipe.

Investigations show a content-free status receipt and fetch a finding only when
opened. Reading never starts capture or inference. The browser clears sensitive
content on original expiry, page/background/session loss and changed time
reference. Revocation and unavailable source identity fail closed.

## Validation boundary

Automated tests use invented journal rows and an in-process model adapter;
hosted screenshots use explicitly synthetic intercepted DTOs. They do not prove
that a deployed helper, journal permissions, native service visibility or a real
provider is configured or reachable. Native acceptance still requires the
existing administrator-reviewed local journal setup and explicit deployment
provider/data approval. No actual grant is supplied by this source change.

An unresolved journal-scope storage mutation fence keeps that scope unavailable
after restart; ordinary manager health/inventory startup remains usable. If even
the fence cannot be saved, the API explicitly reports that a durable stop could
not be confirmed, rather than promising restart-safe revocation.
