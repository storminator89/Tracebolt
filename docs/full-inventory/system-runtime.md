# Managed-v3 system-observation integration

This MVP combines complete supported dpkg generations with separate periodic
service/socket observations under the same fresh managed-operations-v3 consent.
The source and transport retain their separately documented limits. No network
scan, command line/environment, raw log body, account identity or AI export is
added. Local socket binding does not establish external reachability.

The native sender requires three existing private sequence domains before any
collection: metrics, chunked packages and system observations. Fresh enrollment
initializes all three before publishing agent.json/ready.json. Missing or
incompatible state is never re-created by one-shot, foreground or pending-service
startup. The system state is a separately bound instance of the reviewed one-body
sender storage design, with a1MiB+4KiB body cap and2MiB encoded-state cap. New
create-only constructors reject existing state without cleaning temporary files.

Foreground attempts serialize metrics, one system observation, then at most64
package protocol operations. Each stage has a20-second cooperative budget; the
service/socket collector has its own15-second cooperative source budget. These
are not hard bounds on synchronous filesystem operations. Normal package burst
exhaustion is explicit pending progress and does not trigger failure backoff.
Transport failures retain exact bytes. Old system observations may be discarded
as stale while preserving the consumed floor; package generations require their
explicit receipt/status/abort protocol. No retry refreshes collection timestamps.

System requests use the dedicated /v3/agent/system-observation path, a strict
three-field frame and independent generation/sequence domain. Explicit HTTP-test
has separate signed headers/domain and remains unauthenticated in the server-to-
agent direction. TLS uses ordinary dedicated-issuer verification. The same global
work limit and possession-first per-certificate exclusion guard both. Final save
rechecks current identity, profile, leaf, revocation and replay in one transaction.

Operator metadata is GET /api/devices/{id}/inventory/system. Generation-pinned
pages use a CSRF/Origin-protected POST to /query, with fresh trusted time acquired
after body validation and the session lease. The page includes a server clock,
section generation, original metadata, scan/exhaustion counts and opaque cursor.
Responses are capped at256KiB; the UI requests100 services or25 sockets per page.
Expired/replaced generations return conflict, never an empty successful list.

Acceptance must distinguish source/fixture tests, actual loopback runtime,
background process restart, installed systemd service, and real OS reboot. None
of these automatically establishes the others. The service uses the existing
least-privilege sandbox; unavailable sources/attribution stay explicit.
