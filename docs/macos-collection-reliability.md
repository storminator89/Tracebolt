# macOS network collection budget boundary

This source-only correction makes the passive interface adapter check its shared
provider context before either fixed command. If IPv4 completes and that context
has ended at the next check, it preserves the independently parsed IPv4 result
and marks IPv6 unavailable for budget exhaustion without attempting it. A
timeout of the IPv4 command alone does not block IPv6 while the shared provider
context remains live. The Darwin fixed-command runner also refuses an already
canceled context before attempting to start its child.

Portable synthetic tests cover those call-order and quality outcomes. They do
not exercise native `ifconfig`, prove its output schema or establish interface
coverage on either macOS architecture. The earlier native interface rejection
remains unresolved; there is no parser relaxation, new provider, log collection,
scope activation, host permission or release evidence in this change.
