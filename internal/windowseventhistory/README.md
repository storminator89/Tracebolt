# Bounded Windows event history source

Source-only implementation of a separately consented Application/System search.
It does not activate a scope or prove native Windows acceptance.

- Exactly one fixed channel, a UTC half-open interval `[start,end)`, and optional
  exact numeric level/event-ID filters. The request contract binds at most seven
  days inside the thirty days preceding the original operation creation.
- At most 100 rendered six-field headers and one unrendered lookahead, with a
  separately enforced 256 KiB encoded search-report cap. Query exhaustion is not
  a claim that retained history is complete, immutable, or gap-free.
- Empty exhausted searches are valid. Denied, unsupported, interrupted and stale
  source failures remain unavailable/partial reports with fixed reasons.
- Metadata uses a fixed six-property render context, not XML or broad System
  rendering. Query text is generated only from validated times and typed numbers.
  No raw query, path, remote session, subscription, privilege or write API exists.
- Exact message selections delegate to the unchanged selected-message reader,
  which verifies all six fields again before formatting. The separate request
  stack binds them to the accepted original search receipt/result digest; a new
  selection never refreshes the original fifteen-minute expiry.
- The native source is cooperative for five seconds. The purpose-separated owned
  process worker imposes ten seconds and synchronously kills/reaps on failure.

Synthetic fixtures and cross-compilation neither read native events nor grant
permission to install a service, change access or create credentials. Native
acceptance under the reviewed installed identity remains a separate gate.
