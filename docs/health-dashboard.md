# Device Health dashboard

The device Health tab presents current state before setup and history:

- A summary explicitly limited to agent contact, root filesystem and selected
  service checks. An unresolved alert remains visible when its current evidence
  becomes unknown. Maintenance does not hide existing alerts.
- CPU and memory cards use the same device metadata already displayed by the
  device page. They are readings, not new alarm rules. No overall score or
  whole-device health claim is computed.
- Root filesystem and selected-service cards use the existing Health response.
  An empty service selection is not shown as successful service monitoring.
- Current alerts, pending confirmation and missing evidence show first, with
  original event/observation time and an explicit evidence/logs action.
- Settings, service selection, detailed evidence and history start collapsed.
  The service-inventory reader starts only when settings are opened. Closing and
  reopening settings preserves the unsaved selection; device/session changes
  reset it. Acknowledgement still does not repair or resolve an incident.

Resource values require a matching Linux LAN device, current healthy-quality
percentage metadata and an original collection time within two minutes of the
advancing manager time. A bounded, in-memory device/session/authority clock
watermark retains the elapsed lower bound across refresh, blur and component
remounts, including request-start delay. Equal or tiny timestamp advances cannot
renew old evidence. Missing, invalid, denied, future or stale values are
withheld and labelled; they never become green health. Source times remain in
card tooltips and detailed evidence. A failed Health read removes current cards.

HTTP 404/409 responses remain neutrally unavailable. This UI does not infer
"not configured" or "expired" from a generic backend error. The backend evaluator,
thresholds, maintenance policy, authentication, existing mutation permissions,
external alarm configuration and remote action boundaries are unchanged.

## Verification

Focused component and integration checks cover clear/no-selected-service,
complete selected-service, current issue, stale/missing/denied readings, first
assessment and unavailable states; metadata identity binding; source-age expiry;
retained incident uncertainty; keyboard disclosures; focus and dirty selection;
request deadlines; repeated saves; access loss; and device/session/navigation
isolation. Existing service-to-logs tests continue requiring a separate capture
confirmation.

The existing Investigations/Health LAN browser case also checks these states and
captures the production dashboard at desktop/mobile sizes in English and German.
It uses real loopback fixture login with invented intercepted DTOs and keeps
write/external-request guards. It adds no LAN case registration or send action.
The hosted browser artifacts must be inspected on the exact composed source
before visual acceptance or user rollout is claimed. Local component/fixture
checks alone are not screenshot, native-agent or deployment acceptance.

## Windows observations

Windows uses a separate [read-only observation summary](windows-health-observations.md)
for accepted contact and caller-visible system-volume usage, alongside existing
event headers. It has no durable incidents, Linux alarm thresholds or AI-health
authority. The Linux evaluator and its inputs remain unchanged.
