/** Browser assertions and independent DOM regressions share these expected
 * meanings. Production copy remains separate, so a future edit must update
 * this contract and pass actual component rendering before hosted capture. */
export const conciseCopy = {
 endpointPermission: 'Off by default. Requires protected, identity-bound local administrator consent. The manager cannot verify the current local setting.',
 applicationDNS: 'DNS uses system resolution, including hosts, cache or search domains. Every returned address needs approval; this is not a complete, authoritative DNS record.',
 applicationApprovalDE: 'Exakte Ziele und IPs freigeben; LAN und unverschlüsseltes HTTP separat bestätigen.',
 alarmBrowserTime: 'Loaded time is this browser’s time, not an event or server observation. Refresh reads saved counts.',
 journalReference: 'Reference time may be old. Refresh status, then choose a window; this does not capture logs.',
 journalReferenceLabel: 'Last checked manager time (UTC)',
 journalPaused: 'Content paused. Return here or refresh status to recheck access; no new capture starts.',
 fleetMore: '+2 more',
};
