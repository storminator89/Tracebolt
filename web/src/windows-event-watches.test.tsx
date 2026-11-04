// @vitest-environment node
// Node-only source contracts and server rendering. No browser or DOM acceptance.
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { EventWatchEditor, WindowsEventWatches, WindowsEventWatchPanel, eventWatchCopy } from './windows-event-watches';
import { eventWatchConfirmed, eventWatchTime, validEventWatchSelector, validEventWatches } from './windows-event-watches-types';
import type { EventWatchRequest, EventWatchesView } from './windows-event-watches-types';
import { eventWatchElapsed } from './windows-event-watches-resource';
const id = 'agent_' + 'a'.repeat(32), source = 'eventsource_' + 'b'.repeat(32), requestId = 'eventrequest_' + 'c'.repeat(32);
function fixture(): EventWatchesView { return {
    schemaVersion: 'tracebolt.windows-event-watches.v1', deviceId: id, serverNow: '2026-11-04T20:00:00Z', validUntil: '2026-11-04T20:00:30Z', revision: 0, canManage: true,
    source: { token: source, available: true, collectedAt: '2026-11-04T19:59:55Z', receivedAt: '2026-11-04T19:59:56Z', reason: 'none', choices: [{ channel: 'Application', provider: 'Exact Provider', eventId: 1000, level: 2 }] },
    policy: { enabled: false, selectors: [], enabledAt: null, retentionAcknowledged: false }, status: 'disabled', incidents: [], retentionDays: 7, maxSelectors: 4, maxIncidents: 100, lastRequest: null,
}; }
function incident(v = fixture()) { v.incidents.push({ id: 'wevent_' + 'd'.repeat(16), selector: v.source.choices[0], firstObservedAt: '2026-11-04T19:59:55Z', lastObservedAt: '2026-11-04T19:59:55Z', firstReceivedAt: '2026-11-04T19:59:56Z', lastReceivedAt: '2026-11-04T19:59:56Z', countLowerBound: 1, reviewedAt: null }); return v; }
describe('strict sampled-event watch contract', () => {
    it('runs without a DOM environment', () => { expect(typeof document).toBe('undefined'); });
    it('accepts disabled default and a bounded private observation', () => { expect(validEventWatches(fixture(), id)).toBe(true); expect(validEventWatches(incident(), id)).toBe(true); });
    it('rejects foreign devices, unsafe revisions, expanded retention and extra private fields', () => {
        for (const patch of [{ deviceId: 'agent_' + 'e'.repeat(32) }, { revision: -1 }, { revision: Number.MAX_SAFE_INTEGER + 1 }, { retentionDays: 8 }, { maxSelectors: 5 }, { message: 'private raw event' }]) expect(validEventWatches({ ...fixture(), ...patch }, id)).toBe(false);
        const v = fixture(); expect(validEventWatches({ ...v, source: { ...v.source, recordId: '100' } }, id)).toBe(false);
    });
    it('accepts only exact bounded Application/System selectors with no wildcard interpretation', () => {
        const s = fixture().source.choices[0];
        expect(validEventWatchSelector({ ...s, provider: '* [literal]' })).toBe(true);
        for (const patch of [{ channel: 'Security' }, { eventId: -1 }, { eventId: 65536 }, { eventId: 1.5 }, { level: 256 }, { provider: '' }, { provider: 'bad\nprovider' }, { provider: 'x'.repeat(257) }, { message: 'raw' }]) expect(validEventWatchSelector({ ...s, ...patch })).toBe(false);
    });
    it('matches backend Unicode provider exclusions without rejecting valid surrogate pairs', () => {
        const s = fixture().source.choices[0];
        for (const forbidden of ['\u0001', '\u0085', '\u200b', '\u202e', '\u2028', '\u2029', '\ufffd', '\ud800', '\udfff']) expect(validEventWatchSelector({ ...s, provider: `A${forbidden}B` })).toBe(false);
        expect(validEventWatchSelector({ ...s, provider: 'Provider 😀' })).toBe(true);
        expect(validEventWatchSelector({ ...s, provider: '😀'.repeat(128) })).toBe(true);
        expect(validEventWatchSelector({ ...s, provider: '😀'.repeat(129) })).toBe(false);
    });
    it('rejects duplicate choices and consent-free enabled policies', () => {
        const v = fixture(); v.source.choices.push(v.source.choices[0]); expect(validEventWatches(v, id)).toBe(false);
        const enabled = fixture(); enabled.policy = { enabled: true, selectors: enabled.source.choices, enabledAt: enabled.serverNow, retentionAcknowledged: true }; enabled.status = 'baselining'; expect(validEventWatches(enabled, id)).toBe(true);
        enabled.policy.retentionAcknowledged = false; expect(validEventWatches(enabled, id)).toBe(false);
    });
    it('fails closed on unavailable source rows and original age/lease boundaries', () => {
        const v = fixture(); v.source.available = false; v.source.reason = 'unavailable'; expect(validEventWatches(v, id)).toBe(false);
        v.source.choices = []; v.source.collectedAt = null; v.source.receivedAt = null; expect(validEventWatches(v, id)).toBe(true);
        v.status = 'unknown'; expect(validEventWatches(v, id)).toBe(true);
        for (const collectedAt of ['2026-11-04T19:58:00Z', '2026-11-04T20:00:00.000000001Z', '2026-02-30T19:59:55Z']) { const value = fixture(); value.source.collectedAt = collectedAt; expect(validEventWatches(value, id)).toBe(false); }
        expect(validEventWatches({ ...fixture(), validUntil: '2026-11-04T20:00:30.000000001Z' }, id)).toBe(false);
        expect(eventWatchTime('2026-02-30T00:00:00Z')).toBeNull();
    });
    it('rejects duplicates, raw event content and expired derived observations', () => {
        const v = incident(); v.incidents.push(v.incidents[0]); expect(validEventWatches(v, id)).toBe(false);
        const raw = incident(); Object.assign(raw.incidents[0], { recordId: '123' }); expect(validEventWatches(raw, id)).toBe(false);
        const old = incident(); Object.assign(old.incidents[0], { firstObservedAt: '2026-10-28T19:59:00Z', lastObservedAt: '2026-10-28T19:59:00Z', firstReceivedAt: '2026-10-28T20:00:00Z', lastReceivedAt: '2026-10-28T20:00:00Z' }); expect(validEventWatches(old, id)).toBe(false);
    });
    it('rejects zero incident ids, pre-receipt reviews and matched without an open retained observation', () => {
        const zero = incident(); zero.incidents[0].id = 'wevent_0000000000000000'; expect(validEventWatches(zero, id)).toBe(false);
        const early = incident(); early.incidents[0].reviewedAt = '2026-11-04T19:59:55.999999999Z'; expect(validEventWatches(early, id)).toBe(false);
        early.incidents[0].reviewedAt = early.incidents[0].lastReceivedAt; expect(validEventWatches(early, id)).toBe(true);
        const v = incident(); v.policy = { enabled: true, selectors: v.source.choices, enabledAt: '2026-11-04T19:59:00Z', retentionAcknowledged: true }; v.status = 'matched'; expect(validEventWatches(v, id)).toBe(true);
        v.incidents[0].reviewedAt = v.serverNow; expect(validEventWatches(v, id)).toBe(false);
        v.incidents = []; expect(validEventWatches(v, id)).toBe(false);
    });
    it('confirms only exact request receipt plus next revision', () => {
        const change: EventWatchRequest = { operation: 'policy', body: { requestId, expectedRevision: 0, sourceToken: source, enabled: false, selectors: [], retentionAcknowledged: false } };
        const v = fixture(); v.revision = 1; v.lastRequest = { requestId, operation: 'policy', incidentId: null }; expect(eventWatchConfirmed(v, change)).toBe(true);
        for (const revision of [0, 2]) expect(eventWatchConfirmed({ ...v, revision }, change)).toBe(false);
        expect(eventWatchConfirmed({ ...v, lastRequest: null }, change)).toBe(false);
        expect(eventWatchConfirmed({ ...v, source: { ...v.source, token: 'eventsource_' + 'f'.repeat(32) } }, change)).toBe(false);
    });
    it('expires conservatively after elapsed time or wall/monotonic jumps', () => {
        expect(eventWatchElapsed({ wall: 1000, mono: 100 }, 1300, 400)).toBe(300);
        expect(eventWatchElapsed({ wall: 1000, mono: 100 }, 900, 400)).toBe(Infinity);
        expect(eventWatchElapsed({ wall: 1000, mono: 100 }, 5000, 400)).toBe(Infinity);
    });
});
describe('Node-rendered private watch UI', () => {
    it('starts collapsed with no selector or consent state rendered', () => {
        const html = renderToStaticMarkup(<WindowsEventWatchPanel deviceId={id} scope="fixture-session" sessionEnd="2026-11-04T21:00:00Z"/>);
        expect(html).toContain('aria-expanded="false"'); expect(html).not.toContain('type="checkbox"'); expect(html).not.toContain('Exact Provider');
    });
    it('renders nothing without an authenticated operator and cannot auto-enable', () => { expect(renderToStaticMarkup(<WindowsEventWatches deviceId={id}/>)).toBe(''); });
    it.each(['en', 'de'] as const)('offers bounded observed choices and unchecked consent in %s', locale => {
        const html = renderToStaticMarkup(<EventWatchEditor view={fixture()} disabled={false} locale={locale} write={() => { throw new Error('Render must never write'); }}/>);
        expect(html).toContain('Exact Provider'); expect(html).toContain('1000'); expect(html).toContain(eventWatchCopy[locale].consent); expect(html).not.toContain('checked=""'); expect(html).not.toMatch(/type="(?:text|search)"/); expect(html).toContain('type="submit" class="button small" disabled=""');
    });
    it('uses reviewed, never recovery wording for an open sampled match', () => {
        const html = renderToStaticMarkup(<EventWatchEditor view={incident()} disabled={false} locale="en" write={() => {}}/>);
        expect(html).toContain('Mark reviewed'); expect(html).toContain('At least'); expect(html).toContain('First capture'); expect(html).not.toContain('resolved'); expect(html).toContain('Expiration is not recovery');
    });
    it('hides management for read-only access and escapes provider content', () => {
        const v = fixture(); v.canManage = false; v.source.choices[0].provider = '<script>test</script>'; v.policy.selectors = v.source.choices;
        const html = renderToStaticMarkup(<EventWatchEditor view={v} disabled={false} locale="en" write={() => {}}/>);
        expect(html).not.toContain('<form'); expect(html).not.toContain('<script>'); expect(html).toContain('&lt;script&gt;');
    });
});
