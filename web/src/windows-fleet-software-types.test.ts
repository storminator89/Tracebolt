import { describe, expect, it } from 'vitest';
import { fleetSoftwareFresh, fleetSoftwareVisible, validFleetSoftwarePage, validFleetSoftwareQuery } from './windows-fleet-software-types';
import type { FleetSoftwarePage } from './windows-fleet-software-types';
import { fleetSoftwareCursor, fleetSoftwareExpiry, fleetSoftwareItem, fleetSoftwarePage, fleetSoftwareQuery } from './windows-fleet-software-fixtures';
import { fullSoftwareManifestHash } from './windows-full-software-types';
const expected = { mode: 'fleet', offset: 0 } as const;
const valid = (page: unknown) => validFleetSoftwarePage(page, fleetSoftwareQuery, expected);

describe('bounded read-only fleet software contract', () => {
    it('validates fleet previews and exact detail pages with original total and deadline', () => {
        const page = fleetSoftwarePage(); expect(valid(page)).toBe(true); expect(page.items).toHaveLength(5); expect(page.items[0].rows).toHaveLength(3);
        const query = { ...fleetSoftwareQuery, cursor: page.items[0].detailCursor }, detail = fleetSoftwarePage(query);
        const pin = { mode: 'device', offset: 0, device: page.items[0], totalDevices: 6, deadline: fleetSoftwareExpiry } as const;
        expect(validFleetSoftwarePage(detail, query, pin)).toBe(true); expect(detail.items[0].rows).toHaveLength(20);
        const nextQuery = { ...query, cursor: detail.nextCursor }, next = fleetSoftwarePage(nextQuery);
        expect(validFleetSoftwarePage(next, nextQuery, { ...pin, offset: 20 })).toBe(true); expect(next.items[0].rows).toHaveLength(3); expect(next.nextCursor).toBe('');
    });
    it('accepts Unicode literal input without trimming or semantic version comparison', () => {
        for (const name of ['İΣß🛠', '[.*]', ' ']) expect(validFleetSoftwareQuery({ name, version: '>=1.0', cursor: '' })).toBe(true);
        expect(validFleetSoftwareQuery({ name: '', version: '1.2', cursor: '' })).toBe(true);
        for (const name of ['\0', '\ud800', '🛠'.repeat(65), 'a'.repeat(257)]) expect(validFleetSoftwareQuery({ name, version: '', cursor: '' })).toBe(false);
        expect(validFleetSoftwareQuery({ name: '', version: '', cursor: '' })).toBe(false);
        expect(validFleetSoftwareQuery({ name: 'a', version: '', cursor: 'x'.repeat(4097) })).toBe(false);
    });
    it.each([
        ['unknown top-level field', (p: FleetSoftwarePage) => Object.assign(p, { private: 'unexpected' })],
        ['wrong name', (p: FleetSoftwarePage) => { p.name = 'other'; }],
        ['wrong version', (p: FleetSoftwarePage) => { p.version = 'other'; }],
        ['wrong mode', (p: FleetSoftwarePage) => { p.mode = 'device'; }],
        ['wrong offset', (p: FleetSoftwarePage) => { p.offset = 1; }],
        ['oversized fleet', (p: FleetSoftwarePage) => { p.totalDevices = 26; }],
        ['fractional count', (p: FleetSoftwarePage) => { p.totalDevices = 5.5; }],
        ['six devices', (p: FleetSoftwarePage) => { p.items.push(fleetSoftwareItem(5)); }],
        ['out of order devices', (p: FleetSoftwarePage) => { p.items.reverse(); }],
        ['duplicate devices', (p: FleetSoftwarePage) => { p.items[1] = p.items[0]; }],
        ['duplicate identity', (p: FleetSoftwarePage) => { p.items[1].identity = p.items[0].identity; }],
        ['invalid identity', (p: FleetSoftwarePage) => { p.items[0].identity = 'x'; }],
        ['extra item field', (p: FleetSoftwarePage) => Object.assign(p.items[0], { hostname: 'not admitted' })],
        ['missing authority', (p: FleetSoftwarePage) => { p.items[0].authorityUntil = ''; }],
        ['expired authority', (p: FleetSoftwarePage) => { p.items[0].authorityUntil = p.serverNow; }],
        ['authority earlier than cursor', (p: FleetSoftwarePage) => { p.items[0].authorityUntil = '2026-10-11T06:01:00Z'; }],
        ['new lifetime', (p: FleetSoftwarePage) => { p.cursorExpiresAt = '2026-10-11T06:05:11Z'; }],
        ['missing deadline', (p: FleetSoftwarePage) => { p.cursorExpiresAt = null; }],
        ['bad timestamp', (p: FleetSoftwarePage) => { p.serverNow = '2026-02-30T06:00:00Z'; }],
        ['missing continuation', (p: FleetSoftwarePage) => { p.nextCursor = ''; }],
        ['unavailable query field', (p: FleetSoftwarePage) => { p.items[0].rows[0].name = null; p.items[0].rows[0].nameQuality = 'unavailable'; }],
        ['invalid field truth', (p: FleetSoftwarePage) => { p.items[0].rows[0].version = null; }],
        ['excess preview', (p: FleetSoftwarePage) => { p.items[0].rows.push(p.items[0].rows[0]); }],
        ['duplicate rows', (p: FleetSoftwarePage) => { p.items[0].rows[1] = p.items[0].rows[0]; }],
        ['out of order', (p: FleetSoftwarePage) => { p.items[0].rows.reverse(); }],
        ['missing matches', (p: FleetSoftwarePage) => { p.items[0].rows = []; }],
        ['impossible counts', (p: FleetSoftwarePage) => { p.items[0].unknownCount = 27; }],
        ['missing detail cursor', (p: FleetSoftwarePage) => { p.items[0].detailCursor = ''; }],
        ['bad complete hash', (p: FleetSoftwarePage) => { p.items[0].complete!.manifestSha256 = 'a'.repeat(64); }],
        ['cross-device manifest', (p: FleetSoftwarePage) => { p.items[0].complete = p.items[1].complete; }],
        ['no latest attempt', (p: FleetSoftwarePage) => { p.items[0].latestAttempt = null; }],
        ['invalid same-sequence attempt', (p: FleetSoftwarePage) => { p.items[0].latestAttempt!.status = 'pending'; }],
        ['future attempt', (p: FleetSoftwarePage) => { p.items[0].latestAttempt!.attemptedAt = '2026-10-11T07:00:00Z'; }],
    ] as const)('rejects %s', (_, change) => { const page = fleetSoftwarePage(); change(page); expect(valid(page)).toBe(false); });
    it('pins exact detail identity, generation, counts, total, deadline and offset', () => {
        const page = fleetSoftwarePage(), query = { ...fleetSoftwareQuery, cursor: page.items[0].detailCursor }, pin = { mode: 'device', offset: 0, device: page.items[0], totalDevices: 6, deadline: fleetSoftwareExpiry } as const;
        for (const change of [(p: FleetSoftwarePage) => { p.items[0].identity = 'b'.repeat(64); }, (p: FleetSoftwarePage) => { p.totalDevices = 1; }, (p: FleetSoftwarePage) => { p.offset = 20; }, (p: FleetSoftwarePage) => { p.cursorExpiresAt = '2026-10-11T06:05:09Z'; }, (p: FleetSoftwarePage) => { p.items[0].unknownCount--; }, (p: FleetSoftwarePage) => { p.items[0].complete!.manifest.senderBinding = 'd'.repeat(64); p.items[0].complete!.manifestSha256 = fullSoftwareManifestHash(p.items[0].complete!.manifest); }]) {
            const detail = fleetSoftwarePage(query); change(detail); expect(validFleetSoftwarePage(detail, query, pin)).toBe(false);
        }
    });
    it('retains failed/pending latest attempts without replacing original capture', () => {
        for (const status of ['pending', 'source_failed', 'expired'] as const) {
            const p = fleetSoftwarePage(); p.items[0].latestAttempt = { sequence: 2, attemptedAt: '2026-10-11T06:00:09Z', status, reason: status === 'source_failed' ? 'access_denied' : '' }; expect(valid(p)).toBe(true);
        }
    });
    it('keeps zero matches with unknown fields distinct from missing data and zero devices', () => {
        const query = { ...fleetSoftwareQuery, name: 'no match' }, page = fleetSoftwarePage(query); expect(validFleetSoftwarePage(page, query, expected)).toBe(true); expect(page.items[0].matchingCount).toBe(0); expect(page.items[0].unknownCount).toBe(4); expect(page.items[0].detailCursor).not.toBe('');
        for (const status of ['not_configured', 'disabled', 'awaiting', 'unavailable'] as const) {
            const p = fleetSoftwarePage(); Object.assign(p.items[0], { status, complete: null, latestAttempt: null, matchingCount: 0, unknownCount: 0, rows: [], detailCursor: '' }); expect(valid(p)).toBe(true); p.items[0].rows = fleetSoftwareItem().rows; expect(valid(p)).toBe(false);
        }
        expect(valid(fleetSoftwarePage(fleetSoftwareQuery, 0))).toBe(true);
        const p = { ...fleetSoftwarePage(fleetSoftwareQuery, 0), status: 'not_configured', cursorExpiresAt: null }; expect(valid(p)).toBe(true); expect(valid({ ...p, items: [fleetSoftwareItem()] })).toBe(false);
    });
    it('uses original capture freshness and clears at the earliest original deadline', () => {
        const page = fleetSoftwarePage(), item = page.items[0]; expect(fleetSoftwareFresh(item, page.serverNow, 0)).toBe(true); expect(fleetSoftwareFresh(item, page.serverNow, 121000)).toBe(false);
        expect(fleetSoftwareVisible(page, 299999)).toBe(true); expect(fleetSoftwareVisible(page, 300000)).toBe(false); expect(fleetSoftwareVisible(page, Infinity)).toBe(false); expect(fleetSoftwareVisible(page, -1)).toBe(false);
        const query = { ...fleetSoftwareQuery, cursor: fleetSoftwareCursor('fleet_5') }; expect(validFleetSoftwarePage(fleetSoftwarePage(query), query, { mode: 'fleet', offset: 5, totalDevices: 6, deadline: fleetSoftwareExpiry })).toBe(true);
    });
});
