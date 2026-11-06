import { describe, expect, it } from 'vitest';
import goFixture from './windows-fleet-software-history-go-fixture.json';
import { fleetHistoryPage } from './windows-fleet-software-history-fixtures';
import { fleetHistoryVisible, validFleetHistoryPage } from './windows-fleet-software-history-types';
import type { FleetHistoryQuery } from './windows-fleet-software-history-types';
import { validSoftwareHistoryPage } from './windows-software-history-types';
const query: FleetHistoryQuery = { view: 'history', name: '', version: '', cursor: '' };
describe('private fleet software-history contract', () => {
    it('accepts bounded fleet and exact history pages, rejects ordinary nested cursor domains', () => {
        const p = fleetHistoryPage(); expect(validFleetHistoryPage(p, query, { mode: 'fleet', offset: 0 })).toBe(true);
        const q = { ...query, cursor: p.items[0].detailCursor }, detail = fleetHistoryPage(q);
        expect(validFleetHistoryPage(detail, q, { mode: 'device', offset: 0, device: p.items[0], deadline: p.cursorExpiresAt!, totalDevices: p.totalDevices })).toBe(true);
        expect(validSoftwareHistoryPage(p.items[0].history, p.items[0].deviceId, { search: '', sort: 'observed-desc', limit: 3, cursor: '' }, 0)).toBe(false);
        p.items[0].history.nextCursor = 'ordinary.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
        expect(validFleetHistoryPage(p, query, { mode: 'fleet', offset: 0 })).toBe(false);
    });
    it('accepts byte-short device pages without implying omitted devices, and rejects empty prefixes', () => {
        const p = fleetHistoryPage(); p.items = p.items.slice(0, 2);
        expect(validFleetHistoryPage(p, query, { mode: 'fleet', offset: 0 })).toBe(true);
        p.items = []; expect(validFleetHistoryPage(p, query, { mode: 'fleet', offset: 0 })).toBe(false);
    });
    it('rejects authority, identity, expiry and schema corruption', () => {
        for (const alter of [
            (p: ReturnType<typeof fleetHistoryPage>) => { p.items[0].identity = ''; },
            (p: ReturnType<typeof fleetHistoryPage>) => { p.items[0].history.cursorExpiresAt = '2026-10-11T06:15:10Z'; },
            (p: ReturnType<typeof fleetHistoryPage>) => { p.items[0].history.rows[0].expiresAt = p.serverNow; },
            (p: ReturnType<typeof fleetHistoryPage>) => { p.items[0].history.grantId = null; },
            (p: ReturnType<typeof fleetHistoryPage>) => { p.items[0].authorityUntil = p.serverNow; },
            (p: ReturnType<typeof fleetHistoryPage>) => { p.items[0].history.rows[0].changedFields = ['version']; },
        ]) { const p = fleetHistoryPage(); alter(p); expect(validFleetHistoryPage(p, query, { mode: 'fleet', offset: 0 })).toBe(false); }
        const p = fleetHistoryPage(); expect(fleetHistoryVisible(p, 299999)).toBe(true); expect(fleetHistoryVisible(p, 300000)).toBe(false);
    });
    it('consumes the actual Go-generated projection fixture', () => {
        const p = goFixture;
        expect(validFleetHistoryPage(p, query, { mode: 'fleet', offset: 0 })).toBe(true);
        expect(p.items[0].history.nextCursor).toBe('');
        expect(p.items[0].history.cursorExpiresAt).toBe(p.cursorExpiresAt);
    });
});
