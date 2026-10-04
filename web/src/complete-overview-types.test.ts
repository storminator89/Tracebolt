import { describe, expect, it } from 'vitest';
import { overviewDevice, overviewGolden, overviewPage, overviewView, processRows, volumeRows } from './complete-overview-fixtures';
import { compareOverviewRows, overviewSectionVisible, overviewSearchLower, validOverviewManifest, validOverviewPage, validOverviewProcess, validOverviewSearch, validOverviewView, validOverviewVolume } from './complete-overview-types';

describe('complete overview Go DTO contract', () => {
    it('accepts checked-in real Go DTO encoding with independent retained captures and latest failure', () => {
        const f = overviewGolden(); expect(validOverviewView(f.view, overviewDevice)).toBe(true);
        expect(validOverviewPage(f.processPage, overviewDevice, 'processes', f.view.processes.complete!, '', '')).toBe(true);
        expect(validOverviewPage(f.volumePage, overviewDevice, 'volumes', f.view.volumes.complete!, '', '')).toBe(true);
        expect(f.view.processes.complete!.manifest.captureGenerationId).not.toBe(f.view.volumes.complete!.manifest.captureGenerationId);
    });
    it('accepts zero and nullable field distinctions, but rejects forged observations', () => {
        const rows = processRows(1); expect(validOverviewProcess(rows[0].process)).toBe(true);
        expect(validOverviewProcess({ ...rows[0].process, rssBytes: null })).toBe(false);
        expect(validOverviewProcess({ ...rows[0].process, pid: 0 })).toBe(false);
        expect(validOverviewProcess({ ...rows[0].process, cpuTimeSeconds: NaN })).toBe(false);
        expect(validOverviewProcess({ ...rows[0].process, cmdline: 'unexpected' })).toBe(false);
        const v = volumeRows(1)[0].volume!; expect(validOverviewVolume(v)).toBe(true);
        expect(validOverviewVolume({ ...v, availableBytes: 1 })).toBe(false);
        expect(validOverviewVolume({ ...v, usedPercent: 0 })).toBe(false);
        const pseudo = overviewGolden().volumePage.items.find(r => r.volume?.kind === 'virtual')!.volume!;
        expect(validOverviewVolume(pseudo)).toBe(true); expect(validOverviewVolume({ ...pseudo, filesystem: 'fusectl' })).toBe(true); expect(validOverviewVolume({ ...pseudo, filesystem: 'fusectl', kind: 'remote' })).toBe(false); expect(validOverviewVolume({ ...pseudo, totalBytes: 0 })).toBe(false);
        expect(validOverviewVolume({ ...v, mountPoint: '/home/alice' })).toBe(false);
    });
    it('rejects invalid counts, mismatched sections, manifest changes and expiry extension', () => {
        const f = overviewGolden(), c = f.view.processes.complete!;
        expect(validOverviewManifest({ ...c.manifest, observedCount: c.manifest.observedCount + 1 }, 'processes')).toBe(false);
        expect(validOverviewView({ ...f.view, deviceId: 'agent_' + 'b'.repeat(32) }, overviewDevice)).toBe(false);
        expect(validOverviewPage({ ...f.processPage, section: 'volumes' }, overviewDevice, 'processes', c, '', '')).toBe(false);
        expect(validOverviewPage({ ...f.processPage, retainedUntil: '2026-10-06T18:30:00Z' }, overviewDevice, 'processes', c, '', '')).toBe(false);
        expect(validOverviewPage({ ...f.processPage, manifest: { ...f.processPage.manifest, rowsSha256: '0'.repeat(64) } }, overviewDevice, 'processes', c, '', '')).toBe(false);
        expect(validOverviewPage({ ...f.processPage, cursorExpiresAt: '2026-10-05T18:30:00Z' }, overviewDevice, 'processes', c, '', '')).toBe(false);
        c.manifest.processes.fieldCoverage.denied++; expect(validOverviewView(f.view, overviewDevice)).toBe(false);
    });
    it('accepts complete empty generations and never promotes missing metadata to zero', () => {
        const v = overviewView(0, 0); expect(validOverviewView(v, overviewDevice)).toBe(true);
        const p = overviewPage(v, [], [], JSON.stringify({ section: 'processes', cursor: '', search: '', limit: 100 })); expect(validOverviewPage(p, overviewDevice, 'processes', v.processes.complete!, '', '')).toBe(true);
        expect(validOverviewView({ ...v, processes: { ...v.processes, complete: null } }, overviewDevice)).toBe(false);
    });
    it('orders mounts by measured local first and validates repeated or reversed rows', () => {
        const f = overviewGolden(); expect(f.volumePage.items.every((r, i, all) => i === 0 || compareOverviewRows(all[i - 1], r) < 0)).toBe(true);
        const p = { ...f.volumePage, items: [...f.volumePage.items].reverse() }; expect(validOverviewPage(p, overviewDevice, 'volumes', f.view.volumes.complete!, '', '')).toBe(false);
    });
    it('matches Go simple lowercase for ASCII searches through Unicode process names and mount paths', () => {
        expect(overviewSearchLower('İd ΚΟΣ K')).toBe('id κοσ k');
        const v = overviewView(1, 1), p = processRows(1), m = volumeRows(1); p[0].process!.name = 'İd'; m[0].volume!.mountPoint = '/İd';
        for (const section of ['processes', 'volumes'] as const) {
            const page = overviewPage(v, p, m, JSON.stringify({ section, cursor: '', search: 'id', limit: 100 })); expect(page.items).toHaveLength(1);
            expect(validOverviewPage(page, overviewDevice, section, v[section].complete!, 'id', '')).toBe(true);
        }
    });
    it('accepts actual Go-encoded Unicode-search pages for process names and mount paths', () => {
        const { unicodeSearch: f } = overviewGolden(); expect(f.search).toBe('id');
        for (const page of [f.processPage, f.volumePage]) {
            const selected = { binding: page.binding, manifest: page.manifest, state: 'complete' as const, completedAt: page.completedAt, retainedUntil: page.retainedUntil };
            expect(page.items).toHaveLength(1); expect(validOverviewPage(page, overviewDevice, page.section, selected, f.search, '')).toBe(true);
        }
    });
    it('accepts a completed-expired late upload without extending age or blocking a fresh sibling', () => {
        const v = overviewView(), c = v.processes.complete!; c.state = v.processes.status = 'expired';
        c.manifest.captureStartedAt = c.manifest.collectedAt = '2026-10-02T18:30:00Z'; c.manifest.captureFinishedAt = '2026-10-02T18:30:00.75Z'; c.retainedUntil = '2026-10-03T18:30:00Z'; c.completedAt = '2026-10-04T18:34:30Z';
        v.processes.transfer = { binding: structuredClone(c.binding), manifest: structuredClone(c.manifest), state: 'expired', declaredRows: c.manifest.observedCount, acceptedRows: c.manifest.observedCount, expectedChunks: c.manifest.chunkCount, acceptedChunks: c.manifest.chunkCount, collectedAt: c.manifest.collectedAt, startedAt: '2026-10-04T18:34:00Z', expiresAt: c.retainedUntil };
        expect(validOverviewView(v, overviewDevice)).toBe(true); expect(overviewSectionVisible(v, 'processes', 0)).toBe(false); expect(overviewSectionVisible(v, 'volumes', 0)).toBe(true);
        v.processes.transfer.acceptedRows--; expect(validOverviewView(v, overviewDevice)).toBe(false);
    });
    it('enforces actual search and capture-age boundaries', () => {
        expect(validOverviewSearch('root / 123')).toBe(true); expect(validOverviewSearch('ä')).toBe(false); expect(validOverviewSearch('a'.repeat(129))).toBe(false); expect(validOverviewSearch('\n')).toBe(false);
        const v = overviewGolden().view, remaining = Date.parse(v.processes.complete!.retainedUntil) - Date.parse(v.serverNow);
        expect(overviewSectionVisible(v, 'processes', remaining - 1)).toBe(true); expect(overviewSectionVisible(v, 'processes', remaining)).toBe(false); expect(overviewSectionVisible(v, 'processes', Infinity)).toBe(false);
    });
});
