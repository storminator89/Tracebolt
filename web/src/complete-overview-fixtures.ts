// Synthetic fixtures only. The production UI never imports this module.
import golden from '../../internal/api/testdata/complete-overview-synthetic.json';
import { compareOverviewRows, overviewSearchText, overviewSearchLower } from './complete-overview-types';
import type { OverviewView, OverviewPage, OverviewSection, OverviewRow } from './complete-overview-types';
export const overviewDevice = golden.view.deviceId;
export const overviewGolden = () => structuredClone(golden) as { view: OverviewView; processPage: OverviewPage; volumePage: OverviewPage; unicodeSearch: { search: string; processPage: OverviewPage; volumePage: OverviewPage } };
export function processRows(count = 350): OverviewRow[] { return Array.from({ length: count }, (_, i) => ({ process: { pid: i + 1, parentPid: 0, name: `fixture-process-${String(i).padStart(6, '0')}`, state: 'sleeping', rssBytes: 0, cpuTimeSeconds: 0, threads: 1, observation: { status: 'observed', reason: 'none' } }, volume: null })); }
export function volumeRows(count = 85): OverviewRow[] { return Array.from({ length: count }, (_, i) => ({ process: null, volume: { id: `mount_${i + 1}`, mountPoint: i === 0 ? '/' : `/fixture-${String(i).padStart(6, '0')}`, filesystem: 'ext4', kind: 'local', filesystemGroup: 'fs_8_1', capacityScope: 'agent-mount-namespace', totalBytes: 0, availableBytes: 0, usedPercent: null, measurement: { status: 'observed', reason: 'none' } } })); }
export function overviewView(processCount = 350, volumeCount = 85): OverviewView {
    const v = overviewGolden().view;
    for (const section of ['processes', 'volumes'] as const) {
        const c = v[section].complete!, count = section === 'processes' ? processCount : volumeCount;
        v[section].transfer = null; v[section].failure = null;
        c.manifest.observedCount = count; c.manifest[section].observedCount = count;
        c.manifest[section].fieldCoverage = { observed: count, denied: 0, exited: 0, invalid: 0, unsupported: 0, unavailable: 0, notApplicable: 0 };
        c.manifest.chunkCount = Math.ceil(count / 128); c.manifest.canonicalRowBytes = count * 300;
    }
    return v;
}
export function overviewPage(view: OverviewView, processes: OverviewRow[], volumes: OverviewRow[], raw: string): OverviewPage {
    const input = JSON.parse(raw) as { section: OverviewSection; cursor: string; search: string; limit: number }, selected = view[input.section].complete!;
    const all = [...(input.section === 'processes' ? processes : volumes)].sort(compareOverviewRows);
    let index = input.cursor ? Number(input.cursor.slice(7)) : 0, scanned = 0; const items: OverviewRow[] = [], query = input.search.trim().toLowerCase();
    for (; index < all.length && scanned < 2048 && items.length < input.limit; index++) { const row = all[index]; scanned++; if (!query || overviewSearchLower(overviewSearchText(row)).includes(query)) items.push(row); }
    return { schemaVersion: 'tracebolt.complete-overview-page.v1', deviceId: view.deviceId, serverNow: view.serverNow, section: input.section, binding: selected.binding, manifest: selected.manifest, collectedAt: selected.manifest.collectedAt, completedAt: selected.completedAt, retainedUntil: selected.retainedUntil, totalRows: all.length, items, scannedRows: scanned, exhausted: index === all.length, searchIncomplete: Boolean(query) && index < all.length, nextCursor: index === all.length ? '' : `cursor_${index}`, cursorExpiresAt: new Date(Math.min(Date.parse(view.serverNow) + 900000, Date.parse(selected.retainedUntil))).toISOString() };
}
