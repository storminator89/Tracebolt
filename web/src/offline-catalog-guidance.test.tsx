import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mutateRaw, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { OfflineCatalogPanel } from './security-coverage';
import type { OfflineCatalogView } from './security-coverage-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: vi.fn() }));
const now = '2026-10-04T00:00:10Z';
const revision = `revision_${'a'.repeat(32)}`;
const raw = '{ "schema":"debian-tracker-normalized-1", "synthetic":true, "coveredSources":["fixture-source"], "rules":[] }\n';
const operator = { mode: 'lan' as const, authenticated: true, expiresAt: '2026-10-04T00:30:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light' as const, setTheme: vi.fn() };
function catalog(loaded = false): OfflineCatalogView {
    return { schemaVersion: 'tracebolt.offline-catalog.v1', enabled: true, serverNow: now, revision, storage: 'memory-only', resetsOnRestart: true, limits: { maxBytes: 2097152, maxRules: 10000, maxInFlight: 1 }, catalog: loaded ? { id: `catalog_${'c'.repeat(32)}`, sha256: 'd'.repeat(64), format: 'debian-tracker-normalized-1', provider: 'debian-security-tracker', declaredRelease: 'trixie', importedAt: '2026-10-04T00:00:05Z', publishedAt: null, freshness: 'unknown', originAssurance: 'unverified', synthetic: true, byteCount: new TextEncoder().encode(raw).byteLength, ruleCount: 0, coveredSourceCount: 1 } : null };
}

beforeEach(() => { vi.mocked(request).mockReset(); vi.mocked(mutateRaw).mockReset(); vi.mocked(useOperator).mockReturnValue(operator); setLocale('en', false); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
async function start(loaded = false) { vi.mocked(request).mockResolvedValue(catalog(loaded)); render(<OfflineCatalogPanel/>); fireEvent.click(await screen.findByText('Import a normalized JSON catalog')); }
async function choose(text = raw) {
    fireEvent.change(screen.getByLabelText('Choose JSON file'), { target: { files: [new File([text], 'PRIVATE_FILENAME.json', { type: 'application/json' })] } });
    await screen.findByText('Prepared locally, not imported. The manager checks the catalog format when you import it.');
}
describe('offline catalog selection guidance', () => {
    it.each([false, true])('explains local selection before explicit import, existing catalog=%s', async loaded => {
        await start(loaded);
        expect(screen.getByLabelText('Choose JSON file')).toHaveAccessibleDescription(/Choosing a file does not send it/);
        const submit = screen.getByRole('button', { name: loaded ? 'Replace current catalog' : 'Import catalog' });
        expect(submit).toBeDisabled(); await choose(); expect(submit).toBeEnabled();
        expect(screen.getByLabelText('Choose JSON file')).toHaveAccessibleDescription(/Prepared locally, not imported/);
        expect(screen.getByRole('status')).toHaveTextContent('manager checks the catalog format');
        expect(document.body).not.toHaveTextContent('PRIVATE_FILENAME');
        expect(mutateRaw).not.toHaveBeenCalled(); expect(request).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: 'Cancel file selection' }));
        expect(screen.queryByText(/Prepared locally/)).toBeNull(); expect(submit).toBeDisabled();
    });
    it('does not mistake local UTF-8 preparation for successful JSON validation', async () => {
        await start(); await choose('not valid JSON');
        expect(screen.getByRole('status')).toHaveTextContent('not imported');
        expect(mutateRaw).not.toHaveBeenCalled();
        fireEvent.click(screen.getByText('Import a normalized JSON catalog'));
        await waitFor(() => expect(screen.queryByText(/Prepared locally/)).toBeNull());
    });
    it('localizes selected guidance without another read and clears it on refresh', async () => {
        await start(); await choose(); act(() => setLocale('de', false));
        expect(screen.getByLabelText('JSON-Datei auswählen')).toHaveAccessibleDescription(/Lokal vorbereitet, noch nicht importiert/);
        expect(request).toHaveBeenCalledTimes(1); expect(mutateRaw).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole('button', { name: 'Katalogstatus aktualisieren' }));
        await waitFor(() => expect(screen.queryByText(/Lokal vorbereitet/)).toBeNull());
    });
});
