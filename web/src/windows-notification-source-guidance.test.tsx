import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, request } from './api';
import { setLocale } from './i18n';
import { windowsCapacityDevice, windowsCapacitySession } from './windows-capacity-fixture';
import { windowsNow } from './windows-inventory-fixture';
import { windowsCompleteNotificationView } from './windows-complete-notifications-fixture';
import { windowsNotificationView } from './windows-notifications-fixture';
import { WindowsNotifications } from './windows-notifications';
import type { WindowsNotificationView } from './windows-notifications-types';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn() }));
const session = { mode: 'lan', transport: 'https', insecureTestMode: false, transportWarning: null, authenticationRequired: true, authenticated: true, csrfToken: 'fixture-csrf', serverNow: windowsNow, expiresAt: windowsCapacitySession, expiresInSeconds: 3590, loginMode: 'shared', actorId: null, capabilities: ['read'] };
let view: WindowsNotificationView;
const flush = () => act(async () => {});
const posts = () => vi.mocked(request).mock.calls.filter(([, options]) => options?.method === 'POST');
const reads = () => vi.mocked(request).mock.calls.filter(([path]) => path === '/fleet/windows-notifications');
function Harness({ admin = true }: { admin?: boolean }) { return <WindowsNotifications devices={[{ ...windowsCapacityDevice(), name: 'Desk One' }]} sessionKey={windowsCapacitySession} admin={admin}/>; }
async function open() { fireEvent.click(screen.getByRole('button', { name: 'Windows notifications' })); await flush(); }
beforeEach(() => {
    abortProtectedRequests(); vi.useFakeTimers(); vi.setSystemTime(windowsNow); setLocale('en', false); vi.mocked(request).mockReset(); view = windowsNotificationView();
    vi.mocked(request).mockImplementation(async (path, options) => {
        if (path === '/auth/session') return structuredClone(session);
        if (path === '/fleet/windows-notifications/complete') return windowsCompleteNotificationView();
        if (options?.method === 'POST') { const body = JSON.parse(options.body as string); view.targets = view.targets.map(t => t.key === body.key ? { ...t, revision: t.revision + 1, enabled: body.enabled, effective: body.enabled, changedAt: view.serverNow } : t); }
        return structuredClone(view);
    });
});
afterEach(() => { cleanup(); abortProtectedRequests(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('notification source guidance', () => {
    it.each(['en', 'de'] as const)('explains each source beside its selector without approving it (%s)', async locale => {
        setLocale(locale, false); const de = locale === 'de'; render(<Harness/>);
        fireEvent.click(screen.getByRole('button', { name: de ? 'Windows-Benachrichtigungen' : 'Windows notifications' })); await flush();
        const group = screen.getByRole('group', { name: de ? 'Benachrichtigungsquelle' : 'Notification source' });
        expect(group).toHaveAccessibleDescription(de ? 'Vorschauquelle: Kontakt-, CPU-, Systemvolume-, RAM- und ausgewählte Dienstprüfungen.' : 'Preview source: contact, CPU, system-volume, physical-RAM and selected-service checks.');
        expect(reads()).toHaveLength(1); expect(posts()).toHaveLength(0);
        fireEvent.click(screen.getByRole('button', { name: de ? 'Vollständig' : 'Complete' })); await flush();
        expect(group).toHaveAccessibleDescription(de ? /Eine Vorschaufreigabe gilt nicht/ : /Preview approval does not cover/);
        expect(screen.queryByText(/^Preview source:|^Vorschauquelle:/)).toBeNull();
        expect(posts()).toHaveLength(0); expect(screen.queryByRole('checkbox')).toBeNull();
        expect(vi.mocked(request).mock.calls.filter(([path]) => path === '/fleet/windows-notifications/complete')).toHaveLength(1);
        fireEvent.click(screen.getByRole('button', { name: de ? 'Vorschau' : 'Preview' })); await flush();
        expect(group).toHaveAccessibleDescription(de ? /^Vorschauquelle:/ : /^Preview source:/); expect(posts()).toHaveLength(0);
    });
    it('removes scope guidance when collapsed and retains read-only source browsing', async () => {
        render(<Harness admin={false}/>); await open();
        expect(screen.getByRole('group', { name: 'Notification source' })).toHaveAccessibleDescription(/^Preview source:/);
        fireEvent.click(screen.getByRole('button', { name: 'Windows notifications' }));
        expect(screen.queryByRole('group', { name: 'Notification source' })).toBeNull();
        expect(screen.queryByText(/^Preview source:/)).toBeNull(); expect(posts()).toHaveLength(0);
    });
});
