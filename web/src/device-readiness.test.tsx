import { act, cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DeviceReadiness } from './device-readiness';
import { setLocale } from './i18n';
import type { Device } from './types';

const at = '2026-11-03T12:00:00Z';
const device = (): Device => ({ id: 'agent_fixture', source: 'lan', synthetic: false, lastSeen: at, agentVersion: 'reported-v1', capabilities: [{ id: 'inventory', status: 'scope', name: 'Inventory', detail: '' }], agentCertificate: { source: 'guided-enrollment', checkedAt: at, expiresAt: '2026-11-06T12:00:00Z' } } as Device);
const panel = (value = device(), available = true) => <DeviceReadiness device={value} available={available} metadataElapsed={0} profiles={['managed-operations-v3', '', 'managed-operations-v3']} observations={[{ state: 'available' }, { state: 'scope' }, { state: 'configured' }, { state: 'denied' }]}/>;
beforeEach(() => { setLocale('en', false); vi.useFakeTimers({ toFake: ['Date', 'performance'] }); vi.setSystemTime(new Date(at)); });
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });
describe('device readiness presentation', () => {
    it('includes metadata age accumulated before mounting and never reduces it on rerender', () => {
        const value = device(); value.agentCertificate!.expiresAt = '2026-11-03T12:01:00Z';
        const view = (age: number) => <DeviceReadiness device={value} available metadataElapsed={age} observations={[]} profiles={[]}/>;
        const mounted = render(view(121000));
        expect(document.querySelector('[data-report-state]')).toHaveAttribute('data-report-state', 'stale');
        expect(document.querySelector('[data-certificate-state]')).toHaveAttribute('data-certificate-state', 'expired');
        mounted.rerender(view(0));
        expect(document.querySelector('[data-report-state]')).toHaveAttribute('data-report-state', 'stale');
        expect(document.querySelector('[data-certificate-state]')).toHaveAttribute('data-certificate-state', 'expired');
    });
    it.each(['en', 'de'] as const)('keeps source profiles, reported version and evidence boundaries separate (%s)', locale => {
        setLocale(locale, false); render(panel());
        expect(screen.getByText('managed-operations-v3')).toBeVisible();
        expect(screen.getByText('reported-v1')).toBeVisible();
        const counts = screen.getByRole('list', { name: locale === 'de' ? 'Fähigkeitsstatus-Zeilen' : 'Capability status rows' });
        expect(within(counts).getAllByRole('listitem')).toHaveLength(4);
        expect(document.querySelector('[data-readiness-state="available"]')).toHaveTextContent(locale === 'de' ? '1 Erfasst' : '1 Collected');
        expect(document.querySelector('[data-readiness-state="configured"]')).toHaveTextContent(locale === 'de' ? '1 Eingerichtet' : '1 Configured');
        expect(document.querySelector('[data-readiness-state="denied"]')).toHaveTextContent(locale === 'de' ? '1 Zugriff verweigert' : '1 Permission denied');
        expect(document.querySelector('[data-report-state] time')).toHaveAttribute('datetime', at);
        expect(screen.getByText(locale === 'de' ? /Eine Agentversion ist kein/ : /An agent version is not/)).toBeInTheDocument();
    });
    it('hides all prior facts and counts when access ends', () => {
        const mounted = render(panel()); mounted.rerender(panel(device(), false));
        expect(screen.getByText('Current evidence unavailable')).toBeVisible();
        expect(screen.queryByText('reported-v1')).not.toBeInTheDocument();
        expect(screen.queryByText('managed-operations-v3')).not.toBeInTheDocument();
        expect(screen.queryByRole('list')).not.toBeInTheDocument();
        expect(document.querySelector('time')).toBeNull();
    });
    it('does not renew unchanged age across repeated metadata or slower advancing manager time', () => {
        const mounted = render(panel());
        act(() => { vi.advanceTimersByTime(121000); }); mounted.rerender(panel());
        expect(document.querySelector('[data-report-state]')).toHaveAttribute('data-report-state', 'stale');
        const slow = device(); slow.agentCertificate!.checkedAt = '2026-11-03T12:00:01Z'; mounted.rerender(panel(slow));
        expect(document.querySelector('[data-report-state]')).toHaveAttribute('data-report-state', 'stale');
        expect(document.querySelector('[data-report-state]')).toHaveTextContent('121 s');
        expect(document.querySelector('[data-report-state] time')).toHaveAttribute('datetime', at);
    });
    it('fails age closed on backward manager time and resets only for a different device', () => {
        const mounted = render(panel()), backward = device(); backward.agentCertificate!.checkedAt = '2026-11-03T11:59:59Z'; mounted.rerender(panel(backward));
        expect(document.querySelector('[data-report-state]')).toHaveAttribute('data-report-state', 'unknown');
        expect(document.querySelector('[data-certificate-state]')).toHaveAttribute('data-certificate-state', 'unknown');
        mounted.rerender(panel({ ...device(), id: 'agent_other' }));
        expect(document.querySelector('[data-report-state]')).toHaveAttribute('data-report-state', 'recent');
    });
    it('does not use a browser wall-clock jump as capture age', () => {
        const mounted = render(panel()); act(() => vi.setSystemTime(new Date('2026-11-03T11:00:00Z'))); mounted.rerender(panel());
        expect(document.querySelector('[data-report-state]')).toHaveAttribute('data-report-state', 'unknown');
    });
    it('does not infer an artifact or a profile from the reported agent version', () => {
        render(<DeviceReadiness device={device()} available metadataElapsed={0} observations={[]} profiles={[]}/>);
        expect(screen.getByText('Not supplied')).toBeVisible();
        expect(screen.getByText('No capability status supplied')).toBeVisible();
    });
});
