import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AgentCertificatePanel, certificateExpiry } from './agent-certificate';
import { setLocale } from './i18n';
import type { AgentCertificate } from './types';

const checkedAt = '2026-10-05T12:00:00Z';
function certificate(offset: number, source: AgentCertificate['source'] = 'guided-enrollment'): AgentCertificate {
    return { source, checkedAt, expiresAt: new Date(Date.parse(checkedAt) + offset).toISOString() };
}
beforeEach(() => setLocale('en', false));
afterEach(cleanup);

describe('operator-owned certificate expiry', () => {
    it.each([
        [-1, 'expired'], [0, 'expired'], [1, 'expiring'], [48 * 3600000, 'expiring'], [48 * 3600000 + 1, 'current'],
    ])('classifies the exact manager-time boundary %s as %s', (offset, state) => {
        expect(certificateExpiry(certificate(Number(offset))).state).toBe(state);
    });
    it.each([
        undefined, null, {}, [], { ...certificate(1), expiresAt: undefined }, { ...certificate(1), expiresAt: 'not-a-date' },
        { ...certificate(1), expiresAt: '2026-02-30T12:00:00Z' }, { ...certificate(1), checkedAt: '0001-01-01T00:00:00Z' },
        { ...certificate(1), source: 'last-seen' }, { ...certificate(1), status: 'renewed' },
    ])('keeps missing or malformed data unknown', value => {
        expect(certificateExpiry(value)).toEqual({ state: 'unknown', certificate: null });
        render(<AgentCertificatePanel value={value}/>);
        expect(screen.getByText('Expiry unknown')).toBeVisible();
        expect(screen.getByText(/ask an administrator to check issuance or approval/)).toBeVisible();
        expect(document.querySelector('time')).toBeNull();
    });
    it('shows a recorded check but no invented expiry before issuance', () => {
        render(<AgentCertificatePanel value={{ ...certificate(1), expiresAt: null }}/>);
        expect(screen.getByText('Expiry unknown')).toBeVisible();
        expect(document.querySelectorAll('time')).toHaveLength(1);
        expect(document.querySelector('time')).toHaveAttribute('datetime', checkedAt);
    });
    it.each(['manual-approval', 'guided-enrollment'] as const)('shows exact expiry and supported %s guidance without any action control', source => {
        const value = certificate(3600000, source);
        render(<AgentCertificatePanel value={value}/>);
        const region = screen.getByRole('region', { name: 'Agent certificate' });
        expect(within(region).getByText('Expires within 48 hours')).toBeVisible();
        expect(region.querySelector('time')).toHaveAttribute('datetime', value.expiresAt);
        expect(region.textContent).toContain('Status at the recorded manager check.');
        expect(region.textContent).toContain('Approval, connection and health are separate.');
        expect(region.textContent).toContain(source === 'manual-approval' ? 'A new approval receives a new device ID.' : 'Existing identity and history are not automatically renewed or merged.');
        expect(region.textContent).toContain('Automatic renewal is unavailable.');
        expect(within(region).queryByRole('button')).not.toBeInTheDocument();
        expect(within(region).queryByRole('link')).not.toBeInTheDocument();
    });
    it('keeps current certificate details collapsed and supports native disclosure', async () => {
        render(<AgentCertificatePanel value={certificate(72 * 3600000)}/>);
        const summary = screen.getByText('Certificate details', { selector: 'summary' });
        expect(summary.parentElement).not.toHaveAttribute('open');
        expect(screen.getByText('More than 48 hours remaining')).toBeVisible();
        expect(screen.getByText('Manager checked')).toBeVisible();
        expect(screen.getByText('Status at manager check')).toBeVisible();
        expect(screen.getByText('Automatic renewal is unavailable.')).toBeVisible();
        expect(screen.getByText(/Status at the recorded manager check/)).not.toBeVisible();
        expect(screen.getByText(/Existing identity and history/)).not.toBeVisible();
        summary.focus();
        expect(summary).toHaveFocus();
        fireEvent.click(summary);
        expect(summary.parentElement).toHaveAttribute('open');
        expect(screen.getByText(/Existing identity and history/)).toBeVisible();
        act(() => setLocale('de', false));
        expect(screen.getByText('Zertifikatsdetails', { selector: 'summary' })).toBe(summary);
        expect(summary.parentElement).toHaveAttribute('open');
        fireEvent.click(summary);
        expect(summary.parentElement).not.toHaveAttribute('open');
        expect(summary).toHaveFocus();
    });
    it.each([0, 3600000])('keeps expiry warning and the authorized next step visible at %s', offset => {
        render(<AgentCertificatePanel value={certificate(offset)}/>);
        expect(screen.getByText(offset === 0 ? 'Expired' : 'Expires within 48 hours')).toBeVisible();
        expect(screen.getByText(/Ask an administrator to plan a separately authorized certificate replacement/)).toBeVisible();
        expect(screen.getByText('Certificate details', { selector: 'summary' }).parentElement).not.toHaveAttribute('open');
        expect(screen.queryByRole('button')).not.toBeInTheDocument();
    });
    it('refreshing the check time cannot extend the recorded expiry or infer renewal', () => {
        const value = certificate(1000), mounted = render(<AgentCertificatePanel value={value}/>);
        expect(screen.getByText('Expires within 48 hours')).toBeVisible();
        mounted.rerender(<AgentCertificatePanel value={{ ...value, checkedAt: value.expiresAt }}/>);
        expect(screen.getByText('Expired')).toBeVisible();
        expect(screen.getByText('Status at manager check')).toBeVisible();
        expect(document.querySelector('time')).toHaveAttribute('datetime', value.expiresAt);
    });
    it('localizes the full expiry warning and guidance without changing its date', () => {
        const value = certificate(0);
        render(<AgentCertificatePanel value={value}/>);
        act(() => setLocale('de', false));
        const region = screen.getByRole('region', { name: 'Agent-Zertifikat' });
        expect(within(region).getByText('Abgelaufen')).toBeVisible();
        expect(region.textContent).toContain('Automatische Erneuerung ist nicht verfügbar.');
        expect(region.textContent).not.toContain('Refresh device metadata');
        expect(region.querySelector('time')).toHaveAttribute('datetime', value.expiresAt);
    });
});
