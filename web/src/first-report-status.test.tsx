import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EnrollmentSection } from './enrollment';
import { EnrollmentReport } from './enrollment-report';
import { ReportTime, reportTimestamp } from './report-time';
import { DeviceTable } from './components';
import { DeviceEssentials } from './device-essentials';
import { mutate, request } from './api';
import { setLocale } from './i18n';
import { fullDate, relativeTime } from './utils';
import { validEnrollmentList } from './enrollment-types';
import type { EnrollmentList, EnrollmentSnapshot, EnrollmentState } from './enrollment-types';
import type { Device } from './types';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const operator = vi.hoisted(() => ({ mode: 'lan', authenticated: true, insecureTestMode: false }));
vi.mock('./auth', async original => ({ ...await original<typeof import('./auth')>(), useOperator: () => operator }));
const now = '2026-10-14T06:00:00Z', seconds = Date.parse(now) / 1000, id = `agent_${'6'.repeat(32)}`, invitation = `invite_${'1'.repeat(32)}`;
const missing = '0001-01-01T00:00:00Z';
function record(state: EnrollmentState = 'activated'): EnrollmentSnapshot {
    return {
        version: 'tracebolt.enrollment-state.v2', binding: { instanceID: `manager_${'2'.repeat(32)}`, origin: window.location.origin, profile: 'tls', collectionProfile: 'managed-operations-v3', issuerFingerprint: 'a'.repeat(64) },
        invitationID: invitation, createRequestID: `request_${'3'.repeat(32)}`, platform: 'linux', revision: 6, state, createdAt: seconds - 300, deadlineAt: seconds + 600, updatedAt: seconds,
        claim: { claimID: `claim_${'4'.repeat(32)}`, requestID: '', keyFingerprint: 'ab'.repeat(32), csrHash: '', claimHash: '', comparisonCode: '12ab'.repeat(8), at: seconds - 200 },
        approval: { requestID: '', deviceID: id, keyFingerprint: 'ab'.repeat(32), at: seconds - 100 },
        intent: { intentID: '', requestID: '', serialHex: '', templateVersion: '', deviceID: id, keyFingerprint: 'ab'.repeat(32), notBefore: seconds - 100, notAfter: seconds + 86400, at: seconds - 100 }, issuance: { requestID: '', certificateHash: 'b'.repeat(64), at: seconds - 90 }, activation: { requestID: '', at: seconds - 80 }, termination: { requestID: '', from: '', at: 0 },
    };
}
function device(): Device {
    const metric = { value: null, unit: '%', quality: 'unknown' as const, source: 'Synthetic placeholder', collectedAt: missing };
    return { id, name: 'Synthetic report fixture', platform: 'linux', os: 'Awaiting agent', site: '', group: '', ip: null, status: 'unknown', source: 'lan', synthetic: false, lastSeen: missing, agentVersion: 'unknown', cpu: metric, memory: metric, disk: metric, uptime: '', tags: [], capabilities: [{ id: 'agent_identity', name: 'Enrolled agent identity', status: 'supported', detail: 'Synthetic committed activation' }], evidence: [], trend: [], caseIds: [], agentCertificate: { source: 'guided-enrollment', checkedAt: now, expiresAt: '2026-10-15T06:00:00Z' } };
}
let current: EnrollmentList;
const labels = { en: { waiting: 'Waiting for first report', pending: 'Activation pending', missing: 'No report recorded yet', expired: 'Identity expired', denied: 'Identity not admitted', unknown: 'Report status unavailable', report: 'Report', invitations: /Invitations/, review: `Review invitation ${invitation}`, refresh: 'Check status' }, de: { waiting: 'Warte auf erste Meldung', pending: 'Aktivierung ausstehend', missing: 'Noch keine Meldung erfasst', expired: 'Identität abgelaufen', denied: 'Identität nicht zugelassen', unknown: 'Meldungsstatus nicht verfügbar', report: 'Meldung', invitations: /Einladungen/, review: `Einladung ${invitation} prüfen`, refresh: 'Status prüfen' } } as const;
beforeEach(() => {
    setLocale('en', false); operator.authenticated = true; operator.mode = 'lan';
    current = { schemaVersion: 'tracebolt.enrollment-operator.v2', serverNow: now, enabled: true, platforms: ['linux'], recordLimit: 25, items: [record()], collectionProfile: 'managed-operations-v3', collectionPrivacy: 'complete_system_inventory_metadata_may_be_sensitive' };
    expect(validEnrollmentList(current, 'linux')).toBe(true);
    vi.mocked(request).mockReset().mockImplementation(async () => structuredClone(current)); vi.mocked(mutate).mockReset();
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it.each(['', missing, '0001-01-01T00:00:00.000000000Z', 'invalid', '2026-02-31T00:00:00Z', '2026-10-14T24:00:00Z', '2026-10-14', null, undefined])('rejects missing or invalid report timestamp %s', value => expect(reportTimestamp(value)).toBe(false));
it.each(['2020-01-01T12:00:00Z', '2026-10-13T12:00:00.123456789Z', '2026-10-13T14:00:00+02:00'])('preserves recorded timestamp bytes %s', lastSeen => {
    const d = { ...device(), lastSeen }; const result = render(<ReportTime device={d}/>);
    const time = result.container.querySelector('time')!;
    expect(time).toHaveAttribute('datetime', lastSeen); expect(time).toHaveAttribute('title', fullDate(lastSeen)); expect(time).toHaveTextContent(relativeTime(lastSeen));
});

for (const locale of ['en', 'de'] as const) describe(`conservative first-report state (${locale})`, () => {
    beforeEach(() => setLocale(locale, false)); const c = labels[locale];
    it.each(['approved', 'issuance_intent', 'issued'] as const)('keeps %s at activation pending', state => {
        const d = device(); d.capabilities[0].status = 'limited';
        render(<EnrollmentReport item={record(state)} device={d} now={Date.parse(now)} available/>);
        expect(screen.getByText(c.pending)).toBeVisible(); expect(screen.queryByText(c.waiting)).not.toBeInTheDocument();
    });
    it.each([missing, '0001-01-01T00:00:00.000000000Z'])('uses waiting only with matched activated admitted metadata and no valid time (%s)', lastSeen => {
        render(<EnrollmentReport item={record()} device={{ ...device(), lastSeen }} now={Date.parse(now)} available/>);
        expect(screen.getByText(c.waiting)).toBeVisible();
    });
    it.each(['', 'invalid', '2026-02-31T00:00:00Z', undefined])('keeps malformed or absent metadata unavailable (%s)', lastSeen => {
        const d = { ...device(), lastSeen } as Device;
        render(<><EnrollmentReport item={record()} device={d} now={Date.parse(now)} available/><DeviceTable devices={[d]} onSelect={vi.fn()}/></>);
        expect(screen.getAllByText(c.unknown)).toHaveLength(2); expect(screen.queryByText(c.waiting)).not.toBeInTheDocument(); expect(screen.queryByText(c.missing)).not.toBeInTheDocument();
    });
    it.each(['missing-device', 'wrong-device', 'missing-identity', 'limited-identity', 'duplicate-identity', 'absent-capabilities', 'null-capability', 'manual-certificate', 'invalid-certificate', 'future-check', 'synthetic'] as const)('keeps unsupported or inconsistent evidence unavailable for %s', scenario => {
        let d: Device | undefined = device();
        if (scenario === 'missing-device') d = undefined;
        else if (scenario === 'wrong-device') d.id = `agent_${'7'.repeat(32)}`;
        else if (scenario === 'missing-identity') d.capabilities = [];
        else if (scenario === 'limited-identity') d.capabilities[0].status = 'limited';
        else if (scenario === 'duplicate-identity') d.capabilities.push({ ...d.capabilities[0] });
        else if (scenario === 'absent-capabilities') d.capabilities = undefined as unknown as Device['capabilities'];
        else if (scenario === 'null-capability') d.capabilities = [null] as unknown as Device['capabilities'];
        else if (scenario === 'manual-certificate') d.agentCertificate!.source = 'manual-approval';
        else if (scenario === 'invalid-certificate') d.agentCertificate!.checkedAt = 'invalid';
        else if (scenario === 'future-check') d.agentCertificate!.checkedAt = '2026-10-14T06:00:01Z';
        else d.synthetic = true;
        render(<EnrollmentReport item={record()} device={d} now={Date.parse(now)} available/>);
        expect(screen.getByText(c.unknown)).toBeVisible(); expect(screen.queryByText(c.waiting)).not.toBeInTheDocument();
    });
    it.each(['denied', 'revoked', 'expired', 'certificate-expired', 'deadline', 'unavailable', 'clock'] as const)('gives %s precedence over waiting', scenario => {
        const d = device(), item = record();
        if (scenario === 'denied') d.capabilities[0].status = 'denied';
        if (scenario === 'revoked' || scenario === 'expired') item.state = scenario;
        if (scenario === 'certificate-expired') { d.agentCertificate!.expiresAt = now; item.intent.notAfter = seconds; }
        if (scenario === 'deadline') item.intent.notAfter = seconds;
        render(<EnrollmentReport item={item} device={d} now={scenario === 'clock' ? null : Date.parse(now)} available={scenario !== 'unavailable'}/>);
        expect(screen.getByText(['unavailable', 'clock', 'deadline'].includes(scenario) ? c.unknown : ['denied', 'revoked'].includes(scenario) ? c.denied : c.expired)).toBeVisible();
        expect(screen.queryByText(c.waiting)).not.toBeInTheDocument();
    });
    it.each(['healthy', 'blocked'] as const)('uses a generation-2 current leaf after original-anchor expiry (%s)', status => {
        const item = record(); item.intent.notAfter = seconds - 60;
        const d = device(); d.agentCertificate!.renewal = { status, enabled: status !== 'blocked', identityGeneration: `identity_${'8'.repeat(32)}`, credentialGeneration: 2, currentNotAfter: d.agentCertificate!.expiresAt!, authorityExpiresAt: '2026-10-16T06:00:00Z' };
        const result = render(<EnrollmentReport item={item} device={d} now={Date.parse(now)} available/>);
        expect(screen.getByText(c.waiting)).toBeVisible(); expect(screen.queryByText(c.expired)).not.toBeInTheDocument();
        d.lastSeen = '2026-10-14T05:59:30.123456789Z';
        result.rerender(<EnrollmentReport item={item} device={d} now={Date.parse(now)} available/>);
        expect(result.container.querySelector('time')).toHaveAttribute('datetime', d.lastSeen); expect(screen.queryByText(c.expired)).not.toBeInTheDocument(); expect(screen.queryByText(c.waiting)).not.toBeInTheDocument();
    });
    it.each(['no-renewal', 'generation-one', 'bad-generation', 'wrong-current-expiry', 'future-check'] as const)('does not accept an arbitrary later leaf from %s', problem => {
        const item = record(); item.intent.notAfter = seconds - 60;
        const d = device(); d.agentCertificate!.renewal = { status: 'healthy', enabled: true, identityGeneration: `identity_${'8'.repeat(32)}`, credentialGeneration: 2, currentNotAfter: d.agentCertificate!.expiresAt!, authorityExpiresAt: '2026-10-16T06:00:00Z' };
        if (problem === 'no-renewal') delete d.agentCertificate!.renewal;
        else if (problem === 'generation-one') d.agentCertificate!.renewal!.credentialGeneration = 1;
        else if (problem === 'bad-generation') d.agentCertificate!.renewal!.identityGeneration = 'invalid';
        else if (problem === 'wrong-current-expiry') d.agentCertificate!.renewal!.currentNotAfter = '2026-10-15T07:00:00Z';
        else d.agentCertificate!.checkedAt = '2026-10-14T06:01:00Z';
        render(<EnrollmentReport item={item} device={d} now={Date.parse(now)} available/>);
        expect(screen.getByText(c.unknown)).toBeVisible(); expect(screen.queryByText(c.waiting)).not.toBeInTheDocument(); expect(screen.queryByText(c.expired)).not.toBeInTheDocument();
    });
    it('keeps the renewed row, progress, report and warning consistent after anchor expiry', async () => {
        const item = record(); item.intent.notAfter = seconds - 60; current.items = [item];
        const d = device(); d.agentCertificate!.renewal = { status: 'healthy', enabled: true, identityGeneration: `identity_${'8'.repeat(32)}`, credentialGeneration: 2, currentNotAfter: d.agentCertificate!.expiresAt!, authorityExpiresAt: '2026-10-16T06:00:00Z' };
        const view = render(<EnrollmentSection devices={[d]} reportsAvailable deviceIds={[id]} onChanged={vi.fn()} onDevice={vi.fn()}/>);
        fireEvent.click(await screen.findByRole('button', { name: c.invitations }));
        const row = screen.getByRole('button', { name: c.review });
        expect(row.querySelector('.enrollment-status')).toHaveClass('state-activated');
        expect(row).toHaveTextContent(locale === 'de' ? 'Identität aktiviert' : 'Identity activated');
        fireEvent.click(row); const dialog = screen.getByRole('dialog');
        expect(within(dialog).getByText(c.waiting)).toBeVisible();
        expect(dialog.querySelector('.enrollment-status')).toHaveClass('state-activated');
        expect(dialog.querySelector('[aria-current="step"]')).toHaveTextContent(locale === 'de' ? 'Daten prüfen' : 'Check data');
        expect(dialog.querySelector('.enrollment-message.error')).toBeNull(); expect(dialog.querySelector('.state-expired')).toBeNull();
        fireEvent.click(within(dialog).getByText(locale === 'de' ? 'Ziel & Profil' : 'Destination & profile'));
        const originalLabel = within(dialog).getByText(locale === 'de' ? 'Ursprüngliches Zertifikat gültig bis' : 'Original certificate valid until');
        expect(originalLabel.nextElementSibling).toHaveTextContent(fullDate(new Date(item.intent.notAfter * 1000).toISOString()));
        const currentLabel = within(dialog).getByText(locale === 'de' ? 'Aktuelles Zertifikat gültig bis' : 'Current certificate valid until');
        expect(currentLabel.nextElementSibling).toHaveTextContent(fullDate(d.agentCertificate!.expiresAt!));
        // A later date alone is insufficient: the same real section must withdraw
        // its activation assertion and active progress when renewal proof disappears.
        delete d.agentCertificate!.renewal;
        view.rerender(<EnrollmentSection devices={[d]} reportsAvailable deviceIds={[id]} onChanged={vi.fn()} onDevice={vi.fn()}/>);
        expect(within(dialog).getByText(c.unknown)).toBeVisible(); expect(screen.queryByText(c.waiting)).not.toBeInTheDocument();
        expect(dialog.querySelector('.enrollment-status')).toHaveClass('state-unavailable'); expect(row.querySelector('.enrollment-status')).toHaveClass('state-unavailable');
        expect(dialog.querySelector('[aria-current="step"]')).toBeNull(); expect(dialog.querySelector('.enrollment-next-step')).toBeNull(); expect(dialog.querySelector('.state-expired')).toBeNull();
        expect(within(dialog).queryByText(locale === 'de' ? 'Aktuelles Zertifikat gültig bis' : 'Current certificate valid until')).not.toBeInTheDocument(); expect(mutate).not.toHaveBeenCalled();
    });
    it('preserves expiry precedence for an expired generation-2 current leaf', () => {
        const item = record(); item.intent.notAfter = seconds - 120;
        const d = device(); d.agentCertificate!.expiresAt = new Date((seconds - 60) * 1000).toISOString();
        d.agentCertificate!.renewal = { status: 'expired', enabled: true, identityGeneration: `identity_${'8'.repeat(32)}`, credentialGeneration: 2, currentNotAfter: d.agentCertificate!.expiresAt, authorityExpiresAt: '2026-10-16T06:00:00Z' };
        render(<EnrollmentReport item={item} device={d} now={Date.parse(now)} available/>);
        expect(screen.getByText(c.expired)).toBeVisible(); expect(screen.queryByText(c.waiting)).not.toBeInTheDocument();
    });
    it('retains expiry and denial without borrowing a missing device match', () => {
        const expired = record('expired'), result = render(<EnrollmentReport item={expired} now={Date.parse(now)} available/>);
        expect(screen.getByText(c.expired)).toBeVisible(); result.rerender(<EnrollmentReport item={record('revoked')} now={Date.parse(now)} available/>); expect(screen.getByText(c.denied)).toBeVisible();
    });
    it.each(['linux', 'macos', 'windows'] as const)('keeps an old %s report with missing metrics and original age', platform => {
        const d = { ...device(), platform, lastSeen: '2026-10-01T00:00:00.123456789Z' };
        if (platform === 'macos') d.capabilities.push({ id: 'macos_inventory', name: 'macOS inventory', status: 'scope', detail: 'Synthetic inventory-only contact' });
        const result = render(<><DeviceTable devices={[d]} onSelect={vi.fn()}/><EnrollmentReport item={record()} device={d} now={Date.parse(now)} available/><DeviceEssentials device={d} sessionKey={null} readReady={false} onDetails={vi.fn()}/></>);
        const times = result.container.querySelectorAll(`time[datetime="${d.lastSeen}"]`); expect(times.length).toBe(3);
        expect(times[0]).toHaveTextContent(relativeTime(d.lastSeen)); expect(times[1]).toHaveTextContent(fullDate(d.lastSeen));
        expect(screen.queryByText(c.waiting)).not.toBeInTheDocument(); expect(screen.queryByText(c.missing)).not.toBeInTheDocument(); expect(result.container).not.toHaveTextContent(/offline|online/i);
    });
    it('uses the conservative table fallback and keeps fetch-error precedence', () => {
        const result = render(<DeviceTable devices={[device()]} onSelect={vi.fn()}/>);
        expect(screen.getByText(c.missing)).toBeVisible(); expect(result.container.querySelector(`time[datetime="${missing}"]`)).toBeNull();
        result.rerender(<DeviceTable devices={[device()]} reportsAvailable={false} onSelect={vi.fn()}/>);
        expect(screen.getByText(c.unknown)).toBeVisible(); expect(screen.queryByText(c.missing)).not.toBeInTheDocument();
    });
    it('preserves a recorded report even while identity is denied', () => {
        const d = device(); d.lastSeen = '2026-10-01T00:00:00Z'; d.capabilities[0].status = 'denied';
        const result = render(<EnrollmentReport item={record()} device={d} now={Date.parse(now)} available/>);
        expect(screen.getByText(c.denied)).toBeVisible(); expect(result.container.querySelector('time')).toHaveAttribute('datetime', d.lastSeen);
    });
    it('joins the existing enrollment read without new requests, clears on failed refresh and respects navigation', async () => {
        const d = device(); const view = render(<EnrollmentSection devices={[d]} reportsAvailable deviceIds={[id]} onChanged={vi.fn()} onDevice={vi.fn()}/>);
        fireEvent.click(await screen.findByRole('button', { name: c.invitations })); fireEvent.click(screen.getByRole('button', { name: c.review }));
        expect(screen.getByText(c.waiting)).toBeVisible(); expect(request).toHaveBeenCalledTimes(1); expect(mutate).not.toHaveBeenCalled();
        view.rerender(<EnrollmentSection devices={[d, { ...d }]} reportsAvailable deviceIds={[id]} onChanged={vi.fn()} onDevice={vi.fn()}/>);
        expect(screen.getByText(c.unknown)).toBeVisible(); expect(screen.queryByText(c.waiting)).not.toBeInTheDocument();
        view.rerender(<EnrollmentSection devices={[d]} reportsAvailable deviceIds={[id]} onChanged={vi.fn()} onDevice={vi.fn()}/>);
        operator.authenticated = false; view.rerender(<EnrollmentSection devices={[d]} reportsAvailable deviceIds={[id]} onChanged={vi.fn()} onDevice={vi.fn()}/>);
        expect(screen.getByText(c.unknown)).toBeVisible(); expect(screen.queryByText(c.waiting)).not.toBeInTheDocument();
        operator.authenticated = true; view.rerender(<EnrollmentSection devices={[d]} reportsAvailable={false} deviceIds={[id]} onChanged={vi.fn()} onDevice={vi.fn()}/>);
        expect(screen.getByText(c.unknown)).toBeVisible();
        view.rerender(<EnrollmentSection devices={[d]} reportsAvailable deviceIds={[id]} onChanged={vi.fn()} onDevice={vi.fn()}/>);
        expect(screen.getByText(c.waiting)).toBeVisible();
        act(() => window.dispatchEvent(new Event('pagehide'))); expect(screen.getByText(c.unknown)).toBeVisible();
        vi.mocked(request).mockRejectedValueOnce(new Error('Synthetic read failure'));
        fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: c.refresh }));
        await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument()); expect(screen.queryByText(c.waiting)).not.toBeInTheDocument(); expect(screen.getByRole('alert')).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: locale === 'de' ? 'Enrollment-Status aktualisieren' : 'Refresh enrollment status' }));
        await waitFor(() => expect(screen.getByRole('button', { name: c.review })).toBeVisible()); fireEvent.click(screen.getByRole('button', { name: c.review }));
        expect(screen.getByText(c.waiting)).toBeVisible(); act(() => window.dispatchEvent(new Event('hashchange'))); expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(mutate).not.toHaveBeenCalled();
    });
});
