import type {} from 'vitest/jsdom';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { CustomerRecords } from './customer-records';
import { useOperator } from './auth';

vi.mock('./auth', () => ({ useOperator: vi.fn() }));
vi.mock('./customers', () => ({ Customers: ({ readOnly }: { readOnly: boolean }) => <output aria-label="Customer catalog mode">{readOnly ? 'read-only' : 'shared-write'}</output> }));
vi.mock('./customer-devices', () => ({ CustomerDevices: ({ readOnly }: { readOnly: boolean }) => <output aria-label="Customer assignments mode">{readOnly ? 'read-only' : 'shared-write'}</output> }));
const named = { mode: 'lan', authenticated: true, checkingAccess: false, hasExplicitMetadata: true, loginMode: 'named', actorId: `operator_${'1'.repeat(32)}`, capabilities: ['read', 'read_customers'], expiresAt: '2099-01-01T00:00:00Z', insecureTestMode: false, logout: vi.fn(), theme: 'light', setTheme: vi.fn() } satisfies NonNullable<ReturnType<typeof useOperator>>;
beforeEach(() => vi.mocked(useOperator).mockReturnValue(named));
afterEach(() => { cleanup(); vi.clearAllMocks(); });

it.each([
    null,
    { ...named, authenticated: false },
    { ...named, checkingAccess: true },
    { ...named, hasExplicitMetadata: false },
    { ...named, expiresAt: null },
    { ...named, capabilities: ['read'] as const },
    { ...named, capabilities: ['read', 'manage_sessions', 'restart_service'] as const },
])('does not mount customer readers without confirmed explicit access: %j', operator => {
    vi.mocked(useOperator).mockReturnValue(operator);
    render(<CustomerRecords revision={1}/>);
    expect(screen.queryByLabelText('Customer catalog mode')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Customer assignments mode')).not.toBeInTheDocument();
});

it('mounts only read-only customer views for the explicit named grant', () => {
    render(<CustomerRecords revision={1}/>);
    expect(screen.getByLabelText('Customer catalog mode')).toHaveTextContent('read-only');
    expect(screen.getByLabelText('Customer assignments mode')).toHaveTextContent('read-only');
});

it('preserves explicit shared administration without inferring it from missing metadata', () => {
    vi.mocked(useOperator).mockReturnValue({ ...named, loginMode: 'shared', actorId: null, capabilities: ['read'] });
    render(<CustomerRecords revision={1}/>);
    expect(screen.getByLabelText('Customer catalog mode')).toHaveTextContent('shared-write');
    expect(screen.getByLabelText('Customer assignments mode')).toHaveTextContent('shared-write');
});

it('unmounts both views when access is being rechecked or the next actor lacks the grant', () => {
    const { rerender } = render(<CustomerRecords revision={1}/>);
    vi.mocked(useOperator).mockReturnValue({ ...named, checkingAccess: true });
    rerender(<CustomerRecords revision={1}/>);
    expect(screen.queryByLabelText('Customer catalog mode')).not.toBeInTheDocument();
    vi.mocked(useOperator).mockReturnValue({ ...named, actorId: `operator_${'2'.repeat(32)}`, capabilities: ['read'] });
    rerender(<CustomerRecords revision={2}/>);
    expect(screen.queryByLabelText('Customer assignments mode')).not.toBeInTheDocument();
});
