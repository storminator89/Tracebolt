import userEvent from '@testing-library/user-event';
import type {} from 'vitest/jsdom';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Customers, validCustomerCatalog } from './customers';
import { APIError, mutate, request } from './api';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const id = `customer_${'1'.repeat(32)}`;
const empty = { schemaVersion: 'tracebolt.customers.v1', customers: [] };
const record = { id, name: 'Acme', revision: 1 };
const view = { schemaVersion: 'tracebolt.customers.v1', customers: [record] };
const future = '2099-01-01T00:00:00Z';
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset(); vi.mocked(mutate).mockReset(); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); setLocale('en', false); });

describe('customer catalog', () => {
    it('shows explicit read-only records without any create or rename controls', async () => {
        vi.mocked(request).mockResolvedValue(view);
        render(<Customers sessionExpiresAt={future} readOnly/>);
        expect(await screen.findByText('Acme')).toBeVisible();
        expect(screen.getByText('Read-only: customer records and assignments cannot be changed.')).toBeVisible();
        expect(screen.queryByLabelText('Customer name')).not.toBeInTheDocument();
        expect(screen.queryByRole('button', {name: 'Edit Acme'})).not.toBeInTheDocument();
        expect(screen.queryByRole('button', {name: 'Create customer'})).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', {name: 'Refresh customers'}));
        expect(await screen.findByText('Acme')).toBeVisible();
        expect(mutate).not.toHaveBeenCalled();
    });
    it('strictly validates schema, identities, names, revisions and bounds', () => {
        expect(validCustomerCatalog(view)).toBe(true);
        for (const invalid of [null, { ...view, extra: 1 }, { ...view, schemaVersion: 'wrong' }, { ...view, customers: [record, record] }, { ...view, customers: [{ ...record, id: `customer_${'0'.repeat(32)}` }] }, { ...view, customers: [{ ...record, revision: 0 }] }, { ...view, customers: [{ ...record, name: ' Acme' }] }, { ...view, customers: [{ ...record, name: 'A\u0000' }] }, { ...view, customers: new Array(26).fill(record) }]) expect(validCustomerCatalog(invalid)).toBe(false);
    });
    it('loads an empty list and creates one record with explicit revision zero', async () => {
        vi.mocked(request).mockResolvedValue(empty); vi.mocked(mutate).mockResolvedValue(view);
        render(<Customers sessionExpiresAt={future}/>);
        expect(await screen.findByText('No customers yet.')).toBeVisible();
        expect(screen.getByText(/do not isolate access or assign devices or installers/)).toBeVisible();
        expect(screen.getByText('Organization, not tenant isolation')).toBeVisible();
        fireEvent.change(screen.getByLabelText('Customer name'), { target: { value: 'Acme' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create customer' }));
        expect(await screen.findByText('Acme')).toBeVisible();
        expect(mutate).toHaveBeenCalledExactlyOnceWith('/customers', { name: 'Acme', expectedRevision: 0 }, expect.any(AbortSignal));
    });
    it('edits the selected exact id and revision', async () => {
        vi.mocked(request).mockResolvedValue(view); vi.mocked(mutate).mockResolvedValue({ ...view, customers: [{ ...record, name: 'New name', revision: 2 }] });
        render(<Customers sessionExpiresAt={future}/>);
        fireEvent.click(await screen.findByRole('button', { name: 'Edit Acme' }));
        fireEvent.change(screen.getByLabelText('Customer name'), { target: { value: 'New name' } });
        fireEvent.click(screen.getByRole('button', { name: 'Save name' }));
        expect(await screen.findByText('New name')).toBeVisible();
        expect(mutate).toHaveBeenCalledExactlyOnceWith(`/customers/${id}`, { name: 'New name', expectedRevision: 1 }, expect.any(AbortSignal));
    });
    it('stops on conflict and requires an explicit fresh read before another write', async () => {
        vi.mocked(request).mockResolvedValue(view); vi.mocked(mutate).mockRejectedValue(new APIError('conflict', 409));
        render(<Customers sessionExpiresAt={future}/>);
        fireEvent.click(await screen.findByRole('button', { name: 'Edit Acme' }));
        fireEvent.change(screen.getByLabelText('Customer name'), { target: { value: 'New name' } });
        fireEvent.click(screen.getByRole('button', { name: 'Save name' }));
        expect(await screen.findByRole('alert')).toHaveTextContent('changed');
        expect(screen.queryByRole('button', { name: 'Save name' })).not.toBeInTheDocument();
        expect(mutate).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh customers' }));
        expect(await screen.findByRole('button', { name: 'Edit Acme' })).toBeVisible();
        expect(mutate).toHaveBeenCalledTimes(1);
    });
    it('marks a missing or invalid write response uncertain and never retries automatically', async () => {
        vi.mocked(request).mockResolvedValue(empty); vi.mocked(mutate).mockResolvedValue(empty);
        render(<Customers sessionExpiresAt={future}/>); await screen.findByText('No customers yet.');
        fireEvent.change(screen.getByLabelText('Customer name'), { target: { value: 'Acme' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create customer' }));
        expect(await screen.findByRole('alert')).toHaveTextContent('may have been saved');
        expect(mutate).toHaveBeenCalledTimes(1);
        expect(screen.queryByLabelText('Customer name')).not.toBeInTheDocument();
    });
    it('requires explicit readback and a new user action after an uncertain network failure', async () => {
        vi.mocked(request).mockResolvedValue(empty); vi.mocked(mutate).mockRejectedValue(new Error('connection lost'));
        render(<Customers sessionExpiresAt={future}/>); await screen.findByText('No customers yet.');
        fireEvent.change(screen.getByLabelText('Customer name'), { target: { value: 'Acme' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create customer' }));
        expect(await screen.findByRole('alert')).toHaveTextContent('may have been saved');
        expect(request).toHaveBeenCalledTimes(1); expect(mutate).toHaveBeenCalledTimes(1);
        vi.mocked(request).mockResolvedValue(view);
        fireEvent.click(screen.getByRole('button', { name: 'Refresh customers' }));
        expect(await screen.findByText('Acme')).toBeVisible();
        expect(screen.getByLabelText('Customer name')).toHaveValue('');
        expect(screen.getByRole('button', { name: 'Create customer' })).toBeDisabled();
        expect(mutate).toHaveBeenCalledTimes(1);
    });
    it('discards an interrupted German write and requires readback', async () => {
        setLocale('de', false); let finish!: (value: unknown) => void;
        vi.mocked(request).mockResolvedValue(empty);
        vi.mocked(mutate).mockImplementation(() => new Promise(resolve => { finish = resolve; }));
        render(<Customers sessionExpiresAt={future}/>); await screen.findByText('Noch keine Kunden vorhanden.');
        fireEvent.change(screen.getByLabelText('Kundenname'), { target: { value: 'Acme' } });
        fireEvent.click(screen.getByRole('button', { name: 'Kunde erstellen' }));
        fireEvent(window, new HashChangeEvent('hashchange'));
        await act(async () => finish(view));
        expect(screen.getByRole('alert')).toHaveTextContent('möglicherweise gespeichert');
        expect(screen.queryByText('Acme')).not.toBeInTheDocument();
        expect(mutate).toHaveBeenCalledTimes(1);
        expect(screen.queryByLabelText('Kundenname')).not.toBeInTheDocument();
    });
    it('discards a delayed response after navigation', async () => {
        let finish!: (value: unknown) => void;
        vi.mocked(request).mockImplementation(() => new Promise(resolve => { finish = resolve; }));
        render(<Customers sessionExpiresAt={future}/>);
        fireEvent(window, new HashChangeEvent('hashchange'));
        await act(async () => finish(view));
        expect(screen.queryByText('Acme')).not.toBeInTheDocument();
        expect(screen.getByRole('alert')).toHaveTextContent('no longer available');
    });
    it('provides German copy and rejects whitespace-only names', async () => {
        setLocale('de', false); vi.mocked(request).mockResolvedValue(empty);
        render(<Customers sessionExpiresAt={future}/>);
        const panel = await screen.findByRole('region', { name: 'Kunden' });
        expect(within(panel).getByText(/ordnen weder Geräte noch Installer zu/)).toBeVisible();
        expect(within(panel).getByText('Organisation, keine Mandantentrennung')).toBeVisible();
        fireEvent.change(await within(panel).findByLabelText('Kundenname'), { target: { value: '  ' } });
        expect(within(panel).getByRole('button', { name: 'Kunde erstellen' })).toBeDisabled();
    });
    it('hides prior values on an invalid catalog response', async () => {
        vi.mocked(request).mockResolvedValue({ ...view, extra: true }); render(<Customers sessionExpiresAt={future}/>);
        await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('unavailable'));
        expect(screen.queryByText('Acme')).not.toBeInTheDocument();
    });
});


describe('customer edit focus', () => {
    it.each(['en', 'de'] as const)('focuses the editor and returns on cancel without saving (%s)', async locale => {
        setLocale(locale, false); vi.mocked(request).mockResolvedValue(view);
        const user = userEvent.setup(); render(<Customers sessionExpiresAt={future}/>);
        const edit = await screen.findByRole('button', { name: locale === 'de' ? 'Bearbeiten Acme' : 'Edit Acme' });
        edit.focus(); await user.keyboard('{Enter}');
        const input = screen.getByRole('textbox', { name: locale === 'de' ? 'Kundenname' : 'Customer name' });
        expect(input).toHaveFocus(); expect(input).toHaveValue('Acme');
        edit.focus(); await user.keyboard('{Enter}'); expect(input).toHaveFocus();
        await user.type(input, ' draft');
        const cancel = screen.getByRole('button', { name: locale === 'de' ? 'Abbrechen' : 'Cancel' });
        cancel.focus(); await user.keyboard(' ');
        expect(edit).toHaveFocus(); expect(input).toHaveValue('');
        expect(mutate).not.toHaveBeenCalled(); expect(request).toHaveBeenCalledTimes(1);
    });
    it('focuses the newly mounted editor at the 25-customer limit and returns before it disappears', async () => {
        const customers = Array.from({length:25}, (_,i)=>({id:`customer_${(i+1).toString(16).padStart(32,'0')}`,name:`Fixture ${i}`,revision:1}));
        vi.mocked(request).mockResolvedValue({...view,customers}); render(<Customers sessionExpiresAt={future}/>);
        const edit=await screen.findByRole('button',{name:'Edit Fixture 24'});
        expect(screen.queryByRole('textbox')).toBeNull(); fireEvent.click(edit);
        expect(screen.getByRole('textbox',{name:'Customer name'})).toHaveFocus();
        fireEvent.click(screen.getByRole('button',{name:'Cancel'}));
        expect(edit).toHaveFocus(); expect(screen.queryByRole('textbox')).toBeNull(); expect(mutate).not.toHaveBeenCalled();
    });
    it('does not restore focus to an old customer after refresh removes that record', async () => {
        vi.mocked(request).mockResolvedValueOnce(view).mockResolvedValueOnce(empty);
        render(<Customers sessionExpiresAt={future}/>);
        const edit=await screen.findByRole('button',{name:'Edit Acme'}); fireEvent.click(edit);
        const refresh=screen.getByRole('button',{name:'Refresh customers'}); refresh.focus(); fireEvent.click(refresh);
        await screen.findByText('No customers yet.');
        expect(refresh).toHaveFocus(); expect(edit).not.toBeInTheDocument();
        expect(screen.getByRole('textbox',{name:'Customer name'})).toHaveValue(''); expect(screen.queryByRole('button',{name:'Cancel'})).toBeNull(); expect(mutate).not.toHaveBeenCalled();
    });
    it('targets the latest selected customer and does not recreate an editor after read-only access', async () => {
        vi.mocked(request).mockResolvedValue({...view,customers:[record,{...record,id:`customer_${'2'.repeat(32)}`,name:'Other'}]});
        const mounted=render(<Customers sessionExpiresAt={future}/>);
        fireEvent.click(await screen.findByRole('button',{name:'Edit Acme'}));
        const other=screen.getByRole('button',{name:'Edit Other'}); fireEvent.click(other);
        expect(screen.getByRole('textbox',{name:'Customer name'})).toHaveFocus(); expect(screen.getByRole('textbox')).toHaveValue('Other');
        fireEvent.click(screen.getByRole('button',{name:'Cancel'})); expect(other).toHaveFocus();
        fireEvent.click(other); mounted.rerender(<Customers sessionExpiresAt={future} readOnly/>);
        expect(screen.queryByRole('textbox')).toBeNull(); expect(screen.queryByRole('button',{name:'Cancel'})).toBeNull(); expect(mutate).not.toHaveBeenCalled();
    });
});
