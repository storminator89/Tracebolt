import type {} from 'vitest/jsdom';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CustomerDevices, validCustomerDeviceView } from './customer-devices';
import { mutate, request } from './api';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const customer = { id:`customer_${'1'.repeat(32)}`, name:'Acme', revision:3 };
const device = { deviceId:`agent_${'2'.repeat(32)}`, identity:'ab'.repeat(32), customerId:'' };
const view = { schemaVersion:'tracebolt.customer-windows-assignments.v1', serverNow:'2026-10-28T18:00:00Z', validUntil:'2026-10-28T18:00:30Z', customers:[customer], devices:[device], unavailableAssignments:0 };
const assigned = { ...view, devices:[{...device,customerId:customer.id}] };
const future = '2099-01-01T00:00:00Z';
beforeEach(() => { setLocale('en', false); vi.mocked(request).mockReset().mockResolvedValue(view); vi.mocked(mutate).mockReset(); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); setLocale('en', false); });

async function selectBoth() {
    fireEvent.change(await screen.findByLabelText('Select a Windows identity'), { target:{value:device.deviceId} });
    fireEvent.change(screen.getByLabelText('Select a customer'), { target:{value:customer.id} });
}
describe('customer assignment for activated Windows identities', () => {
    it('rejects malformed, duplicate, unbound or oversized projections', () => {
        expect(validCustomerDeviceView(view)).toBe(true);
        expect(validCustomerDeviceView({...view,unavailableAssignments:100})).toBe(true);
        for (const bad of [null, {...view,extra:true}, {...view,serverNow:'unknown'}, {...view,serverNow:'2026-10-28T18:00:00+00:00'}, {...view,validUntil:view.serverNow}, {...view,validUntil:'2026-10-28T18:00:30.000000001Z'}, {...view,validUntil:'2026-10-28T18:00:31Z'}, {...view,devices:[device,device]}, {...view,customers:[customer,customer]}, {...view,devices:[{...device,identity:'0'.repeat(64)}]}, {...view,devices:[{...device,customerId:`customer_${'3'.repeat(32)}`}]}, {...view,unavailableAssignments:-1}, {...view,unavailableAssignments:101}, {...view,devices:Array(26).fill(device)}]) expect(validCustomerDeviceView(bad)).toBe(false);
    });
    it('requires exact selection and unchecked local acknowledgement before a single POST', async () => {
        vi.mocked(mutate).mockResolvedValue(assigned);
        render(<CustomerDevices sessionExpiresAt={future}/>);
        await selectBoth();
        expect(screen.getByText('Organization, not tenant isolation')).toBeVisible();
        expect(screen.getAllByText(device.identity).length).toBeGreaterThan(0);
        const confirm = screen.getByRole('checkbox');
        expect(confirm).not.toBeChecked();
        expect(screen.getByRole('button', {name:'Assign reviewed identity'})).toBeDisabled();
        expect(mutate).not.toHaveBeenCalled();
        fireEvent.click(confirm);
        fireEvent.click(screen.getByRole('button', {name:'Assign reviewed identity'}));
        await waitFor(() => expect(screen.queryByRole('checkbox')).not.toBeInTheDocument());
        expect(within(screen.getByRole('list', {name:'Recorded assignments'})).getByText('Acme')).toBeVisible();
        expect(mutate).toHaveBeenCalledExactlyOnceWith('/customer-windows-assignments', {customerId:customer.id,customerRevision:3,deviceId:device.deviceId,identity:device.identity,acknowledged:true}, expect.any(AbortSignal));
        expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    });
    it('keeps both customers visible while an organizational selection performs no extra read or write', async () => {
        const other = {id:`customer_${'4'.repeat(32)}`,name:'Other customer',revision:1};
        const otherDevice = {deviceId:`agent_${'5'.repeat(32)}`,identity:'cd'.repeat(32),customerId:other.id};
        const unassignedDevice = {deviceId:`agent_${'6'.repeat(32)}`,identity:'ef'.repeat(32),customerId:''};
        vi.mocked(request).mockResolvedValue({...view,customers:[customer,other],devices:[assigned.devices[0],otherDevice,unassignedDevice]});
        render(<CustomerDevices sessionExpiresAt="2089-01-01T00:00:00Z"/>);
        const selection = await screen.findByLabelText('Select a customer');
        const list = screen.getByRole('list',{name:'Recorded assignments'});
        for (const selected of [customer.id,other.id]) {
            fireEvent.change(selection,{target:{value:selected}});
            expect(within(list).getAllByRole('listitem')).toHaveLength(3);
            expect(within(list).getByText(customer.name,{exact:true})).toBeVisible();
            expect(within(list).getByText(other.name,{exact:true})).toBeVisible();
            expect(screen.getByRole('button',{name:'Assign reviewed identity'})).toBeDisabled();
            expect(mutate).not.toHaveBeenCalled();
        }
        expect(request).toHaveBeenCalledExactlyOnceWith('/customer-windows-assignments',{signal:expect.any(AbortSignal)});
    });
    it('clears acknowledgement when the selected customer changes', async () => {
        const other = {id:`customer_${'4'.repeat(32)}`,name:'Other',revision:1};
        vi.mocked(request).mockResolvedValue({...view,customers:[customer,other]});
        render(<CustomerDevices sessionExpiresAt={future}/>); await selectBoth();
        fireEvent.click(screen.getByRole('checkbox'));
        fireEvent.change(screen.getByLabelText('Select a customer'), {target:{value:other.id}});
        expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(mutate).not.toHaveBeenCalled();
    });
    it('stops on an unconfirmed response and only refreshes via GET', async () => {
        vi.mocked(mutate).mockRejectedValue(new Error('response lost'));
        render(<CustomerDevices sessionExpiresAt={future}/>); await selectBoth(); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', {name:'Assign reviewed identity'}));
        expect(await screen.findByRole('alert')).toHaveTextContent('may have been saved');
        expect(screen.queryByRole('button', {name:'Assign reviewed identity'})).not.toBeInTheDocument();
        vi.mocked(request).mockResolvedValue(assigned); fireEvent.click(screen.getByRole('button', {name:'Refresh assignments'}));
        expect(await screen.findByText('Acme')).toBeVisible(); expect(mutate).toHaveBeenCalledTimes(1);
    });
    it('does not treat an unassigned GET as proof that an unconfirmed POST failed', async () => {
        vi.mocked(mutate).mockRejectedValue(new Error('response lost'));
        render(<CustomerDevices sessionExpiresAt={future}/>); await selectBoth(); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', {name:'Assign reviewed identity'}));
        await screen.findByRole('alert');
        fireEvent.click(screen.getByRole('button', {name:'Refresh assignments'}));
        expect(await screen.findByText(/An empty result does not prove/)).toBeVisible();
        expect(screen.queryByRole('button', {name:'Assign reviewed identity'})).not.toBeInTheDocument();
        expect(mutate).toHaveBeenCalledTimes(1);
        vi.mocked(request).mockResolvedValue(assigned);
        fireEvent.click(screen.getByRole('button', {name:'Refresh assignments'}));
        await waitFor(() => expect(screen.queryByText(/An empty result does not prove/)).not.toBeInTheDocument());
        expect(mutate).toHaveBeenCalledTimes(1);
    });
    it('does not show stale or late data after navigation, including an interrupted write', async () => {
        let finish!: (value:unknown) => void;
        vi.mocked(mutate).mockImplementation(() => new Promise(resolve => {finish = resolve;}));
        render(<CustomerDevices sessionExpiresAt={future}/>); await selectBoth(); fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', {name:'Assign reviewed identity'}));
        fireEvent(window,new HashChangeEvent('hashchange')); await act(async () => finish(assigned));
        expect(screen.getByRole('alert')).toHaveTextContent('may have been saved'); expect(screen.queryByText(device.identity)).not.toBeInTheDocument(); expect(mutate).toHaveBeenCalledTimes(1);
    });
    it('provides truthful German empty and unavailable states', async () => {
        setLocale('de',false); vi.mocked(request).mockResolvedValue({...view,devices:[],unavailableAssignments:2});
        render(<CustomerDevices sessionExpiresAt={future}/>);
        const panel = await screen.findByRole('region',{name:'Windows-Geräte Kunden zuordnen'});
        expect(await within(panel).findByText('Keine aktuell zugelassenen Windows-Identitäten.')).toBeVisible();
        expect(within(panel).getByText(/Zuvor gespeicherte Zuordnungen nicht verfügbar: 2/)).toBeVisible();
        expect(within(panel).getByText(/Eine ausstehende Gerätefreigabe wird dadurch nicht erteilt/)).toBeVisible();
    });
    it('withholds the projection and blocks a POST once server-bound source authority expires', async () => {
        render(<CustomerDevices sessionExpiresAt="2097-01-01T00:00:00Z"/>); await selectBoth(); fireEvent.click(screen.getByRole('checkbox'));
        const mono = performance.now(), wall = Date.now();
        vi.spyOn(performance, 'now').mockImplementation(() => mono + 31000);
        vi.spyOn(Date, 'now').mockImplementation(() => wall + 31000);
        // Even before the periodic UI expiry runs, admission checks the clock.
        fireEvent.click(screen.getByRole('button', {name:'Assign reviewed identity'}));
        expect(mutate).not.toHaveBeenCalled();
        await act(async () => { await new Promise(resolve => setTimeout(resolve, 200)); });
        expect(screen.getByRole('alert')).toHaveTextContent('no longer available');
        expect(screen.queryByText(device.identity)).not.toBeInTheDocument();
    });
    it('uses manager time for session expiry even when the workstation clock differs', async () => {
        render(<CustomerDevices sessionExpiresAt="2026-10-28T18:00:02Z"/>); await selectBoth();
        expect(screen.getByRole('checkbox')).not.toBeChecked(); expect(mutate).not.toHaveBeenCalled();
    });
    it('keeps an in-flight write uncertain when the source expires before its response', async () => {
        let finish!: (value:unknown) => void;
        vi.mocked(mutate).mockImplementation(() => new Promise(resolve => {finish=resolve;}));
        render(<CustomerDevices sessionExpiresAt="2096-01-01T00:00:00Z"/>); await selectBoth();
        fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', {name:'Assign reviewed identity'}));
        const mono = performance.now(), wall = Date.now();
        vi.spyOn(performance, 'now').mockImplementation(() => mono + 31000);
        vi.spyOn(Date, 'now').mockImplementation(() => wall + 31000);
        await act(async () => { await new Promise(resolve => setTimeout(resolve, 200)); });
        expect(screen.getByRole('alert')).toHaveTextContent('may have been saved');
        await act(async () => finish(assigned));
        expect(screen.getByRole('alert')).toHaveTextContent('may have been saved');
        expect(screen.queryByText(device.identity)).not.toBeInTheDocument(); expect(mutate).toHaveBeenCalledTimes(1);
    });
    it('preserves the unconfirmed-write fence across a component remount in the same page session', async () => {
        let finish!: (value:unknown) => void;
        vi.mocked(mutate).mockImplementation(() => new Promise(resolve => {finish=resolve;}));
        const component = render(<CustomerDevices sessionExpiresAt="2095-01-01T00:00:00Z"/>); await selectBoth();
        fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', {name:'Assign reviewed identity'}));
        component.unmount(); await act(async () => finish(view));
        render(<CustomerDevices sessionExpiresAt="2095-01-01T00:00:00Z"/>);
        expect(await screen.findByText(/An empty result does not prove/)).toBeVisible();
        expect(screen.queryByRole('button', {name:'Assign reviewed identity'})).not.toBeInTheDocument();
        expect(mutate).toHaveBeenCalledTimes(1);
    });
    it('invalidates an interrupted write on pagehide and does not replay after bfcache return', async () => {
        let finish!: (value:unknown) => void;
        vi.mocked(mutate).mockImplementation(() => new Promise(resolve => {finish=resolve;}));
        render(<CustomerDevices sessionExpiresAt="2094-01-01T00:00:00Z"/>); await selectBoth();
        fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', {name:'Assign reviewed identity'}));
        fireEvent(window, new Event('pagehide')); await act(async () => finish(assigned));
        expect(screen.getByRole('alert')).toHaveTextContent('may have been saved');
        fireEvent(window, new Event('pageshow'));
        expect(screen.queryByText(device.identity)).not.toBeInTheDocument(); expect(mutate).toHaveBeenCalledTimes(1);
    });
});
