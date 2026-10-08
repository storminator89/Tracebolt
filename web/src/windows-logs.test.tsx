import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT } from './api';
import { setLocale } from './i18n';
import { WindowsLogsPanel } from './windows-logs';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import { windowsEventsView, windowsEventsFixture } from './windows-events-fixture';
import { validWindowsInventoryView } from './windows-inventory-types';
import { windowsDeviceId } from './windows-inventory-fixture';

function resource(): WindowsInventoryResource { const view = windowsEventsView(); return { view, snapshot: view.snapshot, events: view.events, eventsStale: false, volumes: null, volumesStale: false, processMetrics: null, processMetricsStale: false, network: null, networkStale: false, networkExpired: false, status: 'fresh', loading: false, error: null, refresh: vi.fn() }; }
const tableRows = () => within(screen.getByRole('table')).getAllByRole('row').slice(1);
const change = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
beforeEach(() => setLocale('en', false));
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('Windows captured-header Logs browser', () => {
    it('uses a valid bounded fixture, interleaves newest event times and preserves full record IDs', () => {
        expect(validWindowsInventoryView(windowsEventsView(), windowsDeviceId)).toBe(true);
        render(<WindowsLogsPanel resource={resource()}/>);
        expect(screen.getByText(/Filters and pages do not retrieve older events/)).toBeVisible();
        expect(tableRows()).toHaveLength(10);
        expect(tableRows()[0]).toHaveTextContent('Application'); expect(tableRows()[1]).toHaveTextContent('System');
        expect(tableRows()[0]).toHaveTextContent('18446744073709551615');
        expect(screen.getByText('Page 1 of 3 · 24 matching headers')).toBeVisible();
        expect(screen.getAllByText('More events are omitted.')).toHaveLength(2);
        expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled();
        fireEvent.click(screen.getByRole('button', { name: 'Next' })); fireEvent.click(screen.getByRole('button', { name: 'Next' }));
        expect(tableRows()).toHaveLength(4); expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
        fireEvent.click(screen.getByRole('button', { name: 'Previous' })); expect(screen.getByText('Page 2 of 3 · 24 matching headers')).toBeVisible();
    });
    it('combines local channel, exact level, literal provider and exact event-ID filters and resets pages', () => {
        const value = resource(); render(<WindowsLogsPanel resource={value}/>);
        fireEvent.click(screen.getByRole('button', { name: 'Next' })); change('Channel', 'System');
        expect(screen.getByText('Page 1 of 2 · 12 matching headers')).toBeVisible();
        change('Level', '2'); change('Provider', 'provider a'); change('Event ID', '102');
        expect(tableRows()).toHaveLength(1); expect(tableRows()[0]).toHaveTextContent('102');
        change('Event ID', '2'); expect(screen.getByText('No headers in this sample match these filters.')).toBeVisible();
        fireEvent.click(screen.getByRole('button', { name: 'Reset filters' }));
        expect(screen.getByLabelText('Provider')).toHaveValue(''); expect(screen.getByLabelText('Channel')).toHaveValue(''); expect(tableRows()).toHaveLength(10);
        change('Provider', '.*'); expect(screen.queryByRole('table')).toBeNull();
        expect(value.refresh).not.toHaveBeenCalled();
    });
    it('keeps unknown/reserved levels visible and rejects invalid event-ID filters', () => {
        render(<WindowsLogsPanel resource={resource()}/>); change('Level', 'unknown');
        expect(tableRows()).toHaveLength(6); expect(screen.getAllByText('Unknown / reserved (6)')).toHaveLength(2);
        change('Event ID', '65536'); expect(screen.getByRole('alert')).toHaveTextContent('Enter an event ID from 0 to 65535.'); expect(screen.getByLabelText('Event ID')).toHaveAttribute('aria-invalid', 'true');
        change('Event ID', '1e2'); expect(screen.queryByRole('table')).toBeNull();
    });
    it('retains filters and page through an identical snapshot refresh, but starts a new generation on page one', () => {
        const value = resource(), ui = render(<WindowsLogsPanel resource={value}/>);
        change('Provider', 'Fixture'); const input = screen.getByLabelText('Provider'); input.focus();
        fireEvent.click(screen.getByRole('button', { name: 'Next' }));
        ui.rerender(<WindowsLogsPanel resource={{ ...value, view: null, snapshot: null, events: null, status: null, loading: true }}/>);
        expect(screen.getByLabelText('Provider')).toBe(input); expect(input).toHaveValue('Fixture'); expect(input).not.toBeDisabled(); expect(input).toHaveFocus(); expect(screen.queryByRole('table')).toBeNull();
        ui.rerender(<WindowsLogsPanel resource={resource()}/>); expect(screen.getByText('Page 2 of 3 · 24 matching headers')).toBeVisible();
        const newer = resource(); newer.events!.generationId = `sample_${'b'.repeat(32)}`; ui.rerender(<WindowsLogsPanel resource={newer}/>);
        expect(screen.getByText('Page 1 of 3 · 24 matching headers')).toBeVisible(); expect(input).toHaveValue('Fixture');
    });
    it('preserves the focused page control through a poll without enabling a page change or retaining rows', () => {
        const value = resource(), ui = render(<WindowsLogsPanel resource={value}/>);
        const next = screen.getByRole('button', { name: 'Next' }); fireEvent.click(next); next.focus();
        ui.rerender(<WindowsLogsPanel resource={{ ...value, view: null, snapshot: null, events: null, status: null, loading: true }}/>);
        expect(screen.getByRole('button', { name: 'Next' })).toBe(next); expect(next).toHaveFocus(); expect(next).toHaveAttribute('aria-disabled', 'true'); expect(screen.queryByRole('table')).toBeNull();
        fireEvent.click(next); ui.rerender(<WindowsLogsPanel resource={resource()}/>);
        expect(next).toHaveFocus(); expect(screen.getByText('Page 2 of 3 · 24 matching headers')).toBeVisible();
    });
    it('shows original capture and source state without turning denied, partial or empty into healthy', () => {
        const value = resource(); value.eventsStale = true; value.events!.channels[0].quality = 'partial'; value.events!.channels[0].reason = 'windows_events_read_failed'; value.events!.channels[1] = { channel: 'System', quality: 'denied', reason: 'windows_events_access_denied', complete: false, truncated: false, observedCount: 0, rows: [] };
        const ui = render(<WindowsLogsPanel resource={value}/>); expect(screen.getByRole('status')).toHaveTextContent('Stale sample'); expect(screen.getByText('Source read incomplete.')).toBeVisible(); expect(screen.getByText('Access denied · 0 sample headers')).toBeVisible(); expect(document.querySelector('time[datetime="2026-10-07T12:00:02Z"]')).not.toBeNull();
        const empty = resource(); for (const channel of empty.events!.channels) { channel.rows = []; channel.observedCount = 0; channel.truncated = false; channel.quality = 'observed'; channel.complete = true; }
        ui.rerender(<WindowsLogsPanel resource={empty}/>); expect(screen.getByText('No event headers in this sample. This does not establish a healthy system.')).toBeVisible();
        ui.rerender(<WindowsLogsPanel resource={{ ...resource(), events: null, view: null, snapshot: null, status: 'not_configured' }}/>); expect(screen.getByRole('status')).toHaveTextContent('No current event-header sample reported.'); expect(screen.queryByRole('table')).toBeNull();
    });
    it('removes headers on expiration, revoke, session loss and transport error', () => {
        const value = resource(), ui = render(<WindowsLogsPanel resource={value}/>);
        ui.rerender(<WindowsLogsPanel resource={{ ...value, events: null, snapshot: null, status: 'unavailable' }}/>); expect(screen.getByRole('status')).toHaveTextContent('Event sample expired.'); expect(screen.queryByRole('table')).toBeNull(); expect(screen.queryByText('Fixture Provider A')).toBeNull();
        ui.rerender(<WindowsLogsPanel resource={{ ...value, error: 'unavailable' }}/>); expect(screen.getByRole('alert')).toHaveTextContent('unavailable'); expect(screen.queryByRole('table')).toBeNull();
        ui.rerender(<WindowsLogsPanel resource={{ ...value, status: 'revoked' }}/>); expect(screen.getByRole('status')).toHaveTextContent('Device access ended.'); expect(screen.queryByRole('table')).toBeNull();
        ui.rerender(<WindowsLogsPanel resource={value}/>); change('Provider', 'Fixture');
        ui.rerender(<WindowsLogsPanel resource={{ ...value, error: 'session' }}/>); expect(screen.getByLabelText('Provider')).toHaveValue(''); expect(screen.getByRole('button', { name: 'Refresh sample' })).toBeDisabled(); expect(screen.queryByRole('table')).toBeNull();
    });
    it('discards copied provider text after expiry or an accepted report without event scope', () => {
        const value = resource(), ui = render(<WindowsLogsPanel resource={value}/>);
        change('Provider', 'Fixture Provider A');
        ui.rerender(<WindowsLogsPanel resource={{ ...value, events: null, snapshot: null, status: 'unavailable' }}/>);
        expect(screen.getByLabelText('Provider')).toHaveValue(''); expect(document.body).not.toHaveTextContent('Fixture Provider A');
        ui.rerender(<WindowsLogsPanel resource={resource()}/>); expect(screen.getByLabelText('Provider')).toHaveValue('');
        change('Provider', 'Fixture Provider B'); const absent = resource(); delete absent.view!.events; absent.events = null;
        ui.rerender(<WindowsLogsPanel resource={absent}/>); expect(screen.getByLabelText('Provider')).toHaveValue('');
        ui.rerender(<WindowsLogsPanel resource={resource()}/>); expect(screen.getByLabelText('Provider')).toHaveValue('');
    });
    it.each(['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT])('discards local filter text on %s', event => {
        render(<WindowsLogsPanel resource={resource()}/>); change('Provider', 'Fixture');
        act(() => window.dispatchEvent(new Event(event))); expect(screen.getByLabelText('Provider')).toHaveValue('');
    });
    it('discards filters when hidden and never interprets collected provider text as markup', () => {
        const value = resource(); value.events!.channels[0].rows[0].provider = '<img src=x onerror=alert(1)>'; render(<WindowsLogsPanel resource={value}/>);
        expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeVisible(); expect(document.querySelector('img')).toBeNull();
        change('Provider', '<img'); vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden'); act(() => document.dispatchEvent(new Event('visibilitychange'))); expect(screen.getByLabelText('Provider')).toHaveValue('');
    });
    it('orders nanosecond ties deterministically without narrowing full record IDs', () => {
        const value = resource(), row = windowsEventsFixture().channels[0].rows[0];
        value.events!.channels[0].rows = [{ ...row, recordId: '9007199254740992', timestamp: '2026-10-06T10:30:00.123456788Z' }, { ...row, recordId: '9007199254740993', timestamp: '2026-10-06T10:30:00.123456789Z' }, { ...row, recordId: '18446744073709551615', timestamp: '2026-10-06T10:30:00.123456789Z' }]; value.events!.channels[1].rows = [];
        render(<WindowsLogsPanel resource={value}/>); expect(tableRows()[0]).toHaveTextContent('18446744073709551615'); expect(tableRows()[1]).toHaveTextContent('9007199254740993'); expect(tableRows()[2]).toHaveTextContent('9007199254740992');
    });
    it('localizes labels and keeps responsive table labels and keyboard controls', () => {
        setLocale('de', false); render(<WindowsLogsPanel resource={resource()}/>);
        expect(screen.getByRole('region', { name: 'Windows-Logs' })).toBeVisible(); expect(screen.getByLabelText('Ereignis-ID')).toBeVisible(); expect(screen.getByLabelText('Kanal')).toBeVisible();
        const next = screen.getByRole('button', { name: 'Weiter' }); next.focus(); expect(next).toHaveFocus(); fireEvent.click(next); expect(screen.getByText('Seite 2 von 3 · 24 passende Köpfe')).toBeVisible();
        expect(tableRows()[0].querySelectorAll('[data-label]')).toHaveLength(6); expect(tableRows()[0].lastElementChild).toHaveAttribute('data-label', 'Datensatz-ID');
    });
});
