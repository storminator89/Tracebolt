import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { WindowsEventsPanel } from './windows-events';
import { validWindowsEvents, type WindowsEvents } from './windows-events-types';
import { validWindowsInventoryView } from './windows-inventory-types';
import { windowsDeviceId, windowsNow, windowsView } from './windows-inventory-fixture';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import { setLocale } from './i18n';
beforeEach(() => setLocale('en', false));
afterEach(cleanup);
function events(): WindowsEvents { return { schemaVersion: 'tracebolt.windows-event-metadata.v1', scope: 'windows-application-system-event-headers-v1', grantId: 'e'.repeat(32), generationId: `sample_${'a'.repeat(32)}`, collectedAt: '2026-10-07T12:00:02Z', channels: [{ channel: 'Application', quality: 'observed', reason: '', complete: true, truncated: false, observedCount: 1, rows: [{ recordId: '18446744073709551615', eventId: 42, level: 2, provider: 'Invented Provider', timestamp: '2026-10-06T10:00:00Z' }] }, { channel: 'System', quality: 'denied', reason: 'windows_events_access_denied', complete: false, truncated: false, observedCount: 0, rows: [] }] }; }
function resource(event: WindowsEvents | null = events()): WindowsInventoryResource { const view = windowsView(); if(event)view.events=event; return { updates: null, updatesStale: false, updatesExpired: false, updatesAhead: false, serviceStartup: null, serviceStartupStale: false, elapsedMS: 0, network: null, networkStale: false, networkExpired: false, adapterContext: null, adapterContextStale: false, adapterContextExpired: false, patchContext: null, patchContextStale: false, patchContextExpired: false, patchContextAhead: false, storageIO: null, storageIOStale: false, storageIOExpired: false, storageIOAhead: false, storageContext: null, storageContextStale: false, storageContextExpired: false, storageContextAhead: false, resourceContext: null, resourceContextStale: false, resourceContextExpired: false, resourceContextAhead: false, hardwareContext: null, hardwareContextStale: false, hardwareContextExpired: false, hardwareContextAhead: false, sessionContext: null, sessionContextStale: false, sessionContextExpired: false, sessionContextAhead: false, securityCoverage: null, securityCoverageStale: false, securityCoverageExpired: false, securityCoverageAhead: false, securityPosture: null, securityPostureStale: false, securityPostureExpired: false, securityPostureAhead: false, processMetrics: null, processMetricsStale: false, volumes: null, volumesStale: false, events: event, eventsStale: false, view, snapshot: view.snapshot, status: 'fresh', loading: false, error: null, refresh: vi.fn() }; }
describe('Windows event header boundary', () => {
    it('accepts old inventory views and exact event metadata with uint64 record strings', () => { const view=windowsView(); expect(validWindowsInventoryView(view,windowsDeviceId)).toBe(true); view.events=events(); expect(validWindowsInventoryView(view,windowsDeviceId)).toBe(true); });
    it('rejects content, Security, mismatched scope, unsafe IDs and quality lies', () => {
        const mutations: ((s: WindowsEvents) => void)[] = [s=>Object.assign(s.channels[0].rows[0],{message:'private'}),s=>Object.assign(s.channels[0],{channel:'Security'}),s=>Object.assign(s,{scope:'windows-inventory-v1'}),s=>{s.channels[0].rows[0].recordId='18446744073709551616';},s=>Object.assign(s.channels[1],{quality:'observed'}),s=>{s.channels[0].rows[0].provider='bad\n';},s=>{s.channels[0].rows[0].level=256;},s=>{s.channels[0].rows[0].provider='a'.repeat(257);},s=>{s.channels[0].observedCount=2;}];
        for(const mutate of mutations){const e=events();mutate(e);expect(validWindowsEvents(e,events().generationId,windowsNow)).toBe(false);}
        const v=windowsView();Object.assign(v,{events:null});expect(validWindowsInventoryView(v,windowsDeviceId)).toBe(false);
    });
    it('shows scoped warning counts and denial without claiming healthy', () => { render(<WindowsEventsPanel resource={resource()}/>); expect(screen.getByText('1 error/warning headers in 1 displayed events.')).toBeTruthy();expect(screen.getByText('Access denied')).toBeTruthy(); expect(screen.queryByText(/healthy/i)).toBeNull();fireEvent.click(screen.getByText('Application · 1 captured event header'));expect(screen.getByText('Invented Provider')).toBeTruthy(); });
    it('never converts unconfigured or empty data to healthy zero', () => { const r=resource(null); const {rerender}=render(<WindowsEventsPanel resource={r}/>);expect(screen.getByRole('status').textContent).toContain('Health unknown');const e=events();e.channels[0].rows=[];e.channels[0].observedCount=0;rerender(<WindowsEventsPanel resource={resource(e)}/>);expect(screen.getByText('No event headers returned. Health unknown.')).toBeTruthy(); });
    it('marks stale samples and removes private data after session loss', () => { const r=resource();r.eventsStale=true;const {rerender}=render(<WindowsEventsPanel resource={r}/>);expect(screen.getByRole('status').textContent).toContain('Stale');rerender(<WindowsEventsPanel resource={{...resource(null),view:null,snapshot:null,error:'session',status:null}}/>);expect(screen.queryByText('Invented Provider')).toBeNull();expect(screen.getByRole('button',{name:'Refresh events'}).hasAttribute('disabled')).toBe(true); });
});


describe('Named event-channel disclosures', () => {
    it.each(['en', 'de'] as const)('distinguishes channel controls and table names in %s', locale => {
        setLocale(locale, false);
        const data = events();
        data.channels[1] = { ...data.channels[0], channel: 'System', rows: [{ ...data.channels[0].rows[0], provider: 'System fixture' }] };
        const r = resource(data), original = JSON.stringify(data);
        render(<WindowsEventsPanel resource={r}/>);
        const summaries = Array.from(document.querySelectorAll<HTMLDetailsElement>('.windows-event-channel-details')).map(detail => detail.querySelector('summary')!);
        expect(summaries[0]).toHaveAccessibleName(locale === 'de' ? 'Application · 1 erfasster Ereigniskopf' : 'Application · 1 captured event header');
        expect(summaries[1]).toHaveAccessibleName(locale === 'de' ? 'System · 1 erfasster Ereigniskopf' : 'System · 1 captured event header');
        summaries[1].focus(); fireEvent.click(summaries[1]); expect(summaries[1]).toHaveFocus();
        const table = screen.getByRole('table', { name: locale === 'de' ? 'System · Erfasste Ereignisköpfe' : 'System · Captured event headers' });
        expect(within(table).getByText('System fixture')).toBeVisible();
        expect(screen.getByText('Invented Provider')).not.toBeVisible();
        expect(document.querySelectorAll<HTMLDetailsElement>('.windows-event-channel-details')[0].open).toBe(false);
        expect(r.refresh).not.toHaveBeenCalled(); expect(JSON.stringify(data)).toBe(original);
    });
    it.each(['en', 'de'] as const)('pluralizes the retained header count in %s', locale => {
        setLocale(locale, false); const data = events();
        data.channels[0].rows.push({ ...data.channels[0].rows[0], recordId: '2' }); data.channels[0].observedCount = 2;
        render(<WindowsEventsPanel resource={resource(data)}/>);
        expect(screen.getByText(locale === 'de' ? 'Application · 2 erfasste Ereignisköpfe' : 'Application · 2 captured event headers')).toBeVisible();
    });
    it('uses retained row counts, not observed counts, for bounded channels', () => {
        const data = events(); Object.assign(data.channels[0], { quality: 'bounded', complete: false, truncated: true, observedCount: 24 });
        render(<WindowsEventsPanel resource={resource(data)}/>);
        expect(screen.getByText('Application · 1 captured event header')).toBeVisible();
        expect(screen.getByText('Bounded sample; more events are omitted.')).toBeVisible();
        expect(document.querySelectorAll('.windows-event-channel-details')).toHaveLength(1);
    });
});
