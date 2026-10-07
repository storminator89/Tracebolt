import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useState } from 'react';
import { Monitor } from 'lucide-react';
import { DeviceTabs, type DeviceTab } from './device-tabs';
import { setLocale } from './i18n';

const tabs: DeviceTab[] = ['Overview', 'Inventory', 'Logs', 'Details', 'Capabilities'].map(name => ({ id: name.toLowerCase(), name, icon: Monitor }));
let width = 300, navigationWidth = 300;
const rect = (left: number, right: number) => ({ left, right, top: 300, bottom: 348, x: left, y: 300, width: right - left, height: 48, toJSON() {} });
const list = () => screen.getByRole('tablist');
beforeEach(() => {
    setLocale('en', false); width = 300; navigationWidth = 300;
    vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockImplementation(function (this: HTMLElement) { return this.getAttribute('role') === 'tablist' ? width : this.classList.contains('device-tab-navigation') ? navigationWidth : 0; });
    vi.spyOn(HTMLElement.prototype, 'scrollWidth', 'get').mockImplementation(function (this: HTMLElement) { return this.getAttribute('role') === 'tablist' ? 750 : 0; });
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
        if (this.getAttribute('role') === 'tablist') return rect(100, 100 + width);
        const index = tabs.findIndex(tab => this.id === `tab-${tab.id}`);
        const left = 100 + index * 150 - (this.parentElement?.scrollLeft ?? 0);
        return rect(left, left + 150);
    });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

function Controlled({ initial = 'overview' }: { initial?: string }) {
    const [selected, select] = useState(initial);
    return <DeviceTabs tabs={tabs} selected={selected} onSelect={select}/>;
}

describe('visible and accessible device sections', () => {
    it('reveals a selected offscreen tab on mount and retains panel semantics', () => {
        render(<Controlled initial="capabilities"/>);
        expect(list().scrollLeft).toBe(450);
        const active = screen.getByRole('tab', { name: 'Capabilities' });
        expect(active).toHaveAttribute('aria-selected', 'true');
        expect(active).toHaveAttribute('aria-controls', 'device-capabilities');
        expect(screen.getByRole('button', { name: 'Show more device sections' })).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Show previous device sections' })).toBeEnabled();
    });

    it('offers discoverable 2-way browsing without changing the selected panel', () => {
        const select = vi.fn(); render(<DeviceTabs tabs={tabs} selected="overview" onSelect={select}/>);
        const previous = screen.getByRole('button', { name: 'Show previous device sections' });
        const next = screen.getByRole('button', { name: 'Show more device sections' });
        expect(previous).toBeDisabled(); fireEvent.click(next);
        expect(list().scrollLeft).toBe(225); expect(previous).toBeEnabled();
        fireEvent.click(next); expect(list().scrollLeft).toBe(450); expect(next).toBeDisabled();
        fireEvent.click(previous); expect(list().scrollLeft).toBe(225);
        expect(select).not.toHaveBeenCalled();
        expect(screen.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true');
    });

    it('reveals keyboard selections while preserving roving focus and vertical scroll', () => {
        render(<Controlled/>); const overview = screen.getByRole('tab', { name: 'Overview' });
        list().scrollTop = 17; document.documentElement.scrollTop = 251;
        overview.focus(); fireEvent.keyDown(overview, { key: 'End' });
        const last = screen.getByRole('tab', { name: 'Capabilities' });
        expect(last).toHaveFocus(); expect(last).toHaveAttribute('tabindex', '0');
        expect(overview).toHaveAttribute('tabindex', '-1'); expect(list().scrollLeft).toBe(450);
        fireEvent.keyDown(last, { key: 'ArrowRight' }); expect(overview).toHaveFocus(); expect(list().scrollLeft).toBe(0);
        fireEvent.keyDown(overview, { key: 'ArrowLeft' }); expect(last).toHaveFocus(); expect(list().scrollLeft).toBe(450);
        fireEvent.keyDown(last, { key: 'Home' }); expect(overview).toHaveFocus(); expect(list().scrollLeft).toBe(0);
        expect(list().scrollTop).toBe(17); expect(document.documentElement.scrollTop).toBe(251);
    });

    it('keeps the active tab visible when a desktop view becomes narrow', () => {
        width = 1000; navigationWidth = 1000; render(<Controlled initial="capabilities"/>);
        expect(screen.queryByRole('button', { name: 'Show more device sections' })).toBeNull();
        width = 300; navigationWidth = 300; act(() => window.dispatchEvent(new Event('resize')));
        expect(list().scrollLeft).toBe(450);
        expect(screen.getByRole('button', { name: 'Show previous device sections' })).toBeEnabled();
    });

    it('removes controls once tabs fit the full row, then stays stable after they disappear', () => {
        render(<Controlled/>);
        expect(screen.getByRole('button', { name: 'Show more device sections' })).toBeEnabled();
        // The full row fits all 750px of tabs, although visible controls still reserve 100px.
        navigationWidth = 800; width = 700;
        act(() => window.dispatchEvent(new Event('resize')));
        expect(screen.queryByRole('button', { name: 'Show more device sections' })).toBeNull();
        // Removing controls expands the strip. A second observation must not restore them.
        width = navigationWidth;
        act(() => window.dispatchEvent(new Event('resize')));
        expect(screen.queryByRole('button', { name: 'Show previous device sections' })).toBeNull();
        expect(screen.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true');
    });

    it('does not reset manual browsing during unchanged metadata rerenders', () => {
        const select = vi.fn(); const mounted = render(<DeviceTabs tabs={tabs} selected="overview" onSelect={select}/>);
        fireEvent.click(screen.getByRole('button', { name: 'Show more device sections' }));
        mounted.rerender(<DeviceTabs tabs={tabs.map(tab => ({ ...tab }))} selected="overview" onSelect={select}/>);
        expect(list().scrollLeft).toBe(225); expect(select).not.toHaveBeenCalled();
        fireEvent.keyDown(screen.getByRole('tab', { name: 'Overview' }), { key: 'Home' });
        expect(list().scrollLeft).toBe(0);
    });

    it('localizes overflow controls and removes observers on unmount', () => {
        const disconnect = vi.fn(), observe = vi.fn();
        vi.stubGlobal('ResizeObserver', class { observe = observe; disconnect = disconnect; });
        try {
            setLocale('de', false); const mounted = render(<Controlled/>);
            expect(screen.getByRole('button', { name: 'Weitere Gerätebereiche anzeigen' })).toBeEnabled();
            expect(screen.getByRole('button', { name: 'Vorherige Gerätebereiche anzeigen' })).toBeDisabled();
            expect(observe).toHaveBeenCalledWith(list()); mounted.unmount(); expect(disconnect).toHaveBeenCalledOnce();
        } finally { vi.unstubAllGlobals(); }
    });
});
