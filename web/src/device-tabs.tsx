import { useLayoutEffect, useRef, useState } from 'react';
import { ChevronLeft, ChevronRight, type LucideIcon } from 'lucide-react';
import { t, useLocale } from './i18n';
import './device-tabs.css';

export type DeviceTab = { id: string; name: string; short?: string; count?: number; icon: LucideIcon };

function revealTab(list: HTMLElement, item: HTMLElement) {
    if (list.clientWidth <= 0) return;
    const viewport = list.getBoundingClientRect(), bounds = item.getBoundingClientRect();
    const delta = bounds.left < viewport.left ? bounds.left - viewport.left : bounds.right > viewport.right ? bounds.right - viewport.right : 0;
    // Change only this horizontal scroller, never the page or panel position.
    if (delta) list.scrollLeft = Math.max(0, Math.min(list.scrollWidth - list.clientWidth, list.scrollLeft + delta));
}

export function DeviceTabs({ tabs, selected, onSelect }: { tabs: DeviceTab[]; selected: string; onSelect: (id: string) => void }) {
    const [locale] = useLocale();
    const listRef = useRef<HTMLDivElement>(null);
    const [overflow, setOverflow] = useState({ visible: false, previous: false, next: false });
    // Metadata polling must not reset a manually scrolled strip with unchanged labels.
    const layoutKey = JSON.stringify(tabs.map(({ id, name, short, count }) => [id, name, short, count]));
    useLayoutEffect(() => {
        const list = listRef.current;
        if (!list) return;
        const measure = () => {
            const maximum = Math.max(0, list.scrollWidth - list.clientWidth);
            // Measure against the full row so controls do not keep themselves visible.
            const available = list.parentElement?.clientWidth ?? list.clientWidth;
            const next = { visible: list.scrollWidth > available + 1, previous: list.scrollLeft > 1, next: list.scrollLeft < maximum - 1 };
            setOverflow(current => current.visible === next.visible && current.previous === next.previous && current.next === next.next ? current : next);
        };
        const reveal = () => {
            const active = list.querySelector<HTMLElement>('[aria-selected="true"]');
            if (active) revealTab(list, active);
            measure();
        };
        reveal();
        list.addEventListener('scroll', measure, { passive: true });
        window.addEventListener('resize', reveal);
        const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(reveal);
        observer?.observe(list);
        return () => { list.removeEventListener('scroll', measure); window.removeEventListener('resize', reveal); observer?.disconnect(); };
    }, [selected, layoutKey]);

    const browse = (direction: number) => {
        const list = listRef.current;
        if (!list) return;
        list.scrollLeft = Math.max(0, Math.min(list.scrollWidth - list.clientWidth, list.scrollLeft + direction * Math.max(44, list.clientWidth * 0.75)));
        // Browsing reveals choices only. It never selects a panel or starts a read.
        list.dispatchEvent(new Event('scroll'));
    };
    return <div className="device-tab-navigation">
        {overflow.visible && <button type="button" className="device-tab-scroll" disabled={!overflow.previous} onClick={() => browse(-1)} aria-label={locale === 'de' ? 'Vorherige Gerätebereiche anzeigen' : 'Show previous device sections'}><ChevronLeft size={17} aria-hidden="true"/></button>}
        <div ref={listRef} className="drawer-tabs" role="tablist" aria-label={t('Gerätedaten')}>
            {tabs.map((item, index) => <button type="button" key={item.id} role="tab" aria-label={item.name} tabIndex={selected === item.id ? 0 : -1} aria-selected={selected === item.id} aria-controls={`device-${item.id}`} id={`tab-${item.id}`} onClick={() => onSelect(item.id)} onKeyDown={event => {
                const target = event.key === 'ArrowRight' ? (index + 1) % tabs.length : event.key === 'ArrowLeft' ? (index + tabs.length - 1) % tabs.length : event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : null;
                if (target !== null) {
                    event.preventDefault(); onSelect(tabs[target].id);
                    const next = document.getElementById(`tab-${tabs[target].id}`), list = listRef.current;
                    next?.focus({ preventScroll: true });
                    if (list && next) { revealTab(list, next); list.dispatchEvent(new Event('scroll')); }
                }
            }}><item.icon size={15} aria-hidden="true"/>{item.short ?? item.name}{item.count !== undefined && <span>{item.count}</span>}</button>)}
        </div>
        {overflow.visible && <button type="button" className="device-tab-scroll" disabled={!overflow.next} onClick={() => browse(1)} aria-label={locale === 'de' ? 'Weitere Gerätebereiche anzeigen' : 'Show more device sections'}><ChevronRight size={17} aria-hidden="true"/></button>}
    </div>;
}
