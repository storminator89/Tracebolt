import { useEffect, useId, useRef, useState } from 'react';
import { inventoryAge } from './complete-packages-types';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import { useWindowsFullServices } from './windows-full-services-resource';
import type { WindowsServiceHealthCopy } from './windows-service-health-copy';
import { completeServicePickerCopy } from './windows-service-health-complete-copy';
import { completeServiceHealthSource, sameWindowsServiceHealthSource, windowsServiceHealthSourceFresh } from './windows-service-health-complete-types';
import type { WindowsServiceHealthSource } from './windows-service-health-complete-types';
import { compareWindowsServiceNames, sameWindowsServiceNames } from './windows-service-health-types';

export interface CompleteServiceSelectionEvidence { source: WindowsServiceHealthSource; names: string[] }
type Reviewed = { source: WindowsServiceHealthSource; choices: { name: string; displayName: string }[] };
/** At most eight selected identities survive paging. Page rows never accumulate;
 * one exact immutable generation must back every newly selected identity. */
export function WindowsServiceHealthCompletePicker({ deviceId, sessionKey, enabled, disabled, selected, onChange, onEvidence, c }: { deviceId: string; sessionKey: string | null; enabled: boolean; disabled: boolean; selected: readonly string[]; onChange: (names: string[]) => void; onEvidence: (value: CompleteServiceSelectionEvidence | null) => void; c: WindowsServiceHealthCopy }) {
    const [locale] = useLocale(), copy = completeServicePickerCopy[locale], id = useId();
    const resource = useWindowsFullServices(deviceId, enabled, sessionKey), { page } = resource;
    const [reviewed, setReviewed] = useState<Reviewed | null>(null), [, tick] = useState(0);
    const anchor = useRef<{ page: typeof page; mono: number; wall: number } | null>(null), callback = useRef(onEvidence);
    callback.current = onEvidence;
    if (page && anchor.current?.page !== page) anchor.current = { page, mono: performance.now(), wall: Date.now() };
    const elapsed = anchor.current ? performance.now() - anchor.current.mono : Infinity;
    const clockValid = anchor.current && Number.isFinite(elapsed) && elapsed >= 0 && Math.abs(Date.now() - anchor.current.wall - elapsed) <= 1500;
    const source = page?.complete ? completeServiceHealthSource(page.complete) : null;
    const latestComplete = page?.latestAttempt?.status === 'complete' && page.latestAttempt.sequence === source?.sequence;
    const fresh = !!(enabled && latestComplete && page && source && clockValid && sessionKey && inventoryAge(sessionKey, page.serverNow) > elapsed && windowsServiceHealthSourceFresh(source, page.serverNow, elapsed));
    const sourceKey = source ? JSON.stringify(source) : '', namesKey = JSON.stringify(selected);
    useEffect(() => { const timer = window.setInterval(() => tick(n => n + 1), 250); return () => window.clearInterval(timer); }, []);
    useEffect(() => {
        if (resource.loading || !page && resource.view) { callback.current(null); return; }
        if (!fresh || !page || !source) { setReviewed(null); callback.current(null); return; }
        const prior = reviewed && sameWindowsServiceHealthSource(reviewed.source, source) ? reviewed.choices : [];
        const choices = selected.flatMap(name => { const row = page.rows.find(r => r.name === name) ?? prior.find(r => r.name === name); return row ? [{ name, displayName: row.displayName ?? '' }] : []; });
        if (!reviewed || !sameWindowsServiceHealthSource(reviewed.source, source) || !sameWindowsServiceNames(choices.map(r => r.name), reviewed.choices.map(r => r.name))) setReviewed({ source, choices });
        callback.current({ source, names: choices.map(r => r.name) });
        // Callback identity does not reset the reviewed generation when the parent renders.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [page, resource.view, resource.loading, resource.error, fresh, sourceKey, namesKey]);
    useEffect(() => () => { callback.current(null); }, []);
    const options = fresh ? page?.rows ?? [] : [], choices = fresh && reviewed && sameWindowsServiceHealthSource(reviewed.source, source) ? reviewed.choices : [];
    const change = (name: string) => { if (disabled) return; if (selected.includes(name)) onChange(selected.filter(n => n !== name)); else if (fresh && selected.length < 8 && options.some(row => row.name === name)) onChange([...selected, name].sort(compareWindowsServiceNames)); };
    return <div className="windows-service-picker windows-service-complete-picker">
        <p role="status">{selected.length} {c.count}{selected.length >= 8 && <> · {c.maximum}</>}</p>
        {selected.length ? <ul className="windows-service-selections" aria-label={c.selected}>{selected.map(name => <li key={name}><span>{choices.find(r => r.name === name)?.displayName || name}<small>{c.name}: <code>{name}</code></small>{!choices.some(r => r.name === name) && <small>{c.unavailableSelection}</small>}</span><button type="button" className="text-button" disabled={disabled} aria-label={`${c.remove}: ${name}`} onClick={() => change(name)}>×</button></li>)}</ul> : <p>{c.noSelection}</p>}
        <fieldset><legend>{c.choose}</legend>
            <div className="windows-capacity-actions"><label htmlFor={`${id}-search`}>{c.search}<input id={`${id}-search`} type="search" autoComplete="off" spellCheck={false} maxLength={256} value={resource.controls.search} disabled={!enabled || resource.loading} onChange={event => resource.changeSearch(event.target.value)} onKeyDown={event => { if (event.key === 'Enter') { event.preventDefault(); resource.apply(); } }}/></label><button type="button" className="button small" disabled={!enabled || resource.loading || disabled} onClick={resource.apply}>{copy.apply}</button><button type="button" className="text-button" disabled={!enabled || resource.loading || resource.error === 'session' || disabled} onClick={() => { setReviewed(null); callback.current(null); resource.restart(); }}>{copy.restart}</button></div>
            {resource.loading && <p role="status">{c.refreshing}</p>}
            {resource.error && <p role="status">{copy.changed}</p>}
            {page && source && !fresh && <p role="status">{latestComplete ? copy.stale : copy.unavailable}</p>}
            {!resource.loading && !page && !resource.error && <p>{copy.unavailable}</p>}
            {fresh && page && source && <><p>{source.rowCount} {copy.total} · {page.matchingCount} {copy.matching} · {page.rows.length ? page.offset + 1 : 0}–{page.offset + page.rows.length}</p>
                {options.length ? <ul className="windows-service-options" aria-label={c.choices}>{options.map(row => <li key={row.name}><label><input type="checkbox" checked={selected.includes(row.name)} disabled={disabled || selected.length >= 8 && !selected.includes(row.name)} onChange={() => change(row.name)}/><span>{row.displayName || row.name}<small>{c.name}: <code>{row.name}</code></small></span></label></li>)}</ul> : <p>{c.noMatches}</p>}
                <nav className="windows-inventory-table-pagination"><button type="button" className="button small" disabled={disabled || page.offset === 0} onClick={resource.previous}>{copy.previous}</button><button type="button" className="button small" disabled={disabled || !page.nextCursor} onClick={resource.next}>{copy.next}</button></nav>
                <details><summary>{copy.source}</summary><dl className="windows-capacity-times"><div><dt>{copy.captured}</dt><dd><time dateTime={source.capturedAt}>{fullDate(source.capturedAt)}</time></dd></div><div><dt>{copy.received}</dt><dd><time dateTime={source.receivedAt}>{fullDate(source.receivedAt)}</time></dd></div><div><dt>{copy.generation}</dt><dd><code>{source.generationId}</code></dd></div><div><dt>{copy.grant}</dt><dd><code>{source.grantId}</code> · {source.grantRevision}</dd></div><div><dt>{copy.expiry}</dt><dd><time dateTime={source.expiresAt}>{fullDate(source.expiresAt)}</time></dd></div></dl></details>
            </>}
        </fieldset><p>{c.sourceLimit}</p>
    </div>;
}
