import { useId, useMemo, useState } from 'react';
import type { WindowsServiceHealthCopy } from './windows-service-health-copy';

export interface WindowsServiceChoice { name: string; displayName: string }
/** Reported names are opaque, exact selectors. No normalization, manual query or native read. */
export function WindowsServiceHealthPicker({ choices, selected, disabled, onChange, c }: { choices: readonly WindowsServiceChoice[]; selected: readonly string[]; disabled: boolean; onChange: (names: string[]) => void; c: WindowsServiceHealthCopy }) {
    const id = useId(), [search, setSearch] = useState('');
    // Defensive duplicate handling: an ambiguous exact name is never a chooser option.
    const unique = useMemo(() => {
        const counts = new Map<string, number>();
        for (const row of choices) counts.set(row.name, (counts.get(row.name) ?? 0) + 1);
        return choices.filter(row => counts.get(row.name) === 1);
    }, [choices]);
    const query = search.toLocaleLowerCase(), options = unique.filter(row => row.name.toLocaleLowerCase().includes(query) || row.displayName.toLocaleLowerCase().includes(query));
    const capped = selected.length >= 8;
    const toggle = (name: string) => {
        if (disabled) return;
        if (selected.includes(name)) onChange(selected.filter(value => value !== name));
        else if (!capped && unique.some(row => row.name === name)) onChange([...selected, name]);
    };
    return <div className="windows-service-picker">
        <p role="status">{selected.length} {c.count}{capped && <> · {c.maximum}</>}</p>
        {selected.length ? <ul className="windows-service-selections" aria-label={c.selected}>{selected.map(name => {
            const choice = unique.find(row => row.name === name);
            return <li key={name}><span>{choice?.displayName ? <>{choice.displayName}<small>{c.name}: <code>{name}</code></small></> : <code>{name}</code>}{!choice && <small>{c.unavailableSelection}</small>}</span><button type="button" className="text-button" disabled={disabled} aria-label={`${c.remove}: ${name}`} onClick={() => toggle(name)}>×</button></li>;
        })}</ul> : <p>{c.noSelection}</p>}
        <fieldset><legend>{c.choose}</legend>
            <label htmlFor={`${id}-search`}>{c.search}</label><input id={`${id}-search`} type="search" value={search} disabled={disabled} maxLength={256} autoComplete="off" spellCheck={false} onChange={event => setSearch(event.target.value)} onKeyDown={event => { if (event.key === 'Enter') { event.preventDefault(); event.stopPropagation(); } }}/>
            {options.length ? <ul className="windows-service-options" aria-label={c.choices}>{options.map(row => <li key={row.name}><label><input type="checkbox" checked={selected.includes(row.name)} disabled={disabled || capped && !selected.includes(row.name)} onChange={() => toggle(row.name)}/><span>{row.displayName || row.name}<small>{c.name}: <code>{row.name}</code></small></span></label></li>)}</ul> : <p>{unique.length ? c.noMatches : c.noChoices}</p>}
        </fieldset><p>{c.sourceLimit}</p>
    </div>;
}
