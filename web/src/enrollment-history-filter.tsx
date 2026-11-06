import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { Archive, Clock3, KeyRound, ListFilter, Search, X } from 'lucide-react';
import { AUTH_REQUIRED_EVENT } from './api';
import { terminal, type EnrollmentSnapshot } from './enrollment-types';
import { t, useLocale } from './i18n';
import './enrollment-history-filter.css';

type Phase = 'all' | 'setup' | 'activated' | 'ended';
const phases = ['all', 'setup', 'activated', 'ended'] as const;
const icons = { all: ListFilter, setup: Clock3, activated: KeyRound, ended: Archive };
const copy = {
 en: { title: 'Filter invitation history', search: 'Search invitation IDs', placeholder: 'Invitation ID', phase: 'Stored phase', all: 'All shown', setup: 'Before activation', activated: 'Activated', ended: 'Ended', clear: 'Clear filters', scope: 'Stored phases, not current validity. “Show ended” controls whether ended records are included.', empty: 'No shown invitations match these filters.', count: (matched: number, total: number) => `${matched} of ${total} shown invitations` },
 de: { title: 'Einladungsverlauf filtern', search: 'Einladungs-IDs durchsuchen', placeholder: 'Einladungs-ID', phase: 'Gespeicherte Phase', all: 'Alle angezeigten', setup: 'Vor Aktivierung', activated: 'Aktiviert', ended: 'Beendet', clear: 'Filter leeren', scope: 'Gespeicherte Phasen, nicht die aktuelle Gültigkeit. „Beendete anzeigen“ bestimmt, ob beendete Einträge enthalten sind.', empty: 'Keine angezeigte Einladung passt zu diesen Filtern.', count: (matched: number, total: number) => `${matched} von ${total} angezeigten Einladungen` },
};

/** Filters only the owner's already selected history rows. Never used for
 * admission, current validity, capacity, attention counts or action decisions. */
export function EnrollmentHistoryFilter({ items, reviewOpen = false, children }: { items: readonly EnrollmentSnapshot[]; reviewOpen?: boolean; children: (items: readonly EnrollmentSnapshot[]) => ReactNode }) {
 const [locale] = useLocale(), c = copy[locale], id = useId();
 const [query, setQuery] = useState(''), [phase, setPhase] = useState<Phase>('all');
 const search = useRef<HTMLInputElement>(null);
 const reviewing = useRef(reviewOpen);
 const reset = () => { setQuery(''); setPhase('all'); };
 useEffect(() => {
  const closed = reviewing.current && !reviewOpen; reviewing.current = reviewOpen;
  // The existing dialog restores the original row when it still exists. A
  // newer stored phase can remove that row from this filter while reviewing.
  if (closed && document.activeElement === document.body && document.visibilityState === 'visible' && document.hasFocus()) search.current?.focus();
 }, [reviewOpen]);
 useEffect(() => {
  const clear = () => { setQuery(''); setPhase('all'); };
  const visibility = () => { if (document.visibilityState === 'hidden') clear(); };
  const events = ['blur', 'pagehide', 'hashchange', AUTH_REQUIRED_EVENT];
  events.forEach(event => window.addEventListener(event, clear)); document.addEventListener('visibilitychange', visibility);
  return () => { events.forEach(event => window.removeEventListener(event, clear)); document.removeEventListener('visibilitychange', visibility); };
 }, []);
 const text = query.trim().toLowerCase();
 const filtered = items.filter(item => {
  const matchesPhase = phase === 'all' || phase === 'activated' && item.state === 'activated' || phase === 'ended' && terminal(item.state) || phase === 'setup' && item.state !== 'activated' && !terminal(item.state);
  return matchesPhase && (!text || item.invitationID.toLowerCase().includes(text));
 });
 return <>
  <section className="enrollment-history-filter" aria-label={c.title}>
   <div className="enrollment-history-search">
    <label htmlFor={`${id}-search`}><Search size={15} aria-hidden="true"/>{c.search}</label>
    <input ref={search} id={`${id}-search`} type="search" placeholder={c.placeholder} autoComplete="off" spellCheck={false} maxLength={128} value={query} aria-describedby={`${id}-scope`} onChange={event => setQuery(event.target.value.slice(0, 128))}/>
    <button type="button" className="button" disabled={!query && phase === 'all'} onClick={() => { reset(); search.current?.focus(); }}><X size={14} aria-hidden="true"/>{c.clear}</button>
   </div>
   <div className="enrollment-history-phases" role="group" aria-label={c.phase}>{phases.map(value => {
    const Icon = icons[value];
    return <button type="button" key={value} className="button" aria-pressed={phase === value} onClick={() => setPhase(value)}><Icon size={14} aria-hidden="true"/>{c[value]}</button>;
   })}</div>
   <p id={`${id}-scope`} className="enrollment-history-scope">{c.scope}</p>
   <p className="enrollment-history-count" aria-live="polite" aria-atomic="true">{c.count(filtered.length, items.length)}</p>
  </section>
  {filtered.length ? children(filtered) : <p className="enrollment-empty">{items.length ? c.empty : t('Keine laufenden Einladungen.')}</p>}
 </>;
}
