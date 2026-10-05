import { useId } from 'react';
import { Database, Download, RefreshCw, TriangleAlert } from 'lucide-react';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import { useLinuxCVE } from './linux-cve-resource';
import { LINUX_CVE_FEED_TTL_MS, LINUX_CVE_INVENTORY_TTL_MS, linuxCVEAge } from './linux-cve-types';
import type { LinuxCVEFeed, LinuxCVEFinding } from './linux-cve-types';
import { linuxCVECopy as copy, linuxCVEReasons } from './linux-cve-copy';
import './linux-cve.css';

function date(value: string, locale: 'en' | 'de'): string { return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)); }
function age(value: number, labels: typeof copy.en | typeof copy.de): string {
    if (!Number.isFinite(value) || value < 0) return labels.unknown;
    if (value < 60000) return `${Math.floor(value / 1000)} ${labels.ageSeconds}`;
    if (value < 3600000) return `${Math.floor(value / 60000)} ${labels.ageMinutes}`;
    if (value < 86400000) return `${Math.floor(value / 3600000)} ${labels.ageHours}`;
    return `${Math.floor(value / 86400000)} ${labels.ageDays}`;
}
function publisher(feed: LinuxCVEFeed) { return feed.provider === 'debian-security-tracker' ? 'Debian Security Tracker' : 'Ubuntu OSV'; }
export function groupLinuxCVEWarnings(rows: LinuxCVEFinding[]): LinuxCVEFinding[][] {
    const groups = new Map<string, LinuxCVEFinding[]>();
    for (const row of rows) { const key = `${row.cveId}:${row.sourcePackage}`, group = groups.get(key) ?? []; group.push(row); groups.set(key, group); }
    return [...groups.values()];
}
/** Mounted by the selected device's Security or CVE tab, never both. */
export function LinuxCVEPanel({ deviceId, sessionKey }: { deviceId: string; sessionKey?: string | number }) {
    const operator = useOperator(), [locale] = useLocale();
    if (!operator || operator.mode !== 'lan' || !operator.authenticated) return <p>{copy[locale].access}</p>;
    return <LinuxCVESession key={`${deviceId}:${String(sessionKey ?? operator.expiresAt ?? '')}`} deviceId={deviceId}/>;
}
function LinuxCVESession({ deviceId }: { deviceId: string }) {
    const [locale] = useLocale(), labels = copy[locale], resource = useLinuxCVE(deviceId), heading = useId(), fileId = useId();
    const view = resource.view, report = view?.report, activeReport = view?.status === 'evaluated' && report;
    const disabled = resource.loading || resource.writing !== null || resource.error === 'session';
    const cacheUncertain = view?.feeds.failureReason === 'cache_commit_uncertain', writeDisabled = disabled || !view || cacheUncertain;
    const feedAge = report?.feed && view ? linuxCVEAge(view.serverNow, report.feed.fetchedAt) + resource.elapsed : Infinity;
    const inventoryAge = view?.inventory ? linuxCVEAge(view.serverNow, view.inventory.collectedAt) + resource.elapsed : Infinity;
    const stale = activeReport && (report.status === 'stale' || feedAge >= LINUX_CVE_FEED_TTL_MS || inventoryAge >= LINUX_CVE_INVENTORY_TTL_MS);
    const warnings = activeReport ? groupLinuxCVEWarnings(report.findings) : null;
    return <section className="linux-cve" aria-labelledby={heading} aria-busy={resource.loading || resource.writing !== null}>
        <header className="linux-cve-heading"><div><h2 id={heading}>{labels.title}</h2><p>{labels.subtitle}</p></div><button type="button" className="button small" disabled={disabled} onClick={() => void resource.load()}><RefreshCw size={14}/>{labels.refresh}</button></header>
        <div className="linux-cve-update"><button type="button" className="button primary" disabled={writeDisabled} onClick={() => void resource.sync()}><Download size={15}/>{labels.sync}</button><p>{labels.syncNote}</p></div>
        {(resource.loading || resource.writing) && <p role="status" className="linux-cve-notice">{resource.writing === 'sync' ? labels.syncing : resource.writing === 'import' ? labels.importing : resource.recovering ? labels.recovering : labels.loading}</p>}
        {resource.error && <p role="alert" className="linux-cve-notice caution"><TriangleAlert size={16}/>{labels[resource.error]}</p>}
        {resource.notice && !(resource.notice === 'uncertain' && resource.error === 'uncertain') && <p role="status" className="linux-cve-notice">{labels[resource.notice]}</p>}
        {view && <>
            <div className="linux-cve-summary"><div className="linux-cve-count"><strong>{warnings === null ? '—' : new Intl.NumberFormat(locale).format(warnings.length)}</strong><span>{warnings === null ? labels.unavailableCount : labels.warnings}</span></div><div>
                <p className="linux-cve-state">{labels[view.status]}</p>
                {activeReport && <p>{new Intl.NumberFormat(locale).format(report.findings.length)} {labels.matches}</p>}
                {activeReport && report.unassessedRecordCount > 0 && <p className="linux-cve-warning">{report.truncated && `${labels.atLeast} `}{new Intl.NumberFormat(locale).format(report.unassessedRecordCount)} {report.unassessedRecordCount === 1 ? labels.unassessedSingle : labels.unassessed}</p>}
                <p>{stale ? labels.stale : activeReport ? labels.partial : labels.subtitle}</p>{report?.truncated && <p className="linux-cve-warning">{labels.truncated}</p>}
            </div></div>
            {view.feeds.outcome === 'failed' && <p className="linux-cve-notice caution">{cacheUncertain ? labels.cacheUncertain : labels.feedFailed}</p>}
            <dl className="linux-cve-times"><div><dt>{labels.inventoryRows}</dt><dd>{view.inventory ? new Intl.NumberFormat(locale).format(view.inventory.rowCount) : labels.unknown}</dd></div><div><dt>{labels.assessed}</dt><dd>{report ? <time dateTime={report.assessedAt}>{date(report.assessedAt, locale)}</time> : labels.unknown}</dd></div><div><dt>{labels.inventoryAge}</dt><dd>{age(inventoryAge, labels)}{view.inventory && inventoryAge >= LINUX_CVE_INVENTORY_TTL_MS && ` · ${labels.staleLabel}`}</dd></div><div><dt>{labels.feedAge}</dt><dd>{age(feedAge, labels)}{report?.feed && feedAge >= LINUX_CVE_FEED_TTL_MS && ` · ${labels.staleLabel}`}</dd></div></dl>
            {warnings && (warnings.length ? <ol className="linux-cve-list">{warnings.map(group => {
                const first = group[0];
                return <li key={`${first.cveId}:${first.sourcePackage}`}><article aria-label={`${first.cveId}: ${first.sourcePackage}`}><h3><a href={first.advisoryUrl} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{first.cveId}</a><span>{first.sourcePackage}</span></h3>
                    {group.map(row => <dl className="linux-cve-versions" key={row.installedSourceVersion}><div><dt>{labels.installed}</dt><dd>{row.installedSourceVersion}</dd></div><div><dt>{labels.fixed}</dt><dd>{row.publishedFixedVersion}</dd></div></dl>)}
                    <details><summary>{labels.binaries} ({group.reduce((sum, row) => sum + row.binaries.length, 0)}{group.some(row => row.binariesTruncated) ? '+' : ''})</summary>{group.map(row => <div key={row.installedSourceVersion}>{group.length > 1 && <p>{labels.installed}: {row.installedSourceVersion}</p>}<ul className="linux-cve-binaries">{row.binaries.map(binary => <li key={`${binary.name}:${binary.architecture}`}><span>{binary.name}:{binary.architecture}</span><span>{binary.version}</span></li>)}</ul></div>)}{group.some(row => row.binariesTruncated) && <p>{labels.binariesOmitted}</p>}</details>
                </article></li>;
            })}</ol> : <p className="linux-cve-notice">{labels.empty}</p>)}
            <p className="linux-cve-caveat">{labels.caveat}</p>
            <details className="linux-cve-details"><summary><Database size={15}/>{labels.details}</summary><p>{labels.coverage}</p><p>{labels.scope}</p><p>{labels.feedWindow}</p>
                {view.feeds.snapshots.length === 0 && <p>{labels.noFeed}</p>}
                {view.feeds.snapshots.map(feed => <section key={feed.provider} className="linux-cve-feed"><h3><a href={feed.sourceUrl} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{publisher(feed)}</a></h3>{feed.provider === 'canonical-ubuntu-osv' && <p>{labels.attribution} · <a href="https://creativecommons.org/licenses/by-sa/4.0/" target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{feed.license}</a></p>}<p>{feed.trust === 'https_origin_only' ? labels.syncTrust : labels.importedTrust}</p><dl className="linux-cve-facts"><div><dt>{labels.fetched}</dt><dd><time dateTime={feed.fetchedAt}>{date(feed.fetchedAt, locale)}</time> · {age(linuxCVEAge(view.serverNow, feed.fetchedAt) + resource.elapsed, labels)}</dd></div><div><dt>{labels.validated}</dt><dd><time dateTime={feed.validatedAt}>{date(feed.validatedAt, locale)}</time></dd></div><div><dt>{labels.records}</dt><dd>{new Intl.NumberFormat(locale).format(feed.recordCount)}</dd></div><div><dt>{labels.digest}</dt><dd>{feed.sha256}</dd></div></dl></section>)}
                {report && <><dl className="linux-cve-facts"><div><dt>{labels.checkedSources}</dt><dd>{new Intl.NumberFormat(locale).format(report.evaluatedSourceCount)}</dd></div><div><dt>{labels.skipped}</dt><dd>{new Intl.NumberFormat(locale).format(report.skippedPackageCount)}</dd></div></dl><ul aria-label={labels.reasons} className="linux-cve-reasons">{report.reasonCodes.map(code => <li key={code}>{linuxCVEReasons[locale][code] ?? code}</li>)}</ul></>}
                {view.inventory && <dl className="linux-cve-facts"><div><dt>{labels.generation}</dt><dd>{view.inventory.generationId}</dd></div></dl>}
            </details>
            <details className="linux-cve-details" onToggle={event => { if (!event.currentTarget.open) resource.clearFile(); }}><summary>{labels.importDetails}</summary><p>{labels.importNote}</p><div className="linux-cve-file"><label htmlFor={fileId}>{labels.choose}</label><input id={fileId} type="file" accept="application/json,.json" disabled={writeDisabled} onChange={event => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ''; resource.selectFile(file); }}/>{resource.selectedBytes !== null && <span>{labels.selected}: {new Intl.NumberFormat(locale).format(resource.selectedBytes)} B</span>}<button type="button" className="button small" disabled={writeDisabled || resource.selectedBytes === null} onClick={() => void resource.importSelected()}>{labels.import}</button>{resource.selectedBytes !== null && <button type="button" className="button small" onClick={resource.clearFile}>{labels.clearFile}</button>}</div></details>
        </>}
    </section>;
}
