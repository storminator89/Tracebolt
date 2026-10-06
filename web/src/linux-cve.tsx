import { useId } from 'react';
import { Database, Download, RefreshCw, TriangleAlert } from 'lucide-react';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import { useLinuxCVE } from './linux-cve-resource';
import { LINUX_CVE_FEED_TTL_MS, LINUX_CVE_INVENTORY_TTL_MS, linuxCVEAge } from './linux-cve-types';
import type { LinuxCVEFeed, LinuxCVEFinding, LinuxCVEResult } from './linux-cve-types';
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
function LinuxCVECoverageDetails({ report, locale }: { report: LinuxCVEResult; locale: 'en' | 'de' }) {
    const labels = copy[locale], coverage = report.coverage, format = new Intl.NumberFormat(locale).format;
    const shownWarnings = groupLinuxCVEWarnings(report.findings).length;
    const omitted = coverage.matchedFindingCount > report.findings.length || report.findings.some(row => row.binariesTruncated);
    return <>
        <dl className="linux-cve-facts">
            <div><dt>{labels.processing}</dt><dd>{report.status === 'unavailable' ? labels.unavailable : coverage.evaluationComplete ? labels.processingComplete : labels.processingIncomplete}</dd></div>
            <div><dt>{labels.checks}</dt><dd>{format(coverage.completedCheckCount)} / {format(coverage.totalCheckCount)}</dd></div>
            <div><dt>{labels.comparisons}</dt><dd>{format(coverage.comparisonCount)}</dd></div>
            <div><dt>{labels.checkedSources}</dt><dd>{format(report.evaluatedSourceCount)}</dd></div>
            <div><dt>{labels.matchedVersions}</dt><dd>{!coverage.evaluationComplete && report.status !== 'unavailable' && `${labels.atLeast} `}{format(coverage.matchedFindingCount)}</dd></div>
            <div><dt>{labels.shownVersions}</dt><dd>{format(report.findings.length)}</dd></div>
            <div><dt>{labels.shownWarnings}</dt><dd>{format(shownWarnings)}</dd></div>
            <div><dt>{labels.unassessedRecords}</dt><dd>{!coverage.evaluationComplete && report.status !== 'unavailable' && `${labels.atLeast} `}{format(report.unassessedRecordCount)}</dd></div>
            <div><dt>{labels.skipped}</dt><dd>{format(report.skippedPackageCount)}</dd></div>
            <div><dt>{labels.installationGaps}</dt><dd>{format(coverage.packageGaps.installationIncomplete)}</dd></div>
            <div><dt>{labels.versionGaps}</dt><dd>{format(coverage.packageGaps.nonstandardVersion)}</dd></div>
            <div><dt>{labels.missingSourceGaps}</dt><dd>{format(coverage.packageGaps.sourceMissing)}</dd></div>
        </dl>
        <p>{labels.checkDefinition}</p>
        {coverage.packageGaps.sourceMissing > 0 && <p>{labels.missingSourceNote}</p>}
        {omitted && <p>{labels.displayOmitted}</p>}
        {coverage.unassessedReasons.length > 0 && <><ul aria-label={labels.unassessedBreakdown} className="linux-cve-reasons">{coverage.unassessedReasons.map(entry => <li key={entry.reason}><span>{linuxCVEReasons[locale][entry.reason]}</span> {!coverage.evaluationComplete && `${labels.atLeast} `}{format(entry.count)}</li>)}</ul><p>{labels.reasonOverlap}</p></>}
        <ul aria-label={labels.reasons} className="linux-cve-reasons">{report.reasonCodes.filter(code => !coverage.unassessedReasons.some(entry => entry.reason === code)).map(code => <li key={code}>{linuxCVEReasons[locale][code] ?? code}</li>)}</ul>
    </>;
}
/** Mounted by the selected device's Security or CVE tab, never both. */
export function LinuxCVEPanel({ deviceId, sessionKey }: { deviceId: string; sessionKey?: string | number }) {
    const operator = useOperator(), [locale] = useLocale();
    if (!operator || operator.mode !== 'lan' || !operator.authenticated) return <p>{copy[locale].access}</p>;
    return <LinuxCVESession key={`${deviceId}:${String(sessionKey ?? '')}:${operator.expiresAt ?? ''}`} deviceId={deviceId} sessionExpiresAt={operator.expiresAt} canWrite={operator.hasExplicitMetadata === true && operator.loginMode === 'shared' && operator.actorId === null && operator.capabilities?.length === 1 && operator.capabilities[0] === 'read'}/>;
}
function LinuxCVESession({ deviceId, canWrite, sessionExpiresAt }: { deviceId: string; canWrite: boolean; sessionExpiresAt: string | null }) {
    const [locale] = useLocale(), labels = copy[locale], resource = useLinuxCVE(deviceId, canWrite, sessionExpiresAt), heading = useId(), fileId = useId();
    const view = resource.view, report = view?.report, activeReport = view?.status === 'evaluated' && report;
    const disabled = resource.loading || resource.writing !== null || resource.error === 'session';
    const cacheUncertain = view?.feeds.failureReason === 'cache_commit_uncertain', writeDisabled = disabled || !view || cacheUncertain;
    const feedAge = report?.feed && view ? linuxCVEAge(view.serverNow, report.feed.fetchedAt) + resource.elapsed : Infinity;
    const inventoryAge = view?.inventory ? linuxCVEAge(view.serverNow, view.inventory.collectedAt) + resource.elapsed : Infinity;
    const stale = activeReport && (report.status === 'stale' || feedAge >= LINUX_CVE_FEED_TTL_MS || inventoryAge >= LINUX_CVE_INVENTORY_TTL_MS);
    const warnings = activeReport ? groupLinuxCVEWarnings(report.findings) : null;
    const format = new Intl.NumberFormat(locale).format;
    const pending = report ? report.coverage.totalCheckCount - report.coverage.completedCheckCount : 0;
    return <section className="linux-cve" aria-labelledby={heading} aria-busy={resource.loading || resource.writing !== null}>
        <header className="linux-cve-heading"><div><h2 id={heading}>{labels.title}</h2><p>{labels.subtitle}</p></div><button type="button" className="button small" disabled={disabled} onClick={() => void resource.load()}><RefreshCw size={14}/>{labels.refresh}</button></header>
        {resource.canWrite && <div className="linux-cve-update"><button type="button" className="button primary" disabled={writeDisabled} onClick={() => void resource.sync()}><Download size={15}/>{labels.sync}</button><p>{labels.syncNote}</p></div>}
        {(resource.loading || resource.writing) && <p role="status" className="linux-cve-notice">{resource.writing === 'sync' ? labels.syncing : resource.writing === 'import' ? labels.importing : resource.recovering ? labels.recovering : labels.loading}</p>}
        {resource.error && <p role="alert" className="linux-cve-notice caution"><TriangleAlert size={16}/>{labels[resource.error]}</p>}
        {resource.notice && !(resource.notice === 'uncertain' && resource.error === 'uncertain') && <p role="status" className="linux-cve-notice">{labels[resource.notice]}</p>}
        {view && <>
            <div className="linux-cve-summary"><div className="linux-cve-count"><strong aria-label={activeReport && !report.coverage.evaluationComplete ? `${labels.atLeast} ${format(report.coverage.matchedWarningCount)}` : undefined}>{activeReport ? `${report.coverage.evaluationComplete ? '' : '≥ '}${format(report.coverage.matchedWarningCount)}` : '—'}</strong><span>{warnings === null ? labels.unavailableCount : labels.warnings}</span></div><div>
                <p className="linux-cve-state">{labels[view.status]}</p>
                {activeReport && report.unassessedRecordCount > 0 && <p className="linux-cve-warning">{!report.coverage.evaluationComplete && `${labels.atLeast} `}{format(report.unassessedRecordCount)} {report.unassessedRecordCount === 1 ? labels.unassessedSingle : labels.unassessed}</p>}
                {activeReport && report.skippedPackageCount > 0 && <p className="linux-cve-warning">{format(report.skippedPackageCount)} {report.skippedPackageCount === 1 ? labels.packageGapSingle : labels.packageGaps}</p>}
                {(stale || activeReport && report.coverage.evaluationComplete) && <p>{stale ? labels.stale : labels.partial}</p>}
                {activeReport && warnings && warnings.length > 0 && (report.coverage.matchedWarningCount > warnings.length ? <p>{labels.warningCardsOmitted}</p> : report.coverage.matchedFindingCount > report.findings.length && <p>{labels.versionsOmitted}</p>)}
            </div></div>
            {activeReport && !report.coverage.evaluationComplete && <p role="alert" className="linux-cve-notice caution"><TriangleAlert size={16}/><span>{labels.incomplete} {format(pending)} {pending === 1 ? labels.pendingSingle : labels.pending} {report.reasonCodes.includes('comparison_limit_exceeded') ? labels.processingLimit : labels.retryProcessing}</span></p>}
            {view.feeds.outcome === 'failed' && <p className="linux-cve-notice caution">{cacheUncertain ? labels.cacheUncertain : labels.feedFailed}</p>}
            <dl className="linux-cve-times"><div><dt>{labels.assessed}</dt><dd>{report ? <time dateTime={report.assessedAt}>{date(report.assessedAt, locale)}</time> : labels.unknown}</dd></div><div><dt>{labels.inventoryAge}</dt><dd>{age(inventoryAge, labels)}{view.inventory && inventoryAge >= LINUX_CVE_INVENTORY_TTL_MS && ` · ${labels.staleLabel}`}</dd></div><div><dt>{labels.feedAge}</dt><dd>{age(feedAge, labels)}{report?.feed && feedAge >= LINUX_CVE_FEED_TTL_MS && ` · ${labels.staleLabel}`}</dd></div></dl>
            {warnings && (warnings.length ? <ol className="linux-cve-list">{warnings.map(group => {
                const first = group[0];
                return <li key={`${first.cveId}:${first.sourcePackage}`}><article aria-label={`${first.cveId}: ${first.sourcePackage}`}><h3><a href={first.advisoryUrl} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{first.cveId}</a><span>{first.sourcePackage}</span></h3>
                    {group.map(row => <dl className="linux-cve-versions" key={row.installedSourceVersion}><div><dt>{labels.installed}</dt><dd>{row.installedSourceVersion}</dd></div><div><dt>{labels.fixed}</dt><dd>{row.publishedFixedVersion}</dd></div></dl>)}
                    <details><summary>{labels.binaries} ({group.reduce((sum, row) => sum + row.binaries.length, 0)}{group.some(row => row.binariesTruncated) ? '+' : ''})</summary>{group.map(row => <div key={row.installedSourceVersion}>{group.length > 1 && <p>{labels.installed}: {row.installedSourceVersion}</p>}<ul className="linux-cve-binaries">{row.binaries.map(binary => <li key={`${binary.name}:${binary.architecture}`}><span>{binary.name}:{binary.architecture}</span><span>{binary.version}</span></li>)}</ul></div>)}{group.some(row => row.binariesTruncated) && <p>{labels.binariesOmitted}</p>}</details>
                </article></li>;
            })}</ol> : <p className="linux-cve-notice">{report!.coverage.matchedWarningCount > 0 ? labels.warningDetailsOmitted : report!.coverage.evaluationComplete ? labels.empty : labels.pendingEmpty}</p>)}
            <p className="linux-cve-caveat">{labels.caveat}</p>
            <details className="linux-cve-details"><summary><Database size={15}/>{labels.details}</summary><p>{labels.coverage}</p><p>{labels.scope}</p><p>{labels.feedWindow}</p>
                {view.feeds.snapshots.length === 0 && <p>{labels.noFeed}</p>}
                {view.feeds.snapshots.map(feed => <section key={feed.provider} className="linux-cve-feed"><h3><a href={feed.sourceUrl} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{publisher(feed)}</a></h3>{feed.provider === 'canonical-ubuntu-osv' && <p>{labels.attribution} · <a href="https://creativecommons.org/licenses/by-sa/4.0/" target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{feed.license}</a></p>}<p>{feed.trust === 'https_origin_only' ? labels.syncTrust : labels.importedTrust}</p><dl className="linux-cve-facts"><div><dt>{labels.fetched}</dt><dd><time dateTime={feed.fetchedAt}>{date(feed.fetchedAt, locale)}</time> · {age(linuxCVEAge(view.serverNow, feed.fetchedAt) + resource.elapsed, labels)}</dd></div><div><dt>{labels.validated}</dt><dd><time dateTime={feed.validatedAt}>{date(feed.validatedAt, locale)}</time></dd></div><div><dt>{labels.records}</dt><dd>{new Intl.NumberFormat(locale).format(feed.recordCount)}</dd></div><div><dt>{labels.digest}</dt><dd>{feed.sha256}</dd></div></dl></section>)}
                {report && <LinuxCVECoverageDetails report={report} locale={locale}/>}
                {view.inventory && <dl className="linux-cve-facts"><div><dt>{labels.inventoryRows}</dt><dd>{format(view.inventory.rowCount)}</dd></div><div><dt>{labels.generation}</dt><dd>{view.inventory.generationId}</dd></div></dl>}
            </details>
            {resource.canWrite && <details className="linux-cve-details" onToggle={event => { if (!event.currentTarget.open) resource.clearFile(); }}><summary>{labels.importDetails}</summary><p>{labels.importNote}</p><div className="linux-cve-file"><label htmlFor={fileId}>{labels.choose}</label><input id={fileId} type="file" accept="application/json,.json" disabled={writeDisabled} onChange={event => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ''; resource.selectFile(file); }}/>{resource.selectedBytes !== null && <span>{labels.selected}: {new Intl.NumberFormat(locale).format(resource.selectedBytes)} B</span>}<button type="button" className="button small" disabled={writeDisabled || resource.selectedBytes === null} onClick={() => void resource.importSelected()}>{labels.import}</button>{resource.selectedBytes !== null && <button type="button" className="button small" onClick={resource.clearFile}>{labels.clearFile}</button>}</div></details>}
        </>}
    </section>;
}
