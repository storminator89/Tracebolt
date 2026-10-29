import { useEffect, useRef, useState } from 'react';
import { ArrowDownToLine } from 'lucide-react';
import { useLocale } from './i18n';
import { checkWindowsSetupFile, WINDOWS_SETUP_LINKS, WINDOWS_SETUP_RELEASE } from './windows-setup-release';
import type { WindowsSetupFileResult } from './windows-setup-release';

const copy = {
    en: {
        prepare: 'Prepare Windows Setup',
        before: 'Download and check Setup before creating the 10-minute invitation. Use a fresh x64 device; installation requires local administrator approval.',
        download: 'Download Setup · preview.3', guide: 'Installation guide',
        check: 'Check downloaded Setup (optional)', local: 'Choose the downloaded file on this computer. Its contents stay in this browser and are never uploaded or run.',
        checking: 'Checking the local file…',
        matched: 'File matches the selected preview.3 Setup bytes. It remains unsigned; this is not publisher trust or permission to install.',
        'different-file': 'File does not match the selected Setup name, size or SHA-256. Do not run it as this preview. Use the release download and check again.',
        unavailable: 'Local file checking is unavailable in this browser. Use the release guide to verify SHA-256 independently before running Setup.',
        failed: 'The local file could not be checked. No verification result is available. Select it again or follow the release guide.',
        evidence: 'Release, requirements and verification details',
        limits: 'Unsigned x64 preview. Native evidence covers three Server 2025 Setup cases. Windows 11, real Linux-manager/dashboard operation, full provider access and reboot remain unverified. Keep Windows and endpoint security protections intact.',
        manager: 'The administrator must prepare the matching Linux manager and frontend from the source below, with approved enrollment and TLS material. Downloading Setup does not check manager compatibility; Setup checks it before installation writes.',
        source: 'Matching manager source', provenance: 'Release and native evidence', manifest: 'Release manifest',
        comparison: 'Compare this release and hash with an independently trusted source. A modified dashboard can replace both. No Authenticode signature is provided.',
        http: 'Published preview.3 is TLS-only. This HTTP test needs separately reviewed matching source artifacts and explicit plaintext-risk approval; the published download is not offered for it.',
        install: 'Install and verify Windows',
        steps: [
            'Download the public bootstrap below to a local folder on the Windows device, such as Downloads, then choose it in Setup. Copy it off CD/DVD or a network share first; links are not accepted. Compare the manager identity, origins and full trust fingerprints independently.',
            'Review the 21 local Read admin scopes and the unchecked service, persistent-identity and trust approvals. This dashboard invitation does not grant those scopes. Source HTTP tests require their separate plaintext-risk acknowledgement.',
            'Enter the invitation only in Setup’s separate hidden-input console. Keep Setup and the console open; compare the full device fingerprint and comparison value here before approving the device.',
            'After Setup requests service start, open the device and check for a fresh authenticated report and actual source coverage. An activated identity or a running service alone does not prove reporting.',
        ],
        interruption: 'If Setup stops after making changes, retain all state for administrator review. Fresh Setup cannot overwrite or reset it; service removal retains files, keys and state.',
    },
    de: {
        prepare: 'Windows-Setup vorbereiten',
        before: 'Setup herunterladen und prüfen, bevor die 10-Minuten-Einladung erstellt wird. Ein frisches x64-Gerät verwenden; die Installation benötigt eine lokale Administratorfreigabe.',
        download: 'Setup herunterladen · Preview.3', guide: 'Installationsanleitung',
        check: 'Heruntergeladenes Setup prüfen (optional)', local: 'Die heruntergeladene Datei auf diesem Computer auswählen. Ihr Inhalt bleibt in diesem Browser und wird weder hochgeladen noch ausgeführt.',
        checking: 'Lokale Datei wird geprüft…',
        matched: 'Die Datei entspricht den ausgewählten Preview.3-Setup-Bytes. Sie bleibt unsigniert; dies belegt weder Herausgebervertrauen noch eine Installationsfreigabe.',
        'different-file': 'Name, Größe oder SHA-256 entsprechen nicht dem ausgewählten Setup. Die Datei nicht als diesen Preview ausführen. Den Release-Download verwenden und erneut prüfen.',
        unavailable: 'Die lokale Dateiprüfung ist in diesem Browser nicht verfügbar. SHA-256 vor Ausführung anhand der Release-Anleitung unabhängig prüfen.',
        failed: 'Die lokale Datei konnte nicht geprüft werden. Es liegt kein Prüfergebnis vor. Erneut auswählen oder der Release-Anleitung folgen.',
        evidence: 'Release, Voraussetzungen und Prüfdetails',
        limits: 'Unsignierter x64-Preview. Der native Nachweis umfasst drei Server-2025-Setup-Fälle. Windows 11, echter Linux-Manager/Dashboard-Betrieb, vollständiger Provider-Zugriff und Neustart bleiben ungeprüft. Windows- und Geräteschutz beibehalten.',
        manager: 'Der Administrator muss den passenden Linux-Manager samt Frontend aus dem unten genannten Quellstand sowie freigegebenes Enrollment- und TLS-Material vorbereiten. Der Setup-Download prüft keine Manager-Kompatibilität; Setup prüft sie vor Installationsschreibzugriffen.',
        source: 'Passender Manager-Quellstand', provenance: 'Release und native Nachweise', manifest: 'Release-Manifest',
        comparison: 'Release und Hash mit einer unabhängig vertrauenswürdigen Quelle vergleichen. Ein manipuliertes Dashboard kann beides ersetzen. Es liegt keine Authenticode-Signatur vor.',
        http: 'Der veröffentlichte Preview.3 unterstützt nur TLS. Dieser HTTP-Test braucht separat geprüfte passende Quellartefakte und eine ausdrückliche Klartext-Risikofreigabe; der veröffentlichte Download wird dafür nicht angeboten.',
        install: 'Windows installieren und prüfen',
        steps: [
            'Die öffentliche Bootstrap-Datei unten herunterladen und auf dem Windows-Gerät in einem lokalen Ordner wie Downloads im Setup auswählen. Von CD/DVD oder einer Netzwerkfreigabe zuerst dorthin kopieren; Verknüpfungen sind nicht zulässig. Manager-Identität, Ziele und vollständige Vertrauens-Fingerabdrücke unabhängig vergleichen.',
            'Die 21 lokalen Read-admin-Bereiche sowie die ungeprüften Zustimmungen zu Dienst, dauerhafter Identität und Vertrauensvergleich prüfen. Diese Dashboard-Einladung gewährt diese Bereiche nicht. HTTP-Quelltests benötigen eine separate Klartext-Risikobestätigung.',
            'Die Einladung ausschließlich in der separaten verdeckten Setup-Konsole eingeben. Setup und Konsole geöffnet lassen; hier vor der Gerätefreigabe den vollständigen Geräte-Fingerabdruck und Vergleichswert vergleichen.',
            'Nach der Dienststart-Anforderung das Gerät öffnen und einen frischen authentifizierten Bericht samt tatsächlicher Quellenabdeckung prüfen. Eine aktivierte Identität oder ein laufender Dienst allein belegen keine Berichterfassung.',
        ],
        interruption: 'Bei einem Abbruch nach Änderungen den Zustand für die Administratorprüfung erhalten. Frisches Setup überschreibt oder setzt ihn nicht zurück; die Dienstentfernung erhält Dateien, Schlüssel und Zustand.',
    },
} as const;

const external = { target: '_blank', rel: 'noopener noreferrer', referrerPolicy: 'no-referrer' } as const;

export function WindowsSetupPreparation({ insecureTest }: { insecureTest: boolean }) {
    const [locale] = useLocale(), c = copy[locale];
    const [result, setResult] = useState<WindowsSetupFileResult | 'checking' | null>(null);
    const generation = useRef(0);
    // File reads and WebCrypto cannot be canceled. Discard results from an older
    // selection or unmounted dialog; do not restore a stale positive result.
    useEffect(() => () => { generation.current++; }, []);
    const check = async (file: File | undefined) => {
        const current = ++generation.current;
        setResult(file ? 'checking' : null);
        if (!file) return;
        const next = await checkWindowsSetupFile(file);
        if (generation.current === current) setResult(next);
    };
    if (insecureTest) return <p className="enrollment-message">{c.http}</p>;
    return <section className="enrollment-windows-prepare" aria-label={c.prepare}>
        <h3>{c.prepare}</h3><p>{c.before}</p><p>{c.limits}</p>
        <div className="enrollment-windows-downloads">
            <a className="button" href={WINDOWS_SETUP_LINKS.setup} {...external}><ArrowDownToLine size={15}/>{c.download}</a>
            <a href={WINDOWS_SETUP_LINKS.guide} {...external}>{c.guide}</a>
        </div>
        <label className="enrollment-windows-file">{c.check}<input type="file" accept=".exe" onChange={event => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ''; void check(file); }}/></label>
        <small>{c.local}</small>
        {result && <p role={result === 'different-file' || result === 'failed' ? 'alert' : 'status'}>{c[result]}</p>}
        <details className="enrollment-context"><summary>{c.evidence}</summary>
            <p>{c.manager}</p>
            <p><a href={WINDOWS_SETUP_LINKS.source} {...external}>{c.source}</a>: <code>{WINDOWS_SETUP_RELEASE.sourceCommit}</code></p>
            <p><a href={WINDOWS_SETUP_LINKS.release} {...external}>{c.provenance}</a> · <a href={WINDOWS_SETUP_LINKS.manifest} {...external}>{c.manifest}</a></p>
            <p>SHA-256: <code className="enrollment-windows-digest">{WINDOWS_SETUP_RELEASE.sha256}</code></p><p>{c.comparison}</p>
        </details>
    </section>;
}

export function WindowsSetupInstructions() {
    const [locale] = useLocale(), c = copy[locale];
    return <div className="enrollment-windows-install"><h3>{c.install}</h3><ol>{c.steps.map(step => <li key={step}>{step}</li>)}</ol><p>{c.interruption}</p></div>;
}
