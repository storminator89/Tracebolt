import { ChevronDown } from 'lucide-react';
import { useLocale } from './i18n';
import './enrollment-macos.css';

/** Source-only guidance. No runnable command is serialized because this view
 * cannot establish reviewed local binary, bootstrap or protected state paths. */
export const macOSCopy = {
 en: {
  availability: 'macOS source build · TLS · Basic read-only scope',
  unavailable: 'This manager does not offer macOS enrollment. A matching source build with an explicitly configured macOS TLS/basic-readonly-v1 store is required; existing Linux managed and Windows profiles do not grant macOS support.',
  selected: 'macOS selected. Use reviewed, matching source builds as the intended nonroot reporting user. Persistent identity creation needs separate local approval.',
  scope: 'macOS version, Darwin kernel release, uptime estimate including sleep, physical RAM capacity and root-filesystem allocation.',
  limits: 'CPU and RAM utilization are unavailable. Root-filesystem allocation is not whole-device storage usage. No hostname, IP addresses, serial numbers, accounts, processes or logs are collected.',
  release: 'Source only. No released macOS installer or download command. Native macOS execution, installed-service and boot acceptance are unverified.',
  title: 'Enroll from reviewed macOS source',
  prepare: 'Build enroll-agent and macos-agent from the matching reviewed source. Download the public bootstrap JSON below and independently verify its manager and trust data.',
  enroll: 'As the intended nonroot reporting user, run enroll-agent with --bootstrap set to the JSON file’s absolute path and --state-directory set to a new protected absolute directory. Enter the invitation only at its hidden local prompt. Keep the terminal open, compare the full fingerprint and comparison value here, then approve the device.',
  renewal: 'This bootstrap requests same-key certificate renewal. Add --automatic-certificate-renewal only after separately approving ongoing renewal on the device. Renewal does not expand collection scope.',
  report: 'After activation, run macos-agent with --config pointing to agent.json inside that state directory and --foreground. Verify a fresh report on the device page. This is a foreground source path; launchd setup requires separate service provisioning and approval.',
 },
 de: {
  availability: 'macOS-Quellbuild · TLS · Basis-Leseumfang',
  unavailable: 'Dieser Manager bietet kein macOS-Enrollment an. Erforderlich ist ein passender Quellbuild mit ausdrücklich konfiguriertem macOS-TLS-/basic-readonly-v1-Datenspeicher; bestehende Linux-Managed- und Windows-Profile schalten macOS nicht frei.',
  selected: 'macOS ausgewählt. Verwende geprüfte, passende Quellbuilds unter dem vorgesehenen nicht privilegierten Meldebenutzer. Eine dauerhafte Identität braucht eine separate lokale Zustimmung.',
  scope: 'macOS-Version, Darwin-Kernelversion, geschätzte Laufzeit einschließlich Ruhezustand, physische RAM-Kapazität und Belegung des Root-Dateisystems.',
  limits: 'CPU- und RAM-Auslastung sind nicht verfügbar. Die Belegung des Root-Dateisystems entspricht nicht dem Speicherverbrauch des gesamten Geräts. Keine Erfassung von Hostname, IP-Adressen, Seriennummern, Konten, Prozessen oder Protokollen.',
  release: 'Nur Quellcode. Kein veröffentlichter macOS-Installer oder Download-Befehl. Native macOS-Ausführung, installierter Dienst und Systemstart sind noch nicht abgenommen.',
  title: 'Mit geprüftem macOS-Quellcode anmelden',
  prepare: 'Baue enroll-agent und macos-agent aus dem passenden geprüften Quellcode. Lade unten die öffentliche Bootstrap-JSON herunter und prüfe Manager und Vertrauensdaten unabhängig.',
  enroll: 'Starte enroll-agent als vorgesehenen nicht privilegierten Meldebenutzer: --bootstrap erhält den absoluten Pfad der JSON-Datei, --state-directory ein neues geschütztes absolutes Verzeichnis. Gib die Einladung nur im verdeckten lokalen Prompt ein. Lass das Terminal geöffnet, vergleiche hier den vollständigen Fingerabdruck und Vergleichswert und gib dann das Gerät frei.',
  renewal: 'Dieses Bootstrap fordert Zertifikatserneuerung mit demselben Schlüssel an. Ergänze --automatic-certificate-renewal erst nach separater lokaler Zustimmung zur laufenden Erneuerung. Der Erfassungsumfang wird dadurch nicht erweitert.',
  report: 'Starte nach Aktivierung macos-agent mit --config auf agent.json in diesem Zustandsverzeichnis und --foreground. Prüfe einen neuen Bericht auf der Geräteseite. Dieser Quellcode-Pfad läuft im Vordergrund; launchd erfordert separate Dienstbereitstellung und Zustimmung.',
 },
} as const;

export function MacOSScope() {
 const [locale]=useLocale(), copy=macOSCopy[locale];
 return <div className="enrollment-consent enrollment-macos"><h3>{copy.availability}</h3><p>{copy.scope}</p><details className="enrollment-context enrollment-advanced"><summary>{locale==='de'?'Erfassungsgrenzen':'Collection limits'}<ChevronDown size={14}/></summary><p>{copy.limits}</p></details></div>;
}
export function MacOSSourceInstructions({renewable}:{renewable:boolean}) {
 const [locale]=useLocale(), copy=macOSCopy[locale];
 return <div className="enrollment-macos"><h3>{copy.title}</h3><p>{copy.prepare}</p>{renewable&&<p role="status">{copy.renewal}</p>}<details className="enrollment-context enrollment-advanced"><summary>{locale==='de'?'Lokale Schritte & Voraussetzungen':'Local steps & prerequisites'}<ChevronDown size={14}/></summary><ol><li>{copy.enroll}</li><li>{copy.report}</li></ol></details><p className="enrollment-retention">{copy.release}</p></div>;
}
