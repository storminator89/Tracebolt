import { ChevronDown } from 'lucide-react';
import { useLocale } from './i18n';
import './enrollment-macos.css';

/** Source-only guidance using explicitly reviewed local binaries and paths.
 * No installer/download command or invitation secret is serialized here. */
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

export const macInventoryCopy = {
 en: {
  availability: 'macOS source build · TLS · Explicit read-only inventory',
  unavailable: 'Expanded macOS inventory enrollment is not enabled on this manager. It requires a separately configured inventory store and a fresh approved identity. Existing basic Mac grants remain unchanged.',
  title: 'Fresh macOS read-only inventory',
  scope: 'Hardware model identifier, physical/logical CPU counts and RAM capacity; Installer receipt identifiers; caller-visible process IDs, parent IDs and short kernel accounting labels; separate IPv4/IPv6 interface names, MTU, up/running flags and numeric local addresses/prefixes.',
  limits: 'Labels can identify applications and may be truncated. Addresses can identify a device or network. Installer receipt IDs are not an installed-software list. Receipts can outlive removed files and do not cover all installed software, App Store apps or Homebrew. No usernames, serials, UUIDs, paths, arguments, environment, logs, MAC addresses, Wi-Fi names, DNS, probes, traffic, software actions or privilege changes. Operator-only; no AI/provider export.',
  retention: 'Latest generation only, up to 24 hours from capture; refresh never renews its age. At most 2,048 receipts, 4,096 processes and 128 interfaces per family. Independent failures stay explicit. Stored bytes may remain until cleanup. This fresh scope also needs explicit local approval; it never upgrades a basic identity.',
  acknowledge: 'I acknowledge this expanded read-only macOS inventory collection for the new device.',
  prepare: 'Build enroll-agent and macos-agent from matching reviewed source. Download and independently verify the public TLS bootstrap below for macos-read-inventory-v1. Existing identities and grants cannot be reused or expanded.',
  enroll: 'As the intended nonroot reporting user, run enroll-agent with --macos-read-inventory, --bootstrap set to the verified JSON file’s absolute path, and --state-directory set to a new protected absolute directory. Read the full local disclosure, then type ALLOW MACOS INVENTORY at the local terminal before any keys, private state, grants or network requests. This dashboard acknowledgement does not replace local approval. Enter the invitation only at its separate hidden local prompt, never in arguments, environment, stdin, files or logs. Keep the terminal open, compare the full fingerprint and comparison value here, then approve the device.',
  report: 'After activation, run macos-agent with --config pointing to agent.json inside that state directory and --foreground. Verify a fresh inventory generation on the device page. Reporting runs every minute; stopping the foreground process also stops local retention cleanup. No service is installed. Preserve interrupted or missing state for inspection; never delete or reset it.',
 },
 de: {
  availability: 'macOS-Quellbuild · TLS · Explizites Leseinventar',
  unavailable: 'Erweitertes macOS-Inventar-Enrollment ist auf diesem Manager nicht aktiviert. Es braucht einen separat konfigurierten Inventarspeicher und eine neue freigegebene Identität. Bestehende Mac-Basisfreigaben bleiben unverändert.',
  title: 'Neues macOS-Leseinventar',
  scope: 'Hardware-Modellkennung, physische/logische CPU-Anzahl und RAM-Kapazität; Installer-Belegkennungen; sichtbare Prozess-IDs, Eltern-IDs und kurze Kernel-Prozessbezeichnungen; getrennte IPv4-/IPv6-Schnittstellennamen, MTU, Up-/Running-Flags und numerische lokale Adressen/Präfixe.',
  limits: 'Bezeichnungen können Anwendungen erkennen lassen und gekürzt sein. Adressen können Gerät oder Netzwerk identifizieren. Installer-Belegkennungen sind keine Liste installierter Software. Belege können entfernte Dateien überdauern und decken nicht alle installierte Software, App-Store-Apps oder Homebrew ab. Keine Benutzernamen, Seriennummern, UUIDs, Pfade, Argumente, Umgebung, Protokolle, MAC-Adressen, WLAN-Namen, DNS, Probes, Verkehrsdaten, Softwareaktionen oder Rechteänderungen. Nur für Operatoren; kein KI-/Provider-Export.',
  retention: 'Nur die neueste Generation, bis zu 24 Stunden ab Erfassung; Aktualisieren erneuert ihr Alter nicht. Höchstens 2.048 Belege, 4.096 Prozesse und 128 Schnittstellen je Familie. Quellfehler bleiben getrennt sichtbar. Gespeicherte Bytes können bis zur Bereinigung bleiben. Der neue Umfang braucht zusätzlich explizite lokale Zustimmung und erweitert keine Basisidentität.',
  acknowledge: 'Ich bestätige diese erweiterte, nur lesende macOS-Inventarerfassung für das neue Gerät.',
  prepare: 'Baue enroll-agent und macos-agent aus passendem geprüftem Quellcode. Lade unten die öffentliche TLS-Bootstrap-JSON für macos-read-inventory-v1 herunter und prüfe sie unabhängig. Bestehende Identitäten und Freigaben dürfen nicht wiederverwendet oder erweitert werden.',
  enroll: 'Starte enroll-agent als vorgesehenen nicht privilegierten Meldebenutzer mit --macos-read-inventory, --bootstrap für den absoluten Pfad der geprüften JSON-Datei und --state-directory für ein neues geschütztes absolutes Verzeichnis. Lies die vollständige lokale Erfassungsbeschreibung und tippe ALLOW MACOS INVENTORY im lokalen Terminal, bevor Schlüssel, privater Zustand, Freigaben oder Netzwerkanfragen entstehen. Die Dashboard-Bestätigung ersetzt keine lokale Zustimmung. Gib die Einladung nur im separaten verdeckten lokalen Prompt ein, niemals als Argument, Umgebungsvariable, stdin, Datei oder Protokolleintrag. Lass das Terminal geöffnet, vergleiche hier vollständigen Fingerabdruck und Vergleichswert und gib dann das Gerät frei.',
  report: 'Starte nach Aktivierung macos-agent mit --config auf agent.json in diesem Zustandsverzeichnis und --foreground. Prüfe eine neue Inventargeneration auf der Geräteseite. Berichte erfolgen jede Minute; das Beenden des Vordergrundprozesses stoppt auch die lokale Aufbewahrungsbereinigung. Es wird kein Dienst installiert. Bewahre unterbrochenen oder unvollständigen Zustand zur Prüfung auf; niemals löschen oder zurücksetzen.',
 },
} as const;

export function MacOSScope({inventory=false}:{inventory?:boolean}) {
 const [locale]=useLocale(), copy=macOSCopy[locale];
 if(inventory){const c=macInventoryCopy[locale];return <div className="enrollment-macos"><h3>{c.title}</h3><p>{c.scope}</p><p>{c.retention}</p><details className="enrollment-context enrollment-advanced"><summary>{locale==='de'?'Erfassungsgrenzen':'Collection limits'}<ChevronDown size={14}/></summary><p>{c.limits}</p></details></div>;}
 return <div className="enrollment-consent enrollment-macos"><h3>{copy.availability}</h3><p>{copy.scope}</p><details className="enrollment-context enrollment-advanced"><summary>{locale==='de'?'Erfassungsgrenzen':'Collection limits'}<ChevronDown size={14}/></summary><p>{copy.limits}</p></details></div>;
}
export function MacOSSourceInstructions({renewable,inventory=false}:{renewable:boolean;inventory?:boolean}) {
 const [locale]=useLocale(), copy=macOSCopy[locale];
 if(inventory){const c=macInventoryCopy[locale];return <div className="enrollment-macos"><h3>{c.title}</h3><p>{c.prepare}</p>{renewable&&<p role="status">{copy.renewal}</p>}<details className="enrollment-context enrollment-advanced"><summary>{locale==='de'?'Lokale Schritte & Voraussetzungen':'Local steps & prerequisites'}<ChevronDown size={14}/></summary><ol><li>{c.enroll}</li><li>{c.report}</li></ol></details><p className="enrollment-retention">{copy.release}</p></div>;}
 return <div className="enrollment-macos"><h3>{copy.title}</h3><p>{copy.prepare}</p>{renewable&&<p role="status">{copy.renewal}</p>}<details className="enrollment-context enrollment-advanced"><summary>{locale==='de'?'Lokale Schritte & Voraussetzungen':'Local steps & prerequisites'}<ChevronDown size={14}/></summary><ol><li>{copy.enroll}</li><li>{copy.report}</li></ol></details><p className="enrollment-retention">{copy.release}</p></div>;
}
