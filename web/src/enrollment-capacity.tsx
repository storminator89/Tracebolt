import { useLocale } from './i18n';
import { terminal, type EnrollmentList } from './enrollment-types';

/** Display-only counts from one complete, validated enrollment-domain read.
 * Activation is not proof of a fresh report; ended records are never free slots.
 * Count the entire domain, not only rows visible under the platform/history filter.
 */
export function EnrollmentCapacity({ data }: { data: EnrollmentList }) {
 const [locale] = useLocale();
 const used = data.items.length, available = data.recordLimit - used;
 const activated = data.items.filter(item => item.state === 'activated').length;
 const ended = data.items.filter(item => terminal(item.state)).length;
 const preActivation = used - activated - ended;
 const nearLimit = available > 0 && available <= Math.ceil(data.recordLimit / 5);
 return <section className="enrollment-capacity" aria-label={locale === 'de' ? 'Enrollment-Kapazität' : 'Enrollment capacity'}>
  <p><strong>{locale === 'de' ? `${used} von ${data.recordLimit} gespeicherten Einträgen · ${available} freie Eintragsplätze` : `${used} of ${data.recordLimit} retained records · ${available} record slots available`}</strong></p>
  <p>{locale === 'de' ? `Aktivierte Einträge: ${activated} · Vor Aktivierung (gespeicherte Phase): ${preActivation} · Beendet, aufbewahrt: ${ended}` : `Activated records: ${activated} · Pre-activation records: ${preActivation} · Ended, retained: ${ended}`}</p>
  <p>{locale === 'de' ? 'Gilt für diese Enrollment-Domäne, nicht für die gesamte Flotte. Beendete Einträge belegen weiterhin Platz; eine aktivierte Identität bestätigt keinen frischen Bericht. Die Zahlen zeigen gespeicherte Phasen, nicht aktuelle Gültigkeit. Freie Eintragsplätze sind keine Reservierung und setzen Einladungs-/Pending-Limits nicht außer Kraft.' : 'Applies to this enrollment domain, not the whole fleet. Ended records still occupy slots; an activated identity does not confirm a fresh report. Counts reflect stored phases, not current validity. Free record slots do not reserve admission or override invitation/pending limits.'}</p>
  {(nearLimit || available === 0) && <p role="status">{locale === 'de'
   ? `${available === 0 ? 'Eintragslimit erreicht.' : 'Eintragslimit fast erreicht.'} Vor weiteren Aufnahmen die Pilot-Kapazität prüfen. Abbrechen oder Widerrufen schafft keinen Platz. Enrollment-Zustand und Replay-Ledger nicht löschen; eine größere Flotte ist hier nicht abgenommen.`
   : `${available === 0 ? 'Record limit reached.' : 'Nearing the record limit.'} Review pilot capacity before further enrollment. Canceling or revoking does not free slots. Do not delete enrollment state or replay ledgers; larger fleets are not accepted here.`}</p>}
 </section>;
}
