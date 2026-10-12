package windowsmanagedmsi

const (
	ScheduledVersion             = "tracebolt.windows-managed-msi.v4"
	ScheduledGrantVersion        = "tracebolt.windows-managed-msi-grant.v4"
	ScheduledEndpointVersion     = "tracebolt.windows-managed-msi-endpoint.v4"
	ScheduledOfferVersion        = "tracebolt.windows-managed-msi-setup-offer.v4"
	ScheduledRegistrationVersion = "tracebolt.windows-managed-msi-setup-registration.v4"
	ScheduledDisclosure          = "Allow separately approved exact MSI jobs to wait for one bounded UTC window under this original identity and absolute expiry. Each window still requires named approval of the exact delivered package, publisher evidence, terms, LocalSystem/custom-action risk and native evidence. Scheduling does not approve delivery, another package, an update job, retry, reboot, rollback or cancellation of an issued installation. Fresh readiness and exact shared-owner admission remain required; unavailable or uncertain state blocks execution without extending the window."
)

// Reusable is eligibility for the bounded reusable job ledger. Scheduled is
// independent fresh local authority, never inferred from reusable permission.
func (g Grant) Reusable() bool       { return g.Version == ReusableGrantVersion || g.Scheduled() }
func (g Grant) Scheduled() bool      { return g.Version == ScheduledGrantVersion }
func (o SetupOffer) Reusable() bool  { return o.Version == ReusableOfferVersion || o.Scheduled() }
func (o SetupOffer) Scheduled() bool { return o.Version == ScheduledOfferVersion }

func (r SetupRegistration) validProfile() bool {
	switch r.Version {
	case SetupRegistrationVersion:
		return !r.Grant.Reusable() && r.Offer.Version == SetupOfferVersion
	case ReusableRegistrationVersion:
		return r.Grant.Version == ReusableGrantVersion && r.Offer.Version == ReusableOfferVersion
	case ScheduledRegistrationVersion:
		return r.Grant.Scheduled() && r.Offer.Scheduled()
	}
	return false
}
