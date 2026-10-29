package customerclaim

import "time"

// ValidChallengeContext checks the public wire constraints, not challenge
// ownership, consumption, the active installer profile or customer authority.
// Those checks remain the responsibility of the manager admission service.
func ValidChallengeContext(c Context, now time.Time) bool {
	return validContext(c, now)
}
