package windowsaction

import "encoding/json"

// ServiceReviewBindingDigest pins all immutable public action authority fields.
// It is independent of preview approval and is never a grant or action permit.
func ServiceReviewBindingDigest(binding Binding) string {
	if !ValidBinding(binding) {
		return ""
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		return ""
	}
	return Digest(append([]byte("tracebolt.windows-service-review-binding.v1\x00"), raw...))
}
