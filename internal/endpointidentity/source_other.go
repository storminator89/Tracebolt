//go:build !linux

package endpointidentity

// No non-Linux OS provider exists. The pure DTO and injected test collector are
// portable, but their cross-builds do not establish OS collection support.
const OSProviderUnsupported = true
