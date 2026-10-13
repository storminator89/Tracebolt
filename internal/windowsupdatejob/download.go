package windowsupdatejob

import (
	"context"
	"encoding/json"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"net/url"
	"strconv"
	"strings"
)

const DownloadConsentVersion = "tracebolt.windows-selected-update-consent.v7"
const DownloadPermitVersion = "tracebolt.windows-selected-update-download.v1"
const DownloadRelayVersion = "tracebolt.windows-selected-update-download-relay.v1"
const DownloadScope = "windows-selected-cached-update-download-v1"
const DownloadPurpose = "download"

// Metadata-size admission only: no guaranteed wire-byte quota or disk reservation.
const MaxDownloadMetadataBytes uint64 = 16 << 30
const DownloadDisclosure = "Allow separately reviewed manual download of one exact already-cached Windows update GUID/revision using Windows-managed delivery under unchanged Windows Update policy. Review the normalized metadata origins and minimum/maximum size estimates; these are not an enforced network destination allowlist, hard byte quota or available-disk reservation. Windows may use configured proxies, BITS, Delivery Optimization or peers. The EULA must already be accepted. Partial, canceled or timed-out work may leave cached content; there is no rollback, cache deletion or automatic retry. Download never installs, accepts a license, scans online, changes delivery policy or reboots. A settled successful download must be explicitly retired before a separate fresh installation review and approval."

func (p Permit) Download() bool    { return p.Version == DownloadPermitVersion }
func (p Permit) Reusable() bool    { return p.Version == ReusablePermitVersion || p.Download() }
func (c Challenge) Download() bool { return c.Version == DownloadRelayVersion }
func relayVersion(download bool) string {
	if download {
		return DownloadRelayVersion
	}
	return RelayVersion
}
func digestPurpose(purpose string, v any) string {
	b, _ := json.Marshal(v)
	return actionpermit.Digest(append([]byte(purpose+"\x00"), b...))
}

// Origins are bounded policy context only, never caller-supplied download URLs.
func ValidDownloadOrigins(origins string) bool {
	if origins == "" || len(origins) > 2048 {
		return false
	}
	parts := strings.Split(origins, "\n")
	if len(parts) > 8 {
		return false
	}
	previous := ""
	for _, origin := range parts {
		if len(origin) > 255 || origin <= previous {
			return false
		}
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Host != strings.ToLower(u.Host) || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != origin {
			return false
		}
		if strings.ContainsAny(u.Host, " \t\r\n%\\") || u.Hostname() == "" {
			return false
		}
		if p := u.Port(); p != "" {
			n, err := strconv.ParseUint(p, 10, 16)
			if err != nil || n == 0 || strconv.FormatUint(n, 10) != p || u.Scheme == "https" && p == "443" || u.Scheme == "http" && p == "80" {
				return false
			}
		}
		previous = origin
	}
	return true
}
func (r Readiness) validateDownloadMetadata() error {
	if r.Purpose == "" {
		if r.DownloadMetadataKnown || r.DownloadOrigins != "" || r.DownloadMinBytes != 0 || r.DownloadMaxBytes != 0 || r.DownloadSource != "" || r.DownloadServiceID != "" {
			return ErrInvalid
		}
		return nil
	}
	if r.Purpose != DownloadPurpose {
		return ErrInvalid
	}
	if !r.DownloadMetadataKnown {
		if r.DownloadOrigins != "" || r.DownloadMinBytes != 0 || r.DownloadMaxBytes != 0 || r.DownloadSource != "" || r.DownloadServiceID != "" {
			return ErrInvalid
		}
		return nil
	}
	if !ValidDownloadOrigins(r.DownloadOrigins) || r.DownloadMinBytes > r.DownloadMaxBytes {
		return ErrInvalid
	}
	switch r.DownloadSource {
	case "default", "managed_server", "windows_update":
		if r.DownloadServiceID != "" {
			return ErrInvalid
		}
	case "other":
		if !ValidSelection(Selection{UpdateID: r.DownloadServiceID}) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// Purpose selection is local manager control, not a generic operation dispatcher.
type downloadRequestKey struct{}

func downloadRequest(ctx context.Context) bool {
	return ctx != nil && ctx.Value(downloadRequestKey{}) == true
}
func (m *Manager) RequestDownload(ctx context.Context, device, actor, id string, s Selection) error {
	if ctx == nil {
		return ErrInvalid
	}
	return m.Request(context.WithValue(ctx, downloadRequestKey{}, true), device, actor, id, s)
}
func (m *Manager) ApproveDownload(ctx context.Context, device, actor, id, d string, ack bool) error {
	if ctx == nil {
		return ErrInvalid
	}
	return m.Approve(context.WithValue(ctx, downloadRequestKey{}, true), device, actor, id, d, ack)
}
func (m *Manager) ReviewDownload(ctx context.Context, device, actor, id string) error {
	if ctx == nil {
		return ErrInvalid
	}
	return m.Review(context.WithValue(ctx, downloadRequestKey{}, true), device, actor, id)
}
func (m *Manager) RetireDownload(ctx context.Context, device, actor, id string, occurrence uint64, envelopeDigest, resultDigest string, ack bool) error {
	if ctx == nil {
		return ErrInvalid
	}
	return m.Retire(context.WithValue(ctx, downloadRequestKey{}, true), device, actor, id, occurrence, envelopeDigest, resultDigest, ack)
}
func (j Job) Download() bool { return j.Purpose == DownloadPurpose }
func (m *Manager) operationAllowed(actor string, download bool) bool {
	if download {
		return m.downloadAllowed != nil && m.downloadAllowed(actor)
	}
	return m.operatorAllowed != nil && m.operatorAllowed(actor)
}
func (m *Manager) ConfigureDownloadPolicy(allowed func(string) bool) error {
	if m == nil || allowed == nil {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.downloadAllowed != nil || m.failed {
		return ErrInvalid
	}
	m.downloadAllowed = allowed
	return nil
}

func (r Readiness) downloadReason() string {
	if r.Validate() != nil {
		return "readiness_unknown"
	}
	for _, f := range []Fact{r.Software, r.Installed, r.Hidden, r.Downloaded, r.EULAAccepted, r.OfflineVerified} {
		if f == Unknown {
			return "readiness_unknown"
		}
	}
	if r.BundledCount < 0 || !r.DownloadMetadataKnown {
		return "download_metadata_unknown"
	}
	if r.OfflineVerified != Yes {
		return "offline_unverified"
	}
	if r.Software != Yes || r.Installed != No || r.Hidden != No {
		return "selection_ineligible"
	}
	if r.Downloaded != No {
		return "already_downloaded"
	}
	if r.EULAAccepted != Yes {
		return "license_not_accepted"
	}
	if r.BundledCount != 0 {
		return "bundle_unsupported"
	}
	if r.DownloadMaxBytes > MaxDownloadMetadataBytes {
		return "download_size_exceeds_review_limit"
	}
	return "ready"
}
func (r Result) validateDownload() error {
	if !enrollmentcrypto.ValidID(r.JobID, "update_") || !actionpermit.ValidDigest(r.EnvelopeDigest) || !validTime(r.CompletedAt) || !fact(r.DownloadedAfter) || r.RebootRequired != Unknown || r.OperationResult > 5 || r.AggregateOperationResult > 5 || r.NativeReturned && !r.Attempted {
		return ErrInvalid
	}
	if !r.AggregateResultKnown && r.AggregateOperationResult != 0 || !r.AggregateHResultKnown && r.AggregateHResult != 0 || !r.UpdateResultKnown && r.OperationResult != 0 || !r.UpdateHResultKnown && r.HResult != 0 {
		return ErrInvalid
	}
	if !r.NativeReturned && (r.DownloadedAfter != Unknown || r.AggregateResultKnown || r.AggregateHResultKnown || r.UpdateResultKnown || r.UpdateHResultKnown) {
		return ErrInvalid
	}
	switch r.Outcome {
	case "not_attempted":
		if r.Attempted || r.NativeReturned || r.CleanupSucceeded || r.OperationResult != 0 || r.HResult != 0 || r.AggregateOperationResult != 0 || r.AggregateHResult != 0 || r.DownloadedAfter != Unknown {
			return ErrInvalid
		}
	case "succeeded":
		if !r.AggregateResultKnown || !r.AggregateHResultKnown || !r.UpdateResultKnown || !r.UpdateHResultKnown || !r.Attempted || !r.NativeReturned || !r.CleanupSucceeded || r.OperationResult != 2 || r.HResult < 0 || r.AggregateOperationResult != 2 || r.AggregateHResult < 0 || r.DownloadedAfter != Yes {
			return ErrInvalid
		}
	case "failed":
		if !r.Attempted || !r.NativeReturned || !r.CleanupSucceeded || (r.OperationResult != 4 && r.OperationResult != 5 && r.AggregateOperationResult != 4 && r.AggregateOperationResult != 5) {
			return ErrInvalid
		}
	case "uncertain":
		if !r.Attempted {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (m *Manager) ClaimDownload(ctx context.Context, id string) ([]byte, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	return m.Claim(context.WithValue(ctx, downloadRequestKey{}, true), id)
}
