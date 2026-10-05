package lanclient

import (
	"context"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalgenerationstate"
	"localrmm/internal/journalpolicy"
	"localrmm/internal/journalwire"
	"net/http"
	"path/filepath"
	"slices"
)

func journalGenerationDirectory(c Config) string {
	return filepath.Join(c.StateDirectory, "journal-policy-generation")
}
func (s *journalSender) reportGeneration(ctx context.Context, local journalLocal) error {
	st, e := journalgenerationstate.Open(ctx, journalGenerationDirectory(s.material.config))
	if e != nil {
		return e
	}
	record, e := st.Record()
	if e != nil {
		st.Close()
		return e
	}
	if record.SenderBinding != s.material.binding || record.DeviceID != s.material.config.AgentID || record.CertificateHash != journalLeaf(s.material) || record.PolicyGeneration != local.generation {
		st.Close()
		return errJournalDenied
	}
	report, e := st.NextReport(ctx, record, s.now().UTC())
	closeErr := st.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	// Recheck root activation after consuming the report counter. No cached or
	// pending policy may be advertised if the local authority changed meanwhile.
	fresh, e := s.local(s.material)
	if e != nil || fresh.revision != local.revision {
		return errJournalDenied
	}
	// Older policy consent never authorized disclosure of its service allowlist.
	if local.policy.SchemaVersion == journalpolicy.VersionV3 {
		report.SchemaVersion = journalgeneration.ReportVersionV2
		report.PolicyEnabled = local.policy.Enabled
		report.ServiceAuthorization = journalgeneration.ServiceAuthorization(local.policy.ServiceAuthorization)
		report.AllowedUnits = slices.Clone(local.policy.AllowedUnits)
	}
	raw, e := journalwire.EncodeGenerationReport(report)
	if e != nil {
		return e
	}
	reply, code, e := s.exchange(ctx, journalwire.GenerationPath, report.Sequence, raw)
	if e != nil {
		return e
	}
	if code != http.StatusOK {
		return errJournalDenied
	}
	echoed, e := journalwire.DecodeGenerationReport(reply)
	if e != nil || !journalgeneration.EqualReport(echoed, report) {
		return errJournalDenied
	}
	return nil
}
