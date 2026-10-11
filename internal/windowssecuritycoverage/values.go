package windowssecuritycoverage

func tpmInfo(version uint32) TPM {
	t := TPM{Quality: "observed", Presence: "present", Version: "unknown"}
	switch version {
	case 1:
		t.Version = "1.2"
	case 2:
		t.Version = "2.0"
	default:
		t.Quality = "partial"
		t.Reason = ErrMetadata.Error()
	}
	return t
}
