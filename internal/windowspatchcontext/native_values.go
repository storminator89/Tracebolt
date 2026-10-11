package windowspatchcontext

// A missing value means this one indicator is absent. Success with a nonempty
// REG_MULTI_SZ byte count means an indicator is present, not that its payload
// was validated or that reboot is urgent. Malformed/zero-size metadata is unknown.
func fileOperationsState(typ, size uint32, success, missing, denied bool) string {
	if denied {
		return "denied"
	}
	if missing {
		return "clear"
	}
	if !success || typ != 7 || size < 4 || size%2 != 0 {
		return "unavailable"
	}
	if size == 4 {
		return "unavailable"
	}
	return "pending"
}
