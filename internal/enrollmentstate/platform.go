package enrollmentstate

// ObservationPlatform maps the stored GOOS identity token to the established
// public model token. It grants no profile, credential or collector authority.
func ObservationPlatform(platform string) string {
	if platform == "darwin" {
		return "macos"
	}
	return platform
}
