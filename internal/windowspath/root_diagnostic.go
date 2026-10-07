package windowspath

import "errors"

// rootFailure adds only a finite acquisition category. The original failure
// stays available to errors.Is; formatting never exposes native error text,
// a device path, or a numerical status. It never changes an admission decision.
type rootFailure struct {
	code  string
	cause error
}

func (*rootFailure) GoString() string             { return "<Windows root acquisition failure>" }
func (*rootFailure) Error() string                { return "Windows root acquisition rejected" }
func (e *rootFailure) Unwrap() error              { return e.cause }
func rootRejected(code string, cause error) error { return &rootFailure{code, cause} }

// RootDiagnostic returns only a known category from this package. An arbitrary
// error string or a caller-created wrapper can never become report content.
func RootDiagnostic(err error) string {
	var failure *rootFailure
	if !errors.As(err, &failure) || failure == nil {
		return ""
	}
	switch failure.code {
	case "root-path-syntax", "root-drive-type", "root-device-query-failed", "root-device-buffer-invalid", "root-device-target-rejected", "root-name-encoding",
		"root-open-access-denied", "root-open-sharing-violation", "root-open-reparse", "root-open-invalid-request", "root-open-name-not-found", "root-open-path-not-found", "root-open-name-invalid", "root-open-path-invalid", "root-open-type-mismatch", "root-open-not-directory", "root-open-unsupported", "root-open-privilege", "root-open-reparse-unresolved", "root-open-device-unavailable", "root-open-io-failed", "root-open-other":
		return failure.code
	}
	return ""
}
