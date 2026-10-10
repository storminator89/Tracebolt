package windowsservice

import "fmt"

// setupDiagnosticPairs is an append-only public diagnostic vocabulary. Its
// order is part of the setup-child report codec: never reorder, remove, or reuse
// an entry. Only these explicit pairs are accepted, never a Cartesian product.
// The metadata contains failure sites only, not native codes, paths or causes.
var setupDiagnosticPairs = [...][2]string{
	{"unknown", "unknown"},
	{"service_acl_ace", "failed"},
	{"service_acl_ace", "missing"},
	{"service_acl_ace_size", "invalid"},
	{"service_acl_ace_type", "invalid"},
	{"service_acl_dacl", "failed"},
	{"service_acl_dacl", "missing"},
	{"service_acl_descriptor", "invalid"},
	{"service_acl_owner", "failed"},
	{"service_acl_owner", "invalid"},
	{"service_acl_owner", "unsafe_path"},
	{"service_acl_runtime_read", "denied"},
	{"service_acl_runtime_read", "missing"},
	{"service_acl_security", "failed"},
	{"service_acl_sid", "invalid"},
	{"service_acl_sid_size", "invalid"},
	{"service_acl_writer", "unsafe_path"},
	{"service_create_automatic", "failed"},
	{"service_create_description", "failed"},
	{"service_create_privileges", "failed"},
	{"service_create_scm", "failed"},
	{"service_create_service", "existing"},
	{"service_create_service", "failed"},
	{"service_create_sid", "failed"},
	{"service_create_start_type", "invalid"},
	{"service_inspect_context", "interrupted"},
	{"service_inspect_open", "failed"},
	{"service_inspect_snapshot", "failed"},
	{"service_install_context", "interrupted"},
	{"service_install_create", "failed"},
	{"service_install_current_existing", "existing"},
	{"service_install_executable", "failed"},
	{"service_install_handle", "missing"},
	{"service_install_hash", "changed"},
	{"service_install_inspect", "failed"},
	{"service_install_layout", "failed"},
	{"service_install_plan", "mismatch"},
	{"service_install_plan_existing", "existing"},
	{"service_install_precreate_context", "interrupted"},
	{"service_install_sid", "failed"},
	{"service_install_sid", "invalid"},
	{"service_install_snapshot", "failed"},
	{"service_install_snapshot", "mismatch"},
	{"service_layout_component", "unsafe_path"},
	{"service_layout_program_data", "failed"},
	{"service_layout_program_files", "failed"},
	{"service_layout_root", "unsafe_path"},
	{"service_open_access", "invalid"},
	{"service_open_scm", "failed"},
	{"service_open_service", "failed"},
	{"service_open_service", "missing"},
	{"service_owned_binding", "mismatch"},
	{"service_owned_context", "interrupted"},
	{"service_owned_executable", "failed"},
	{"service_owned_final_context", "interrupted"},
	{"service_owned_hash", "changed"},
	{"service_owned_inspect", "failed"},
	{"service_owned_layout", "failed"},
	{"service_owned_open", "failed"},
	{"service_owned_receipt", "mismatch"},
	{"service_plan_context", "interrupted"},
	{"service_plan_executable", "failed"},
	{"service_plan_inspect", "failed"},
	{"service_plan_layout", "failed"},
	{"service_plan_nonce", "failed"},
	{"service_query_failure_actions", "probe_failed"},
	{"service_query_failure_actions", "probe_invalid"},
	{"service_query_failure_actions", "read_failed"},
	{"service_query_failure_actions", "result_invalid"},
	{"service_query_failure_actions", "size_invalid"},
	{"service_query_privileges", "probe_failed"},
	{"service_query_privileges", "probe_invalid"},
	{"service_query_privileges", "read_failed"},
	{"service_query_privileges", "result_invalid"},
	{"service_query_privileges", "size_invalid"},
	{"service_query_triggers", "probe_failed"},
	{"service_query_triggers", "probe_invalid"},
	{"service_query_triggers", "read_failed"},
	{"service_query_triggers", "result_invalid"},
	{"service_query_triggers", "size_invalid"},
	{"service_sid_lookup", "failed"},
	{"service_sid_validate", "invalid"},
	{"service_snapshot_configuration", "failed"},
	{"service_snapshot_failure_actions", "failed"},
	{"service_snapshot_failure_size", "invalid"},
	{"service_snapshot_privilege_parse", "invalid"},
	{"service_snapshot_privileges", "failed"},
	{"service_snapshot_sid", "failed"},
	{"service_snapshot_status", "failed"},
	{"service_snapshot_trigger_size", "invalid"},
	{"service_snapshot_triggers", "failed"},
	{"service_trust_directory", "case_enabled"},
	{"service_trust_directory", "case_failed"},
	{"service_trust_directory", "final_failed"},
	{"service_trust_directory", "final_mismatch"},
	{"service_trust_directory", "final_size"},
	{"service_trust_directory", "info_failed"},
	{"service_trust_directory", "open_failed"},
	{"service_trust_directory", "reparse"},
	{"service_trust_directory", "type_invalid"},
	{"service_trust_drive", "unsafe_path"},
	{"service_trust_duplicate", "unsafe_path"},
	{"service_trust_file", "final_failed"},
	{"service_trust_file", "final_mismatch"},
	{"service_trust_file", "final_size"},
	{"service_trust_file", "info_failed"},
	{"service_trust_file", "open_failed"},
	{"service_trust_file", "reparse"},
	{"service_trust_file", "type_invalid"},
	{"service_trust_file_handle", "unsafe_path"},
	{"service_trust_file_links", "unsafe_path"},
	{"service_trust_hash_read", "failed"},
	{"service_trust_layout", "failed"},
	{"service_trust_layout", "mismatch"},
	{"service_trust_root", "case_enabled"},
	{"service_trust_root", "case_failed"},
	{"service_trust_root", "final_failed"},
	{"service_trust_root", "final_mismatch"},
	{"service_trust_root", "final_size"},
	{"service_trust_root", "info_failed"},
	{"service_trust_root", "open_failed"},
	{"service_trust_root", "reparse"},
	{"service_trust_root", "type_invalid"},
	{"service_apply_stop_control", "failed"},
	{"service_apply_delete", "failed"},
	{"service_apply_stop_inspect", "failed"},
	{"service_removal_context", "interrupted"},
	{"service_removal_layout", "failed"},
	{"service_removal_receipt", "mismatch"},
	{"service_removal_open", "failed"},
	{"service_removal_reader", "missing"},
	{"service_removal_snapshot", "failed"},
	{"service_removal_binding", "mismatch"},
	{"service_removal_state", "not_stopped"},
	{"service_removal_close", "failed"},
	{"service_removal_executable", "failed"},
	{"service_removal_hash", "changed"},
}

// SetupDiagnosticPairs returns a copy of the finite setup vocabulary in stable
// codec order. Mutating the returned slice cannot affect classification.
func SetupDiagnosticPairs() [][2]string {
	return append([][2]string(nil), setupDiagnosticPairs[:]...)
}

// SetupDiagnosticValid accepts only exact, explicitly registered pairs.
func SetupDiagnosticValid(stage, category string) bool {
	for _, pair := range setupDiagnosticPairs {
		if pair == [2]string{stage, category} {
			return true
		}
	}
	return false
}

type setupDiagnosticError struct {
	stage, category string
	cause           error
}

// This wrapper deliberately preserves the existing public Error string and
// cause chain. Only SetupDiagnostic is suitable for a public child report.
func (e *setupDiagnosticError) Error() string { return e.cause.Error() }

// Preserve ordinary error rendering while preventing reflection formats from
// exposing the wrapper or the cause's private object fields. This is not the
// public report serializer; SetupDiagnostic is the finite metadata boundary.
func (e *setupDiagnosticError) Format(s fmt.State, verb rune) {
	formatDiagnostic(s, verb, e.Error())
}
func (e *setupDiagnosticError) GoString() string { return e.Error() }
func (e *setupDiagnosticError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func setupStageError(stage, category string, cause error) error {
	if cause == nil {
		return nil
	}
	// Preserve a more specific native/inner failure site through plan, install
	// and ownership checks. Never derive metadata from Error or a native code.
	if innerStage, innerCategory := SetupDiagnostic(cause); innerStage != "unknown" {
		stage, category = innerStage, innerCategory
	}
	if !SetupDiagnosticValid(stage, category) {
		stage, category = "unknown", "unknown"
	}
	return &setupDiagnosticError{stage: stage, category: category, cause: cause}
}

// SetupDiagnostic extracts only metadata stamped inside this package. It never
// calls Error, Format, Is or As and bounds wrapped/joined/cyclic chains. Unknown,
// malformed and panicking chains fail closed. Nil has no diagnostic and returns
// the same unknown pair; callers must use their original error to test success.
func SetupDiagnostic(err error) (stage, category string) {
	stage, category = "unknown", "unknown"
	defer func() {
		if recover() != nil {
			stage, category = "unknown", "unknown"
		}
	}()
	pending := []error{err}
	for budget := 64; len(pending) > 0 && budget > 0; budget-- {
		current := pending[0]
		pending = pending[1:]
		if current == nil {
			continue
		}
		if marked, ok := current.(*setupDiagnosticError); ok {
			if marked != nil && SetupDiagnosticValid(marked.stage, marked.category) {
				return marked.stage, marked.category
			}
			return "unknown", "unknown"
		}
		switch wrapped := current.(type) {
		case interface{ Unwrap() error }:
			pending = append(pending, wrapped.Unwrap())
		case interface{ Unwrap() []error }:
			children := wrapped.Unwrap()
			capacity := budget - 1 - len(pending)
			if capacity > len(children) {
				capacity = len(children)
			}
			if capacity > 0 {
				pending = append(pending, children[:capacity]...)
			}
		}
	}
	return stage, category
}
