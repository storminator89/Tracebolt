"""Project finite v3 test diagnostics from private Go JSON; never print raw output."""
import json
import os
import re
import stat
import sys

MAX_FILE = 32 * 1024 * 1024
MAX_LINE = 256 * 1024
MAX_MARKERS = 64
PACKAGE = "localrmm/cmd/lan-manager"
ROOT = "TestCompleteMVPPendingApprovalNativeRestart"
PROFILES = {ROOT: "root", ROOT + "/tls": "tls", ROOT + "/http-test": "http-test"}
PREFIX = re.compile(r"    complete_mvp_process_test\.go:[1-9][0-9]{0,5}: (.*)\n")
REASONS = r"none|source_missing|permission_denied|not_supported|timeout|invalid_source|read_failed|item_limit|byte_limit|collector_busy|not_collected"
STATUS = re.compile(r"native report: sequence=[0-9]{1,19} systemSequence=[0-9]{1,19} packageStatus=(acknowledged|failure_acknowledged|not_due|pending_retained) servicesCoverage=(complete|failed) servicesReason=(" + REASONS + r") socketsCoverage=(complete|failed) socketsReason=(" + REASONS + r")")
PACKAGE_FAILURE = re.compile(r"native complete package attempt: failure=(source_missing|source_invalid|source_changed|resource_limit|collection_failed); no complete package count claimed")
# Exact immutable source payloads map to constants; input text is never emitted.
FAILURES = {
    "complete_native_event_stream_closed": {"category": "complete_native_event_stream_closed", "stage": "sender"},
    "complete_native_outcome_retryable": {"category": "complete_native_outcome_retryable", "stage": "sender"},
    "complete_native_outcome_configuration": {"category": "complete_native_outcome_configuration", "stage": "sender"},
    "complete_native_outcome_state": {"category": "complete_native_outcome_state", "stage": "sender"},
    "complete_native_outcome_revoked": {"category": "complete_native_outcome_revoked", "stage": "sender"},
    "complete_native_outcome_invalid": {"category": "complete_native_outcome_invalid", "stage": "sender"},
    "complete_native_metric_sequence_missing": {"category": "complete_native_metric_sequence_missing", "stage": "sender"},
    "complete_native_system_pending_retained": {"category": "complete_native_system_pending_retained", "stage": "sender"},
    "complete_native_system_status_missing": {"category": "complete_native_system_status_missing", "stage": "sender"},
    "complete_native_system_status_invalid": {"category": "complete_native_system_status_invalid", "stage": "sender"},
    "complete_native_system_sequence_missing": {"category": "complete_native_system_sequence_missing", "stage": "sender"},
    "complete acknowledged report did not advance source times and domains": {
        "category": "complete_acknowledged_report_did_not_advance_source_times_and_domains",
        "stage": "observation"
    },
    "complete activated bound v5 handoff": {
        "category": "complete_activated_bound_v5_handoff",
        "stage": "activation"
    },
    "complete activation and sender handoff": {
        "category": "complete_activation_and_sender_handoff",
        "stage": "activation"
    },
    "complete activation deadline": {
        "category": "complete_activation_deadline",
        "stage": "activation"
    },
    "complete actual device observation missing": {
        "category": "complete_actual_device_observation_missing",
        "stage": "observation"
    },
    "complete administrator approval": {
        "category": "complete_administrator_approval",
        "stage": "activation"
    },
    "complete collection handoff existed before approval": {
        "category": "complete_collection_handoff_existed_before_approval",
        "stage": "pending"
    },
    "complete committed pending claim": {
        "category": "complete_committed_pending_claim",
        "stage": "pending"
    },
    "complete enrollment fixture configuration": {
        "category": "complete_enrollment_fixture_configuration",
        "stage": "setup"
    },
    "complete enrollment fixture profile load": {
        "category": "complete_enrollment_fixture_profile_load",
        "stage": "setup"
    },
    "complete enrollment fixture profile write": {
        "category": "complete_enrollment_fixture_profile_write",
        "stage": "setup"
    },
    "complete exact public bootstrap digest": {
        "category": "complete_exact_public_bootstrap_digest",
        "stage": "bootstrap"
    },
    "complete failed package source fabricated completion": {
        "category": "complete_failed_package_source_fabricated_completion",
        "stage": "observation"
    },
    "complete first process changed enrollment identity": {
        "category": "complete_first_process_changed_enrollment_identity",
        "stage": "continuity"
    },
    "complete first process counters not durable": {
        "category": "complete_first_process_counters_not_durable",
        "stage": "continuity"
    },
    "complete fresh handoff did not start with three unused domains": {
        "category": "complete_fresh_handoff_did_not_start_with_three_unused_domains",
        "stage": "activation"
    },
    "complete fresh-profile acknowledgement advertisement": {
        "category": "complete_fresh_profile_acknowledgement_advertisement",
        "stage": "invitation"
    },
    "complete handoff lacks a sequence domain": {
        "category": "complete_handoff_lacks_a_sequence_domain",
        "stage": "activation"
    },
    "complete identity artifact unavailable": {
        "category": "complete_identity_artifact_unavailable",
        "stage": "continuity"
    },
    "complete invitation admitted without acknowledgement": {
        "category": "complete_invitation_admitted_without_acknowledgement",
        "stage": "invitation"
    },
    "complete invitation creation": {
        "category": "complete_invitation_creation",
        "stage": "invitation"
    },
    "complete last-complete metadata invalid": {
        "category": "complete_last_complete_metadata_invalid",
        "stage": "observation"
    },
    "complete manager fixture configuration": {
        "category": "complete_manager_fixture_configuration",
        "stage": "setup"
    },
    "complete manifest was not atomically completed": {
        "category": "complete_manifest_was_not_atomically_completed",
        "stage": "observation"
    },
    "complete native fixture build failed lan-agent": {
        "category": "complete_native_fixture_build_failed_lan_agent",
        "stage": "build"
    },
    "complete native fixture build failed lan-manager": {
        "category": "complete_native_fixture_build_failed_lan_manager",
        "stage": "build"
    },
    "complete native manager readiness": {
        "category": "complete_native_manager_readiness",
        "stage": "setup"
    },
    "complete native manager start": {
        "category": "complete_native_manager_start",
        "stage": "setup"
    },
    "complete native package status contract": {
        "category": "complete_native_package_status_contract",
        "stage": "sender"
    },
    "complete native report deadline": {
        "category": "complete_native_report_deadline",
        "stage": "sender"
    },
    "complete native report not acknowledged": {
        "category": "complete_native_report_not_acknowledged",
        "stage": "sender"
    },
    "complete native sender start": {
        "category": "complete_native_sender_start",
        "stage": "sender"
    },
    "complete operational provenance or fabricated assessment": {
        "category": "complete_operational_provenance_or_fabricated_assessment",
        "stage": "observation"
    },
    "complete operator explicit root": {
        "category": "complete_operator_explicit_root",
        "stage": "setup"
    },
    "complete operator login": {
        "category": "complete_operator_login",
        "stage": "operator"
    },
    "complete operator read": {
        "category": "complete_operator_read",
        "stage": "operator"
    },
    "complete operator read contract": {
        "category": "complete_operator_read_contract",
        "stage": "operator"
    },
    "complete operator request": {
        "category": "complete_operator_request",
        "stage": "operator"
    },
    "complete operator response": {
        "category": "complete_operator_response",
        "stage": "operator"
    },
    "complete package acknowledgement not visible": {
        "category": "complete_package_acknowledgement_not_visible",
        "stage": "observation"
    },
    "complete package failure acknowledgement not visible": {
        "category": "complete_package_failure_acknowledgement_not_visible",
        "stage": "observation"
    },
    "complete package failure not fixed metadata": {
        "category": "complete_package_failure_not_fixed_metadata",
        "stage": "observation"
    },
    "complete package metadata unavailable": {
        "category": "complete_package_metadata_unavailable",
        "stage": "observation"
    },
    "complete package not-due without prior outcome": {
        "category": "complete_package_not_due_without_prior_outcome",
        "stage": "observation"
    },
    "complete package pending status contradicted by view": {
        "category": "complete_package_pending_status_contradicted_by_view",
        "stage": "observation"
    },
    "complete pending claim fabricated a device observation": {
        "category": "complete_pending_claim_fabricated_a_device_observation",
        "stage": "pending"
    },
    "complete pending public comparison": {
        "category": "complete_pending_public_comparison",
        "stage": "pending"
    },
    "complete pending resume did not poll": {
        "category": "complete_pending_resume_did_not_poll",
        "stage": "pending"
    },
    "complete pending resume returned before approval": {
        "category": "complete_pending_resume_returned_before_approval",
        "stage": "pending"
    },
    "complete public bootstrap changed": {
        "category": "complete_public_bootstrap_changed",
        "stage": "bootstrap"
    },
    "complete public bootstrap fetch": {
        "category": "complete_public_bootstrap_fetch",
        "stage": "bootstrap"
    },
    "complete public bootstrap transport": {
        "category": "complete_public_bootstrap_transport",
        "stage": "bootstrap"
    },
    "complete restart changed identity or recaptured the package generation": {
        "category": "complete_restart_changed_identity_or_recaptured_the_package_generation",
        "stage": "continuity"
    },
    "complete restart created or replaced enrollment": {
        "category": "complete_restart_created_or_replaced_enrollment",
        "stage": "continuity"
    },
    "complete restart did not advance original metric and system domains": {
        "category": "complete_restart_did_not_advance_original_metric_and_system_domains",
        "stage": "continuity"
    },
    "complete sequence ledger unavailable": {
        "category": "complete_sequence_ledger_unavailable",
        "stage": "continuity"
    },
    "complete source last-complete metadata missing": {
        "category": "complete_source_last_complete_metadata_missing",
        "stage": "observation"
    },
    "complete system metadata unavailable": {
        "category": "complete_system_metadata_unavailable",
        "stage": "observation"
    },
    "complete system source metadata invalid": {
        "category": "complete_system_source_metadata_invalid",
        "stage": "observation"
    },
    "complete unavailable source fabricated zero": {
        "category": "complete_unavailable_source_fabricated_zero",
        "stage": "observation"
    },
    "complete_positive_manifest_invalid_or_empty": {
        "category": "complete_positive_manifest_invalid_or_empty",
        "stage": "positive"
    },
    "complete_positive_package_required": {
        "category": "complete_positive_package_required",
        "stage": "positive"
    },
    "complete_positive_requires_four_delivered_samples": {
        "category": "complete_positive_requires_four_delivered_samples",
        "stage": "positive"
    },
    "complete_positive_requires_runtime_opt_in": {
        "category": "complete_positive_requires_runtime_opt_in",
        "stage": "selection"
    },
    "complete_positive_services_required": {
        "category": "complete_positive_services_required",
        "stage": "positive"
    },
    "complete_positive_sockets_required": {
        "category": "complete_positive_sockets_required",
        "stage": "positive"
    },
    "complete_positive_system_unavailable_or_unbound": {
        "category": "complete_positive_system_unavailable_or_unbound",
        "stage": "positive"
    },
    "complete_positive_ubuntu2404_required": {
        "category": "complete_positive_ubuntu2404_required",
        "stage": "positive"
    },
    "complete_runtime_invalid_opt_in": {
        "category": "complete_runtime_invalid_opt_in",
        "stage": "selection"
    },
    "complete_runtime_requires_nonprivileged_execution": {
        "category": "complete_runtime_requires_nonprivileged_execution",
        "stage": "selection"
    },
    "fixture process cleanup unresolved after kill": {
        "category": "fixture_process_cleanup_unresolved_after_kill",
        "stage": "cleanup"
    },
    "fixture process did not stop cleanly": {
        "category": "fixture_process_did_not_stop_cleanly",
        "stage": "cleanup"
    },
    "fixture process shutdown deadline reached": {
        "category": "fixture_process_shutdown_deadline_reached",
        "stage": "cleanup"
    }
}

# Exact endpoint-extension failures retain the same closed diagnostic projection.
FAILURES.update({
    "complete_endpoint_addresses_required": {"category": "complete_endpoint_addresses_required", "stage": "endpoint_identity"},
    "complete_endpoint_collected_before_sender": {"category": "complete_endpoint_collected_before_sender", "stage": "endpoint_identity"},
    "complete_endpoint_consent_changed_existing_state": {"category": "complete_endpoint_consent_changed_existing_state", "stage": "endpoint_identity"},
    "complete_endpoint_consent_cli_contract": {"category": "complete_endpoint_consent_cli_contract", "stage": "endpoint_identity"},
    "complete_endpoint_consent_cli_failed": {"category": "complete_endpoint_consent_cli_failed", "stage": "endpoint_identity"},
    "complete_endpoint_consent_collected_before_sender": {"category": "complete_endpoint_consent_collected_before_sender", "stage": "endpoint_identity"},
    "complete_endpoint_consent_sidecar_not_absent": {"category": "complete_endpoint_consent_sidecar_not_absent", "stage": "endpoint_identity"},
    "complete_endpoint_disabled_restart_changed_identity_or_package_domain": {"category": "complete_endpoint_disabled_restart_changed_identity_or_package_domain", "stage": "endpoint_identity"},
    "complete_endpoint_disabled_restart_refreshed_or_replaced_metadata": {"category": "complete_endpoint_disabled_restart_refreshed_or_replaced_metadata", "stage": "endpoint_identity"},
    "complete_endpoint_fixture_generation": {"category": "complete_endpoint_fixture_generation", "stage": "endpoint_identity"},
    "complete_endpoint_hostname_required": {"category": "complete_endpoint_hostname_required", "stage": "endpoint_identity"},
    "complete_endpoint_interfaces_required": {"category": "complete_endpoint_interfaces_required", "stage": "endpoint_identity"},
    "complete_endpoint_invalid_consent_test_mode": {"category": "complete_endpoint_invalid_consent_test_mode", "stage": "endpoint_identity"},
    "complete_endpoint_invalid_evidence_stage": {"category": "complete_endpoint_invalid_evidence_stage", "stage": "endpoint_identity"},
    "complete_endpoint_invalid_fixture_accepted_or_evidence_not_fixed": {"category": "complete_endpoint_invalid_fixture_accepted_or_evidence_not_fixed", "stage": "endpoint_identity"},
    "complete_endpoint_invalid_opt_in": {"category": "complete_endpoint_invalid_opt_in", "stage": "endpoint_identity"},
    "complete_endpoint_original_age_stale_fixture_rejected": {"category": "complete_endpoint_original_age_stale_fixture_rejected", "stage": "endpoint_identity"},
    "complete_endpoint_protected_state_unavailable": {"category": "complete_endpoint_protected_state_unavailable", "stage": "endpoint_identity"},
    "complete_endpoint_refreshed_fixture_accepted": {"category": "complete_endpoint_refreshed_fixture_accepted", "stage": "endpoint_identity"},
    "complete_endpoint_requires_group_clean_service_identity": {"category": "complete_endpoint_requires_group_clean_service_identity", "stage": "endpoint_identity"},
    "complete_endpoint_requires_runtime_and_positive_opt_ins": {"category": "complete_endpoint_requires_runtime_and_positive_opt_ins", "stage": "endpoint_identity"},
    "complete_endpoint_restart_did_not_advance_generation_time_and_sequence": {"category": "complete_endpoint_restart_did_not_advance_generation_time_and_sequence", "stage": "endpoint_identity"},
    "complete_endpoint_restart_fixture_contract": {"category": "complete_endpoint_restart_fixture_contract", "stage": "endpoint_identity"},
    "complete_endpoint_retained_fixture_rejected": {"category": "complete_endpoint_retained_fixture_rejected", "stage": "endpoint_identity"},
    "complete_endpoint_selection_contract_changed": {"category": "complete_endpoint_selection_contract_changed", "stage": "endpoint_identity"},
    "complete_endpoint_snapshot_invalid_or_unbound": {"category": "complete_endpoint_snapshot_invalid_or_unbound", "stage": "endpoint_identity"},
    "complete_endpoint_valid_fixture_rejected": {"category": "complete_endpoint_valid_fixture_rejected", "stage": "endpoint_identity"},
    "complete_endpoint_view_unavailable_or_unbound": {"category": "complete_endpoint_view_unavailable_or_unbound", "stage": "endpoint_identity"},
})


# Exact source-owned overview test failures; no raw marker or inventory values.
FAILURES.update({
    'complete_overview_bad_metadata_accepted_or_leaked': {"category": 'complete_overview_bad_metadata_accepted_or_leaked', "stage": "complete_overview"},
    'complete_overview_bad_page_accepted': {"category": 'complete_overview_bad_page_accepted', "stage": "complete_overview"},
    'complete_overview_bad_rows_accepted': {"category": 'complete_overview_bad_rows_accepted', "stage": "complete_overview"},
    'complete_overview_changed_existing_gate_selection': {"category": 'complete_overview_changed_existing_gate_selection', "stage": "complete_overview"},
    'complete_overview_collected_before_sender': {"category": 'complete_overview_collected_before_sender', "stage": "complete_overview"},
    'complete_overview_consent_changed_endpoint_consent': {"category": 'complete_overview_consent_changed_endpoint_consent', "stage": "complete_overview"},
    'complete_overview_consent_changed_existing_state': {"category": 'complete_overview_consent_changed_existing_state', "stage": "complete_overview"},
    'complete_overview_consent_cli_contract': {"category": 'complete_overview_consent_cli_contract', "stage": "complete_overview"},
    'complete_overview_consent_cli_failed': {"category": 'complete_overview_consent_cli_failed', "stage": "complete_overview"},
    'complete_overview_consent_sidecar_not_absent': {"category": 'complete_overview_consent_sidecar_not_absent', "stage": "complete_overview"},
    'complete_overview_delivered_metadata_invalid': {"category": 'complete_overview_delivered_metadata_invalid', "stage": "complete_overview"},
    'complete_overview_disable_changed_consumed_floor': {"category": 'complete_overview_disable_changed_consumed_floor', "stage": "complete_overview"},
    'complete_overview_domain_contract': {"category": 'complete_overview_domain_contract', "stage": "complete_overview"},
    'complete_overview_domain_missing': {"category": 'complete_overview_domain_missing', "stage": "complete_overview"},
    'complete_overview_enable_collected_before_sender': {"category": 'complete_overview_enable_collected_before_sender', "stage": "complete_overview"},
    'complete_overview_expected_fresh_domains': {"category": 'complete_overview_expected_fresh_domains', "stage": "complete_overview"},
    'complete_overview_fixture_build': {"category": 'complete_overview_fixture_build', "stage": "complete_overview"},
    'complete_overview_full_rows_manifest_mismatch': {"category": 'complete_overview_full_rows_manifest_mismatch', "stage": "complete_overview"},
    'complete_overview_invalid_consent_mode': {"category": 'complete_overview_invalid_consent_mode', "stage": "complete_overview"},
    'complete_overview_invalid_opt_in': {"category": 'complete_overview_invalid_opt_in', "stage": "complete_overview"},
    'complete_overview_invalid_retained_stage': {"category": 'complete_overview_invalid_retained_stage', "stage": "complete_overview"},
    'complete_overview_opt_in_guard_failed': {"category": 'complete_overview_opt_in_guard_failed', "stage": "complete_overview"},
    'complete_overview_opt_in_not_selected': {"category": 'complete_overview_opt_in_not_selected', "stage": "complete_overview"},
    'complete_overview_original_age_rejected': {"category": 'complete_overview_original_age_rejected', "stage": "complete_overview"},
    'complete_overview_page_bytes_exceeded': {"category": 'complete_overview_page_bytes_exceeded', "stage": "complete_overview"},
    'complete_overview_page_contract': {"category": 'complete_overview_page_contract', "stage": "complete_overview"},
    'complete_overview_page_count_mismatch': {"category": 'complete_overview_page_count_mismatch', "stage": "complete_overview"},
    'complete_overview_page_cursor_repeated': {"category": 'complete_overview_page_cursor_repeated', "stage": "complete_overview"},
    'complete_overview_page_metadata_invalid': {"category": 'complete_overview_page_metadata_invalid', "stage": "complete_overview"},
    'complete_overview_page_row_bound': {"category": 'complete_overview_page_row_bound', "stage": "complete_overview"},
    'complete_overview_positive_capture_required': {"category": 'complete_overview_positive_capture_required', "stage": "complete_overview"},
    'complete_overview_precollection_view_contract': {"category": 'complete_overview_precollection_view_contract', "stage": "complete_overview"},
    'complete_overview_preview_created_domain': {"category": 'complete_overview_preview_created_domain', "stage": "complete_overview"},
    'complete_overview_probe_decode': {"category": 'complete_overview_probe_decode', "stage": "complete_overview"},
    'complete_overview_probe_path': {"category": 'complete_overview_probe_path', "stage": "complete_overview"},
    'complete_overview_refreshed_or_late_restart_accepted': {"category": 'complete_overview_refreshed_or_late_restart_accepted', "stage": "complete_overview"},
    'complete_overview_requires_existing_endpoint_consent': {"category": 'complete_overview_requires_existing_endpoint_consent', "stage": "complete_overview"},
    'complete_overview_requires_runtime_positive_endpoint_opt_ins': {"category": 'complete_overview_requires_runtime_positive_endpoint_opt_ins', "stage": "complete_overview"},
    'complete_overview_restart_must_be_within_capture_interval': {"category": 'complete_overview_restart_must_be_within_capture_interval', "stage": "complete_overview"},
    'complete_overview_restart_refreshed_or_replaced_generation': {"category": 'complete_overview_restart_refreshed_or_replaced_generation', "stage": "complete_overview"},
    'complete_overview_valid_evidence_rejected': {"category": 'complete_overview_valid_evidence_rejected', "stage": "complete_overview"},
    'complete_overview_valid_page_rejected': {"category": 'complete_overview_valid_page_rejected', "stage": "complete_overview"},
})


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def reject_constant(_value):
    raise ValueError("nonfinite JSON")


def project(event):
    if not isinstance(event, dict):
        raise ValueError("invalid event")
    if event.get("Package") != PACKAGE or event.get("Action") != "output":
        return None
    test = event.get("Test")
    if not isinstance(test, str) or test not in PROFILES:
        return None
    output = event.get("Output")
    if not isinstance(output, str):
        return None
    match = PREFIX.fullmatch(output)
    if match is None:
        return None
    payload = match.group(1)
    profile = PROFILES[test]
    if payload in FAILURES:
        return {"profile": profile, "stage": FAILURES[payload]["stage"], "category": FAILURES[payload]["category"]}
    match = STATUS.fullmatch(payload)
    if match is not None:
        return {"profile": profile, "stage": "observation", "category": "native_report", "packageStatus": match.group(1), "servicesCoverage": match.group(2), "servicesReason": match.group(3), "socketsCoverage": match.group(4), "socketsReason": match.group(5)}
    match = PACKAGE_FAILURE.fullmatch(payload)
    if match is not None:
        return {"profile": profile, "stage": "observation", "category": "package_failure", "reason": match.group(1)}
    return {"profile": profile, "stage": "unclassified", "category": "unclassified"}


def read_markers(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_FILE:
            raise ValueError("invalid log file")
        markers = []
        total = 0
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while True:
                line = stream.readline(MAX_LINE + 1)
                if not line:
                    break
                total += len(line)
                if len(line) > MAX_LINE or total > MAX_FILE or not line.endswith(b"\n"):
                    raise ValueError("invalid log bounds")
                event = json.loads(line, object_pairs_hook=unique_object, parse_constant=reject_constant)
                marker = project(event)
                if marker is not None and len(markers) < MAX_MARKERS:
                    markers.append(marker)
        return markers
    finally:
        os.close(fd)


def main(argv):
    try:
        if len(argv) != 2:
            raise ValueError("invalid arguments")
        markers = read_markers(argv[1])
    except Exception:
        print('V3_NATIVE_DIAGNOSTIC {"category":"unavailable","profile":"unknown","stage":"diagnostic"}')
        return 1
    if not markers:
        markers = [{"profile": "unknown", "stage": "unclassified", "category": "unclassified"}]
    for marker in markers:
        print("V3_NATIVE_DIAGNOSTIC " + json.dumps(marker, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
