#!/usr/bin/env python3
"""Explicit current21 Server2025 x64 adapter; exact native-subset tree pinned.

The shared publisher retains its historical default profile. This entry point
selects fixed reviewed contracts before any I/O; no environment or CLI input can
select another schema, gate, artifact namespace or accepted source tree.
"""
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("_current_windows_publisher", Path(__file__).with_name("publish-windows-prerelease.py"))
publisher = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(publisher)
_spec = importlib.util.spec_from_file_location("_current_windows_gate", ROOT / "tests/windows_native_acceptance/run_current_setup_gui.py")
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

# Exact source 62435ef7e605df0b102e030bf1d68cb255829a90, accepted by
# first-attempt current native run 38303755541 (three-case packaged GUI subset).
# This later publisher revision is distinct; never rebuild the accepted bytes.
ACCEPTED_SOURCE_TREE = "b66e8a8eaa8cfdb0a5b7108254c930ae244b6763"
publisher.ACCEPTED_SOURCE_TREE = ACCEPTED_SOURCE_TREE
publisher.gate = gate
publisher.NATIVE_WORKFLOW = gate.provenance.WORKFLOW_PATH
publisher.PUBLISH_WORKFLOW = ".github/workflows/windows-current-prerelease.yml"
publisher.AGGREGATE_JOB = gate.provenance.AGGREGATE_NAME
publisher.ARTIFACT_PREFIX = "windows-current-setup-"
publisher.EVIDENCE_SCHEMA = "tracebolt.windows-current-setup-native-subset.v1"
publisher.EVIDENCE_STATUS = "three_case_current_packaged_gui_subset"
publisher.EVIDENCE_DISTRIBUTION = "unsigned-current-source-candidate-native-subset"
publisher.PLAN_SCHEMA = "tracebolt.windows-current-prerelease-plan.v1"
publisher.MANIFEST_SCHEMA = "tracebolt.windows-current-prerelease.v1"
publisher.RELEASE_DISTRIBUTION = "unsigned-windows-server2025-x64-current21-read-admin-preview-native-subset"
publisher.REQUIRE_REPORT_TREE = True
publisher.GUIDE_SUBDIRECTORY = ""
publisher.ASSETS = gate.PUBLIC_FILES | {gate.AGGREGATE_REPORT, publisher.RELEASE_MANIFEST} | publisher.GUIDES
publisher.BOUNDS = {**gate.provenance.PUBLIC_BOUNDS, gate.REPORT_NAME: 32 << 10,
    gate.AGGREGATE_REPORT: 128 << 10, publisher.RELEASE_MANIFEST: 64 << 10,
    **{name: 64 << 10 for name in publisher.GUIDES}}


def description(request):
    return ("Unsigned Windows Server 2025 x64 current21 Read admin preview; three-case packaged GUI subset. "
        "Exact unchanged Setup/service bytes from source " + request["source"] +
        ", tested in https://github.com/" + publisher.REPOSITORY + "/actions/runs/" + request["acceptanceRunID"] +
        ". Download " + gate.SETUP_NAME + "; read windows-prerelease-install.md and windows-prerelease-changelog.md. "
        "SHA256SUMS covers the unchanged six-file package; release-manifest.json binds the release tag, evidence, "
        "instructions and exact original artifact IDs/hashes. Embedded candidate names/version remain unchanged. "
        "No Authenticode trust, Windows 11, real Linux-manager/browser interoperability, provider completeness, "
        "renewal cutover, reboot, human invitation/UAC, ARM64, verified VM disposal, optional MSI/WUA/service-control "
        "or user-helper acceptance is claimed. Optional-state absence checks never establish optional action acceptance. "
        "Service removal retains files, keys and state. No-overwrite is publisher policy, not GitHub platform immutability.")


publisher.description = description

if __name__ == "__main__":
    try:
        publisher.main()
    except Exception:
        print("Current Windows prerelease stopped. The accepted tree must be reviewed and pinned; original artifacts must remain available. No automatic retry or cleanup was attempted.", file=sys.stderr)
        sys.exit(1)
