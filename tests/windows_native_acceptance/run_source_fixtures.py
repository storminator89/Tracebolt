#!/usr/bin/env python3
"""Source, synthetic-clock and injected shutdown checks; never native proof."""
import os
from pathlib import Path
import sys

# -I intentionally removes the script directory from sys.path. Add only the
# fixed, reviewed sibling directory; never an input-selected Python module path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_acceptance as gate

PACKAGES = (
    "./internal/windowsacceptance/profile",
    "./internal/windowsacceptance/fixture", "./internal/windowsacceptance/native",
    "./internal/windowsacceptance/gate", "./cmd/windows-native-acceptance",
    "./internal/windowsservice", "./cmd/windows-service",
)
REQUIRED = {
    ("localrmm/internal/windowsacceptance/profile", "TestExtensionObservationNeverClaimsFreshOrchestration"),
    ("localrmm/internal/windowsacceptance/fixture", "TestExpandedPeerLoopbackProof"),
    ("localrmm/cmd/windows-native-acceptance", "TestExpandedCLIRequiresFourFreshFlags"),
    ("localrmm/internal/windowsacceptance/profile", "TestExtensionObservationFiniteTruth"),
    ("localrmm/internal/windowsacceptance/fixture", "TestExpandedShapeEvidenceAndFallback"),
    ("localrmm/internal/windowsacceptance/fixture", "TestExpandedPartialCombinationsRejected"),
    ("localrmm/internal/windowsacceptance/fixture", "TestExpandedIndependentCaptureFences"),
    ("localrmm/internal/windowsacceptance/fixture", "TestExpandedQualityCountsAndFirstSample"),
    ("localrmm/internal/windowsacceptance/fixture", "TestExpandedExactDuplicateBeforeCaptureAge"),
    ("localrmm/internal/windowsacceptance/fixture", "TestExpandedMalformedRealDecodersFailClosed"),
    ("localrmm/internal/windowsacceptance/native", "TestCapabilityConfigurationRequiresExactExpandedAuthority"),
    ("localrmm/internal/windowsacceptance/native", "TestCapabilitySiblingSchemasAndExactConsent"),
    ("localrmm/internal/windowsacceptance/native", "TestEveryMutatorBindsExpandedAuthority"),
    ("localrmm/cmd/windows-native-acceptance", "TestExpandedControllerRequiresStoppedGrantAndUsefulV5"),
    ("localrmm/cmd/windows-native-acceptance", "TestExpandedControllerCannotFallbackToBasePeer"),
    ("localrmm/internal/windowsacceptance/gate", "TestExpandedRequiresEveryFreshScopeAndInventory"),
    ("localrmm/internal/windowsacceptance/gate", "TestExpandedReportCannotReuseBaseEvidence"),
    ("localrmm/cmd/windows-native-acceptance", "TestControllerFinalObservationFollowsPeerClosure"),
    ("localrmm/cmd/windows-native-acceptance", "TestControllerLateInventoryQualityKeepsFiniteFailure"),
    ("localrmm/internal/windowsacceptance/profile", "TestFiniteSelection"),
    ("localrmm/internal/windowsacceptance/profile", "TestFiniteObservationQualities"),
    ("localrmm/internal/windowsacceptance/fixture", "TestSelectedProofAndRouteConfusion"),
    ("localrmm/internal/windowsacceptance/fixture", "TestInventoryTLSRejectsSignedFallback"),
    ("localrmm/internal/windowsacceptance/fixture", "TestSelectedBootstrapLifecycleAndInventory"),
    ("localrmm/internal/windowsacceptance/fixture", "TestInventoryHTTPProofsAndOriginalReceipt"),
    ("localrmm/internal/windowsacceptance/fixture", "TestInventoryGenerationAndCaptureFences"),
    ("localrmm/internal/windowsacceptance/fixture", "TestInventoryQualityEvidenceRemainsHonest"),
    ("localrmm/internal/windowsacceptance/fixture", "TestInventoryHTTPCurrentAuthorityRechecked"),
    ("localrmm/internal/windowsacceptance/gate", "TestProfileScopeRequiresExactSeparateApprovals"),
    ("localrmm/cmd/windows-native-acceptance", "TestControllerInventoryTLSAndExplicitHTTPUseExactGrant"),
    ("localrmm/internal/windowsacceptance/gate", "TestManualSourceAuthorityDefaultsDeny"),
    ("localrmm/internal/windowsacceptance/gate", "TestGrantIsBoundedAndRevocable"),
    ("localrmm/cmd/windows-native-acceptance", "TestManualAcceptanceCLIRejectsBeforeExecution"),
    ("localrmm/cmd/windows-native-acceptance", "TestAutomaticEventCannotRunApprovedLookingFlags"),
    ("localrmm/internal/windowsacceptance/fixture", "TestSyntheticOriginalPendingDeadlineAndCertificateRoles"),
    ("localrmm/internal/windowsacceptance/fixture", "TestSyntheticNewSequenceRequiresStrictlyLaterTimesLikeProductionStore"),
    ("localrmm/cmd/windows-service", "TestPendingTimeoutContinuesWithinOriginalThirtyMinuteAuthority"),
    ("localrmm/cmd/windows-service", "TestPendingOriginalDeadlineIsNeverExtended"),
    ("localrmm/cmd/windows-service", "TestPendingCancellationDuringBackoffIsGraceful"),
    ("localrmm/cmd/windows-service", "TestConcurrentStopDoesNotHidePendingAuthorityFailures"),
    ("localrmm/cmd/windows-service", "TestPendingExpiryDuringBackoffStopsWithoutSecondResume"),
    ("localrmm/internal/windowsservice", "TestRuntimeShutdownDuringInitialization"),
    ("localrmm/internal/windowsacceptance/native", "TestOSAncestorsRequireTrustedPathsWithoutTokenClaims"),
    ("localrmm/internal/windowsacceptance/native", "TestNativeTokenPolicy"),
    ("localrmm/internal/windowsacceptance/native", "TestProbeAcceptsOnlyActualAccessDenied"),
    ("localrmm/internal/windowsacceptance/native", "TestOrderlyAcceptanceStopRejectsNativeFailureExitCodes"),
}


def validate_events(raw: bytes) -> None:
    gate.require(type(raw) is bytes and 0 < len(raw) <= 32 * 1024 * 1024)
    passed, skipped, packages = set(), set(), set()
    for line in raw.splitlines():
        event = gate.strict_json(line, 1024 * 1024)
        gate.require(type(event) is dict)
        pair = (event.get("Package"), event.get("Test"))
        if pair in REQUIRED and event.get("Action") == "pass":
            passed.add(pair)
        if pair in REQUIRED and event.get("Action") == "skip":
            skipped.add(pair)
        gate.require(event.get("Action") != "fail")
        if event.get("Action") == "pass" and "Test" not in event:
            packages.add(event.get("Package"))
    gate.require(passed == REQUIRED and not skipped)
    gate.require(packages == {"localrmm/" + name[2:] for name in PACKAGES})


def main() -> int:
    try:
        env = dict(os.environ)
        source = gate.authorize(env)
        child = gate.child_environment(env)
        gate.verify_checkout(child, source, gate.ROOT)
        gate.verify_go(child, gate.ROOT)
        raw = gate.successful(["go", "test", "-mod=readonly", "-json", "-count=1", "-timeout=180s",
                               "-buildvcs=false", *PACKAGES], child, gate.ROOT, 600,
                              32 * 1024 * 1024)
        validate_events(raw)
        print("PASS: source, synthetic-clock expiry and injected shutdown-handler fixtures; no native acceptance proof, OS shutdown or reboot.")
        return 0
    except Exception:
        print("FAIL: source fixtures incomplete or invalid; raw output withheld; no native acceptance proof.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
