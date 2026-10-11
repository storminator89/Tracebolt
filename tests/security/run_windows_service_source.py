#!/usr/bin/env python3
"""Pure/injected Windows source gate; never run an installer, service or real console."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

_reporter_spec = importlib.util.spec_from_file_location(
    "windows_source_go_failure", Path(__file__).with_name("report_go_failure.py"))
_reporter = importlib.util.module_from_spec(_reporter_spec)
_reporter_spec.loader.exec_module(_reporter)
project = _reporter.project

PACKAGES = ("./internal/windowsusersoftwarelocal", "./internal/windowspackage", "./internal/windowssetup", "./internal/windowssetupui", "./internal/windowsstate", "./internal/windowsservice", "./internal/windowsconsole",
            "./internal/windowsagentconfig", "./cmd/windows-service", "./internal/windowsvolumes", "./internal/windowsprocessmetrics", "./internal/windowsnetwork", "./internal/windowsmanaged", "./internal/windowshardware", "./internal/windowshardwareworker", "./internal/windowsstorage", "./internal/windowsstorageworker", "./internal/windowssecuritycoverage", "./internal/windowssecuritycoverageworker")
REQUIRED = {
    ("localrmm/internal/windowsservice", "TestObservationDescriptorExtentIgnoresSuccessByteCount"),
    ("localrmm/internal/windowsservice", "TestObservationDescriptorMemoryFixtures"),
    ("localrmm/internal/windowsservice", "TestObservationPublicConfigIsExactMarkerNotMeasuredHash"),
    ("localrmm/internal/windowsservice", "TestObservationSCMAuthorityRejectsUntrustedMutations"),
    ("localrmm/cmd/windows-service", "TestUserSoftwareCLISeparateAcknowledgementAndDisclosure"),
    ("localrmm/cmd/windows-service", "TestUserSoftwareConsentRequiresStoppedOwnedServiceBeforeState"),
    ("localrmm/internal/windowsusersoftwarelocal", "TestConversationRequiresConsentReserveAndSameConnectionNonce"),
    ("localrmm/internal/windowsusersoftwarelocal", "TestEveryUnsubmittedBeginReleasesChallengeAndConsumedReservation"),
    ("localrmm/internal/windowsusersoftwarelocal", "TestFatalIdentityFailureNeverCallsAdmissionOrCleanupHandler"),
    ("localrmm/internal/windowsusersoftwarelocal", "TestOwnStartupPendingThenRunning"),
    ("localrmm/internal/windowssetup", "TestReadAdminV9SoftwareHistoryCannotPromoteEarlierCapabilities"),
    ("localrmm/cmd/windows-service", "TestSoftwareHistoryCLISeparateAcknowledgementAndDisclosure"),
    ("localrmm/cmd/windows-service", "TestSoftwareHistoryConsentRequiresStoppedOwnedServiceBeforeState"),
    ("localrmm/cmd/windows-service", "TestReadAdminV13FreshProfileReceipt11ExactNineteenGrants"),
    ("localrmm/cmd/windows-service", "TestReadAdminV13FreshGrantFailuresAndOriginalSenderGuard"),
    ("localrmm/cmd/windows-service", "TestFreshReadAdminV13ReconcilePinsSoftwareHistoryDigestAndNeverPromotesReceipts"),
    ("localrmm/internal/windowssecuritycoverage", "TestCoverageNativeReadOnlySourceContract"),
    ("localrmm/internal/windowssecuritycoverage", "TestEscapedProductNamesFitBeforeEnvelopeEncoding"),
    ("localrmm/internal/windowssecuritycoverageworker", "TestServeDeniesAbsentOrChangedAuthority"),
    ("localrmm/internal/windowssecuritycoverageworker", "TestIndependentProviderTimeoutKeepsSibling"),
    ("localrmm/cmd/windows-service", "TestReadAdminV8FreshProfileReceipt6ExactFourteenGrants"),
    ("localrmm/internal/windowsstorage", "TestStorageCanonicalBoundsAndMeaning"),
    ("localrmm/internal/windowsstorage", "TestDriveMappingExactRootsSkipsRemoteAndKeepsDenied"),
    ("localrmm/internal/windowsstorageworker", "TestServeDeniesAbsentOrChangedAuthority"),
    ("localrmm/internal/windowsstorageworker", "TestIndependentProviderTimeoutKeepsSiblings"),
    ("localrmm/cmd/windows-service", "TestReadAdminV7FreshProfileReceipt5ExactThirteenGrants"),
    ("localrmm/internal/windowshardware", "TestPowerSentinelsAndNonchargingMidrange"),
    ("localrmm/internal/windowshardware", "TestModelCanonicalBoundsAndSources"),
    ("localrmm/internal/windowshardware", "TestConsentAndIndependentSourceFailures"),
    ("localrmm/internal/windowshardwareworker", "TestServeDeniesAbsentOrChangedAuthority"),
    ("localrmm/internal/windowshardwareworker", "TestIndependentProviderTimeoutKeepsSiblings"),
    ("localrmm/cmd/windows-service", "TestReadAdminFreshProfileUsesDistinctReceiptAndExactElevenGrants"),
    ("localrmm/cmd/windows-service", "TestReadAdminFreshFailuresNeverStartIncompleteAuthority"),
    ("localrmm/cmd/windows-service", "TestReadAdminFreshGrantGuardPinsOriginalRecordedSender"),
    ("localrmm/cmd/windows-service", "TestReadAdminReconsentOneExplicitScopeExtensionPreservesOriginalReceipt"),
    ("localrmm/cmd/windows-service", "TestReadAdminReconsentRejectsMissingAuthorityBeforeCreation"),
    ("localrmm/cmd/windows-service", "TestReadAdminReconsentEveryFailureRetainsPartialEvidenceAndNeverStarts"),
    ("localrmm/cmd/windows-service", "TestReadAdminCLIRequiresExplicitNewAcknowledgementAndFullDisclosure"),
    ("localrmm/internal/windowssetupui", "TestReadAdminFreshProfileKeepsConsentUncheckedAcrossNavigation"),
    ("localrmm/internal/windowssetupui", "TestReadAdminBusyAndRepeatedDetailsCannotExpandConsent"),
    ("localrmm/internal/windowssetup", "TestReadAdminContractCannotUseFiveScopeAdvertisement"),
    ("localrmm/cmd/windows-service", "TestRestartPublicDeadlineBeginsBeforeReceiptAcquisition"),
    ("localrmm/cmd/windows-service", "TestReceiptLeaseChecksElapsedDeadlineAfterSynchronousWork"),
    ("localrmm/cmd/windows-service", "TestGUILeaseCombinedFailureKeepsPrimaryFiniteDiagnostic"),
    ("localrmm/cmd/windows-service", "TestIndependentGUILeasePreservesKnownRemovalFailure"),
    ("localrmm/cmd/windows-service", "TestIndependentSetupCloseKeepsFirstFailureDiagnosis"),
    ("localrmm/cmd/windows-service", "TestIndependentReceiptLeaseCancellationDuringCloseCannotSucceed"),
    ("localrmm/cmd/windows-service", "TestIndependentSetupCancellationDuringCloseCannotSucceed"),
    ("localrmm/internal/windowsservice", "TestRestartOneHandleExactlyOnceAndHistoricalSCMOutcome"),
    ("localrmm/internal/windowsservice", "TestRestartRequiresInitialRunningAndExactReceipt"),
    ("localrmm/internal/windowsservice", "TestRestartRejectsEveryObservedBindingDrift"),
    ("localrmm/internal/windowsservice", "TestRestartHashAndLeaseFailureBeforeEachEffect"),
    ("localrmm/internal/windowsservice", "TestRestartRejectsExecutableHashDrift"),
    ("localrmm/internal/windowsservice", "TestRestartNativeControlErrorsNeverRetryOrCompensate"),
    ("localrmm/internal/windowsservice", "TestRestartCancellationAndLateReturnsFenceLaterEffects"),
    ("localrmm/internal/windowsservice", "TestRestartPollingHasTimeAndObservationBudgets"),
    ("localrmm/internal/windowsservice", "TestRestartRetainsPrimaryAndCloseErrors"),
    ("localrmm/internal/windowsservice", "TestRestartUnexpectedTransitionsAndInvalidInputsFailClosed"),
    ("localrmm/internal/windowsservice", "TestRestartRequiresRunningPIDButNeverClaimsChangedProcess"),
    ("localrmm/cmd/windows-service", "TestRestartCLIExplicitDispatchHoldsLeaseAndEmitsResult"),
    ("localrmm/cmd/windows-service", "TestRestartCLIRejectsImplicitOrExpandedAuthority"),
    ("localrmm/cmd/windows-service", "TestRestartPartialOutputAndReleaseFailureNeverBecomeSuccess"),
    ("localrmm/cmd/windows-service", "TestOtherLifecycleErrorStillDiscardsResult"),
    ("localrmm/cmd/windows-service", "TestReceiptLeaseValidationAndCancellationBeforeEffects"),
    ("localrmm/cmd/windows-service", "TestReceiptLeasePreservesPrimaryAndReleaseErrors"),
    ("localrmm/cmd/windows-service", "TestReceiptLeaseExcludesConcurrentLifecycleAndConsent"),
    ("localrmm/cmd/windows-service", "TestGUIRemovalSharesLeaseAcrossAllEffectsAndRelease"),
    ("localrmm/cmd/windows-service", "TestSetupJournalHeldThroughEffectsAndCloseFailureRetainsResult"),
    ("localrmm/internal/windowsservice", "TestNativeRestartHandleAccessIsMinimal"),
    ("localrmm/cmd/windows-service", "TestSetupWizardPublicBootstrapPreviewAndExplicitTransportConsent"),
    ("localrmm/cmd/windows-service", "TestSetupWizardDeletionPendingIsObservedNotRetried"),
    ("localrmm/cmd/windows-service", "TestSetupConsoleOnlyControlCAndBreakCancelCooperatively"),
    ("localrmm/internal/windowspackage", "TestAncestorDescriptorMemoryFixtures"),
    ("localrmm/internal/windowspackage", "TestCreatedDescriptorsExactInMemory"),
    ("localrmm/internal/windowspackage", "TestOnlyDirectChildMissingIsFreshness"),
    ("localrmm/internal/windowspackage", "TestProvisionEveryFailureRetainsAndNeverContinues"),
    ("localrmm/internal/windowspackage", "TestProvisionCancellationAtEveryBoundary"),
    ("localrmm/internal/windowssetup", "TestCompatibilityExactAndNoExtensions"),
    ("localrmm/internal/windowssetupui", "TestWin32Supported64BitLayouts"),
    ("localrmm/internal/windowssetupui", "TestLayoutControlsStayReachableAcrossClientSizesAndDPI"),
    ("localrmm/internal/windowssetupui", "TestInitialWindowFitsSmallWorkAreasIncluding125PercentRegression"),
    ("localrmm/internal/windowssetupui", "TestWindowMinimumBoundsAndRounding"),
    ("localrmm/internal/windowssetupui", "TestClampWindowPreservesOrBoundsPlacementAcrossMonitorOrigins"),
    ("localrmm/internal/windowssetupui", "TestLayoutRejectsInvalidParameters"),
    ("localrmm/internal/windowssetupui", "TestDisplayLayoutFailuresInvalidatePreviouslyReadyActions"),
    ("localrmm/internal/windowssetupui", "TestUnavailableDisplayRetainsBusyOperationUntilCancellationCompletes"),
    ("localrmm/internal/windowssetupui", "TestAutomationControlIDsStayStable"),
    ("localrmm/internal/windowssetupui", "TestNativeLayoutMessagePointerDecoding"),
    ("localrmm/internal/windowssetupui", "TestNoInstallWithoutEveryExplicitAcknowledgement"),
    ("localrmm/internal/windowssetupui", "TestCancelRetainsOperationUntilHookReturned"),
    ("localrmm/internal/windowssetupui", "TestExplicitHTTPNeedsSeparateRiskApprovalAndMatchingTransport"),
    ("localrmm/cmd/windows-service", "TestSetupWizardInstallOrderingAndEveryBoundary"),
    ("localrmm/cmd/windows-service", "TestSetupWizardCanceledBeforeApplyIsInert"),
    ("localrmm/cmd/windows-service", "TestSetupWizardRemovalWaitsForExactOwnedStopAndAbsence"),
    ("localrmm/internal/windowsmanaged", "TestServiceStartupNativeRightsAndHandleLifetime"),
    ("localrmm/internal/windowsmanaged", "TestServiceStartupNativeBufferClearedAndNoPointersFollowed"),
    ("localrmm/internal/windowsmanaged", "TestServiceStartupNativeModesAndUnknownDoNotQueryDelayed"),
    ("localrmm/internal/windowsmanaged", "TestServiceStartupNativeFailuresBoundsAndBOOL"),
    ("localrmm/internal/windowsmanaged", "TestServiceStartupNativeCancellationClosesOwnedHandles"),
    ("localrmm/internal/windowsmanaged", "TestServiceStartupNativeInvalidInputsNeverOpen"),
    ("localrmm/internal/windowsmanaged", "TestServiceStartupGoGeneratedDigestFixture"),
    ("localrmm/cmd/windows-service", "TestServiceStartupRequiresOwnedStoppedService"),
    ("localrmm/cmd/windows-service", "TestServiceStartupDisclosureMustCompleteBeforeDispatch"),
    ("localrmm/cmd/windows-service", "TestServiceStartupFlagsDoNotAuthorizeAnotherScope"),
    ("localrmm/cmd/windows-service", "TestFreshReadSetupReconcileOnlyFinalizesCompletedEffect"),
    ("localrmm/cmd/windows-service", "TestFreshReadSetupReconcileDisabledChangedOrUnknownNeverWrites"),
    ("localrmm/cmd/windows-service", "TestFreshReadSetupReconcileStrictCanonicalAndCancellation"),
    ("localrmm/internal/windowsservice", "TestFreshReadSetupStaysDisabledAndOrdinaryLifecycleRejectsReceipt"),
    ("localrmm/internal/windowsservice", "TestFreshReadSetupRejectsUnknownAndRunningBindingsBeforeTransition"),
    ("localrmm/internal/windowsservice", "TestFreshReadSetupIndeterminateTransitionOnlyReadOnlyReconciliation"),
    ("localrmm/internal/windowsservice", "TestFreshReadSetupPlanAdmissionDoesNotBroadenOrdinaryInstall"),
    ("localrmm/cmd/windows-service", "TestFreshReadSetupOneConsentBeforeFirstStart"),
    ("localrmm/cmd/windows-service", "TestFreshReadSetupEveryFailureRetainsStateWithoutStart"),
    ("localrmm/cmd/windows-service", "TestFreshReadSetupPartialGrantOutcomeRetained"),
    ("localrmm/cmd/windows-service", "TestFreshReadSetupReceiptStrictAndLegacyUnchanged"),
    ("localrmm/cmd/windows-service", "TestFreshReadSetupHasNoPublicCommand"),
    ("localrmm/internal/windowsnetwork", "TestNativeNetworkInjectedFourTables"),
    ("localrmm/internal/windowsnetwork", "TestNativeNetworkReturnCodesAndBounds"),
    ("localrmm/internal/windowsnetwork", "TestNativeNetworkDWORDLayouts"),
    ("localrmm/internal/windowsnetwork", "TestFourTablesAndNetworkByteOrder"),
    ("localrmm/internal/windowsnetwork", "TestMalformedAndTrailingNativeTables"),
    ("localrmm/internal/windowsnetwork", "TestBufferGrowthBoundAndCancellation"),
    ("localrmm/internal/windowsnetwork", "TestBoundedCountsStableRowsAndBudget"),
    ("localrmm/internal/windowsnetwork", "TestShrinkingTableIgnoresSurplusAllocation"),
    ("localrmm/internal/windowsnetwork", "TestTCPListenerHasNoRemotePeer"),
    ("localrmm/internal/windowsprocessmetrics", "TestNativeMinimalRightsCloseAndCancel"),
    ("localrmm/internal/windowsvolumes", "TestNativeInjectedEnumeration"),
    ("localrmm/internal/windowsvolumes", "TestNativeRejectMalformedRoots"),
    ("localrmm/internal/windowsstate", "TestWindowsRenameABI"),
    ("localrmm/internal/windowsstate", "TestWindowsDescriptorConversionInMemory"),
    ("localrmm/internal/windowsservice", "TestNativeSCMStructureABI"),
    ("localrmm/internal/windowsservice", "TestNativeTrustedACLMemoryFixtures"),
    ("localrmm/internal/windowsservice", "TestNativeRuntimeReadACLMemoryFixtures"),
    ("localrmm/internal/windowsservice", "TestNativeRuntimeReadRejectsEachMissingAndDeniedBit"),
    ("localrmm/internal/windowsservice", "TestNativeFileGenericRightsMapping"),
    ("localrmm/internal/windowsservice", "TestRuntimeArgumentRejectionHasSanitizedSCMCode"),
    ("localrmm/internal/windowsservice", "TestDiagnosticCodesAreStableAndUnique"),
    ("localrmm/internal/windowsservice", "TestMarkedDiagnosticNeverFormatsCause"),
    ("localrmm/cmd/windows-service", "TestPendingTimeoutContinuesWithinOriginalThirtyMinuteAuthority"),
    ("localrmm/cmd/windows-service", "TestPendingOriginalDeadlineIsNeverExtended"),
    ("localrmm/cmd/windows-service", "TestPendingCancellationDuringBackoffIsGraceful"),
    ("localrmm/cmd/windows-service", "TestCLIFinitePhaseReasonDoesNotEchoCause"),
    ("localrmm/cmd/windows-service", "TestConcurrentStopDoesNotHidePendingAuthorityFailures"),
    ("localrmm/cmd/windows-service", "TestConcurrentStopAcceptsOnlyCooperativePendingOutcomes"),
    ("localrmm/internal/windowsservice", "TestRuntimeStopDoesNotHideDiagnosedOrJoinedFailure"),
    ("localrmm/internal/windowsservice", "TestRuntimeStopStillNormalizesOnlyCanceledChains"),
    ("localrmm/internal/windowsconsole", "TestNativeModeConstants"),
    ("localrmm/cmd/windows-service", "TestWindowsLifecycleFlagsFailBeforeAnyOperation"),
}


def check_events(raw):
    if len(raw) > 32 * 1024 * 1024:
        raise ValueError("test output bound")
    passed, skipped = set(), set()
    for line in raw.splitlines():
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError("event shape")
        pair = (value.get("Package"), value.get("Test"))
        if pair in REQUIRED:
            if value.get("Action") == "pass":
                passed.add(pair)
            if value.get("Action") == "skip":
                skipped.add(pair)
    if passed != REQUIRED or skipped:
        raise ValueError("required source fixtures did not pass")


def command(args, env, timeout):
    result = subprocess.run(args, env=env, capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        raise ValueError("source command failed")
    return result.stdout


def fixture_failure(raw):
    """Project only the gate's fixed vocabulary; never open logs or load an allowlist."""
    diagnostic = {"category": "diagnostic_unavailable", "records": [], "truncated": False}
    try:
        if not isinstance(raw, bytes) or len(raw) > 32 * 1024 * 1024:
            raise ValueError("test output bound")
        allowed = {}
        for package, root in REQUIRED:
            allowed.setdefault(package, set()).add(root)
        diagnostic = project(raw, allowed)
    except (ValueError, TypeError, OverflowError, RecursionError):
        pass
    print("WINDOWS_SOURCE_DIAGNOSTIC " + json.dumps(diagnostic, sort_keys=True, separators=(",", ":"), allow_nan=False))


def pure_fixtures(env):
    raw = None
    try:
        result = subprocess.run(
            ["go", "test", "-json", "-count=1", "-timeout=120s", "-buildvcs=false", *PACKAGES],
            env=env, capture_output=True, timeout=300, check=False)
        raw = result.stdout
        if result.returncode:
            raise ValueError("source command failed")
        check_events(raw)
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        fixture_failure(raw)
        raise ValueError("source fixtures failed") from None


def main():
    stage = "platform"
    try:
        if sys.platform != "win32":
            raise ValueError("native Windows source fixtures required")
        env = os.environ.copy()
        env.pop("GOOS", None)
        env.pop("GOARCH", None)
        env["GOTOOLCHAIN"] = "local"
        # This gate never enables the separate read-only host collector smoke.
        env.pop("TRACEBOLT_WINDOWS_READONLY_NATIVE", None)
        env.pop("TRACEBOLT_KNOWNFOLDER_PROBE", None)
        env.pop("TRACEBOLT_UPDATE_SERVICE_STARTUP_FIXTURE", None)
        if command(["go", "env", "GOHOSTARCH"], env, 30).strip() != b"amd64":
            raise ValueError("native amd64 fixture host required")
        stage = "pure fixtures"
        pure_fixtures(env)
        stage = "vet"
        command(["go", "vet", *PACKAGES], env, 180)
        # Build products stay in a disposable folder. No built executable runs.
        with tempfile.TemporaryDirectory(prefix="tracebolt-source-") as folder:
            for arch in ("amd64", "arm64"):
                stage = arch + " source build"
                cross = dict(env, GOOS="windows", GOARCH=arch, CGO_ENABLED="0")
                command(["go", "build", "-buildvcs=false", "-trimpath", "-o", str(Path(folder) / ("service-" + arch + ".exe")), "./cmd/windows-service"], cross, 300)
                command(["go", "build", "-buildvcs=false", "-trimpath", "-o", str(Path(folder) / ("user-software-" + arch + ".exe")), "./cmd/windows-user-software"], cross, 300)
                command(["go", "build", "-buildvcs=false", "-trimpath", "-tags=tracebolt_setup", "-ldflags=-H windowsgui", "-o", str(Path(folder) / ("setup-source-" + arch + ".exe")), "./cmd/windows-service"], cross, 300)
        print("PASS: Windows source fixtures and amd64/arm64 builds; no service installation/control, DACL grants, enrollment keys, live console or endpoint observation executed.")
        return 0
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError, KeyError):
        print("FAIL: Windows service source gate at " + stage + "; raw output withheld.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
