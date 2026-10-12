"""Inert CI exclusion contract. No Go, shell, native or network work runs."""
import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
DENSE = "TestIndependentPackageStoreDenseCapacityAndActualIngress"
GUIDED = "TestGuidedThreeBinaryEnrollmentAndForeground"

# The dedicated blocks are deliberately pinned byte-for-byte. Altering their
# race/count/timeout, matrix, required evidence or failure handling requires a
# separate coverage review, rather than silently broadening this exclusion.
COVERAGE = {
    DENSE: ("  package-dense-race:\n", "  ubuntu-package-native:\n", "709aa4b5fa8fd72d3716381eb51c95aaea69ee986f5268b48241e1c421665f71"),
    GUIDED: (
        "      - name: Actual guided enrollment and foreground reporting across three Linux binaries\n",
        "      - name: Execute Linux agent and validate bounded support-bundle schema\n",
        "cddfe72c7e0c4cbda6aa50f28767ca1714fb323d3e4225485a7cce05fb3606a2",
    ),
}

SHARD_COVERAGE = [
    ('  backend-checks:\n', '  go-race:\n', 'df9b077b16ef0d63d97cc727b9436c6169615f9dc344f6e317deafff157e521e'),
    ('  go-race:\n', '  backend:\n', '63e0c59ad44d2fd84f2c0009c99812c4c742202bbc3013a67be7da6596da0e61'),
    ('  backend:\n', '  transport-smoke:\n', '31fe09e170c4aab4adc0238ad240c639cd8c225fecfa89afe87f27a219bc6740'),
]
RUNNER_SHA256 = 'd8a592c1cbe85176a1b120d3a4fb386de981d7f8d484b922ec85f92f0cf0492b'


def between(source, start, end):
    if source.count(start) != 1 or source.count(end) != 1:
        raise ValueError("missing or duplicate coverage boundary")
    tail = source.split(start, 1)[1]
    if end not in tail:
        raise ValueError("reversed coverage boundary")
    return tail.split(end, 1)[0]


def check_coverage(source, runner=None):
    # Every package comes from exact go list ./..., in three disjoint source-bound
    # shards. The old required name is now an always-run fail-closed aggregate.
    # Pin the complete orchestration and runner: flags alone cannot prove coverage.
    for start, end, digest in SHARD_COVERAGE:
        if hashlib.sha256(between(source, start, end).encode()).hexdigest() != digest:
            raise ValueError("shard coverage or execution contract changed")
    runner = (ROOT / "tests/security/go_race_shards.py").read_bytes() if runner is None else runner
    if hashlib.sha256(runner).hexdigest() != RUNNER_SHA256:
        raise ValueError("shard runner changed without coverage review")
    for start, end, digest in COVERAGE.values():
        if hashlib.sha256(between(source, start, end).encode()).hexdigest() != digest:
            raise ValueError("dedicated coverage changed")
    return frozenset(COVERAGE)


class CoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / ".github/workflows/validate.yml").read_text()

    def test_every_exclusion_has_unchanged_dedicated_coverage(self):
        self.assertEqual(check_coverage(self.source), {DENSE, GUIDED})

    def test_partition_matrix_and_aggregate_failure_handling_changes_fail(self):
        # Mutate only the pinned backend orchestration. Earlier independent jobs
        # may legitimately use the same upload-artifact or failure-handling keys.
        block = between(self.source, SHARD_COVERAGE[0][0], SHARD_COVERAGE[-1][1])
        for old, new in [
            ("shard: [0, 1, 2]", "shard: [0, 1]"),
            ("needs: [backend-checks, go-race, package-dense-race]", "needs: [go-race]"),
            ("if: ${{ always() }}", "if: ${{ success() }}"),
            ("fail-fast: false\n      matrix:\n        shard:", "fail-fast: true\n      matrix:\n        shard:"),
            ("--verify \"$RUNNER_TEMP/go-race-results\"", "--check-needs"),
            ("merge-multiple: false", "merge-multiple: true"),
            ("if-no-files-found: error", "if-no-files-found: ignore"),
            ("--check-needs", "--help"),
        ]:
            with self.subTest(change=new):
                self.assertEqual(block.count(old), 2 if old == "if-no-files-found: error" else 1)
                with self.assertRaises(ValueError):
                    check_coverage(self.source.replace(block, block.replace(old, new, 1), 1))

    def test_one_transport_fallback_keeps_same_file_and_fails_closed(self):
        block = between(self.source, "  go-race:\n", "  backend:\n")
        primary, fallback = block.split("      - name: Upload normalized completion evidence only\n", 1)[1].split(
            "      - name: Retry normalized completion upload once\n")
        action = "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1"
        self.assertEqual(block.count(action), 2)
        self.assertEqual(block.count("        continue-on-error: true\n"), 1)
        self.assertIn("        id: completion-upload\n        continue-on-error: true\n", primary)
        self.assertNotIn("        if:", primary)
        self.assertIn("        if: ${{ !cancelled() && steps.completion-upload.outcome == 'failure' }}\n", fallback)
        self.assertNotIn("continue-on-error:", fallback)
        self.assertNotIn("overwrite:", primary + fallback)
        self.assertNotIn("run:", primary + fallback)
        for upload, suffix in ((primary, ""), (fallback, "-fallback")):
            self.assertIn("          name: go-race-${{ github.run_attempt }}-${{ matrix.shard }}" + suffix + "\n", upload)
            self.assertIn("          path: ${{ runner.temp }}/go-race-report/completion.json\n", upload)
            self.assertIn("          if-no-files-found: error\n          retention-days: 1\n", upload)
        self.assertEqual(block.count("--shard"), 1)  # Never rerun tests on transfer failure.
        for old, new in (("steps.completion-upload.outcome", "steps.completion-upload.conclusion"),
                         ("&& steps.completion-upload.outcome == 'failure'", "|| true"),
                         ("${{ matrix.shard }}-fallback", "${{ matrix.shard }}"),
                         ("- name: Retry normalized completion upload once\n", "- name: Retry normalized completion upload once\n        continue-on-error: true\n")):
            with self.subTest(change=new), self.assertRaises(ValueError):
                check_coverage(self.source.replace(old, new, 1))

    def test_extra_missing_unanchored_exclusion_or_weakened_runner_fails(self):
        runner = (ROOT / "tests/security/go_race_shards.py").read_bytes()
        for old, new in [
            (DENSE + "|" + GUIDED, DENSE + "|" + GUIDED + "|TestNativeTwoBinaryRoundTrip"),
            (DENSE + "|" + GUIDED, DENSE),
            ('SKIP = "^(', 'SKIP = "('),
            (GUIDED + ')$"', GUIDED + ')"'),
            ('"-race", ', ''), ('"-count=1"', '"-count=0"'),
            ('"-timeout=15m"', '"-timeout=1m"'), ('"./..."', '"./internal/..."'),
            ('"-p", "1"', '"-p", "8"'), ('reporter.load_allowlist()', '{}'),
        ]:
            with self.subTest(change=new):
                self.assertIn(old.encode(), runner)
                with self.assertRaises(ValueError):
                    check_coverage(self.source, runner.replace(old.encode(), new.encode(), 1))

    def test_dedicated_execution_evidence_and_matrix_changes_fail(self):
        for root, (start, end, _) in COVERAGE.items():
            block = between(self.source, start, end)
            changes = [("-count=1", "-count=0"), ("-race", ""),
                       ("-timeout=", "-timeout=9"), ("passed !=", "passed ==")]
            changes += [("profile: [tls, http-test]", "profile: [tls]")] if root == DENSE else [
                ('"' + GUIDED + '/http-test"', '"' + GUIDED + '/omitted"')]
            for old, new in changes:
                with self.subTest(root=root, change=new):
                    self.assertIn(old, block)
                    with self.assertRaises(ValueError):
                        check_coverage(self.source.replace(block, block.replace(old, new, 1), 1))

    def test_missing_duplicate_and_reordered_blocks_fail(self):
        start, end, _ = COVERAGE[GUIDED]
        for source in (self.source.replace(start, "", 1), self.source + start,
                       self.source.replace(start, "SWAP_BOUNDARY", 1).replace(end, start, 1).replace("SWAP_BOUNDARY", end, 1)):
            with self.assertRaises(ValueError):
                check_coverage(source)


if __name__ == "__main__":
    unittest.main()
