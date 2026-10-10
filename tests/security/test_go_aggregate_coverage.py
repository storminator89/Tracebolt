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
    ('  backend-checks:\n', '  go-race:\n', '6d29940b1f175df97203e9e7df32a4da28f86bb38bf5b3cd7a88c189c523ab97'),
    ('  go-race:\n', '  backend:\n', '105a1ee6f737da7f864e531ba5bcd2131b493349606fa0a016851d7df1f97550'),
    ('  backend:\n', '  transport-smoke:\n', '31fe09e170c4aab4adc0238ad240c639cd8c225fecfa89afe87f27a219bc6740'),
]
RUNNER_SHA256 = '1a3f1a2c9cb0d417d959eb68c302677249e58f453c4089f1ed90a540e3fdd1af'


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
                self.assertIn(old, self.source)
                with self.assertRaises(ValueError):
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
