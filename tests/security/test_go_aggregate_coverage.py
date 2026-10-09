"""Inert CI exclusion contract. No Go, shell, native or network work runs."""
import hashlib
from pathlib import Path
import re
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


def between(source, start, end):
    if source.count(start) != 1 or source.count(end) != 1:
        raise ValueError("missing or duplicate coverage boundary")
    tail = source.split(start, 1)[1]
    if end not in tail:
        raise ValueError("reversed coverage boundary")
    return tail.split(end, 1)[0]


def check_coverage(source):
    aggregate = between(source, "      - name: Unit and race tests\n",
                        "      - name: Build local binaries\n")
    commands = re.findall(r"^          if go test ([^\n]+); then$", aggregate, re.M)
    expected = ("-race -json -p 1 -buildvcs=false ./... -skip "
                "'^(" + "|".join(COVERAGE) + ")$' -count=1 -timeout=15m "
                '> "$RUNNER_TEMP/go-tests.jsonl" 2> "$RUNNER_TEMP/go-tests.stderr"')
    if commands != [expected]:
        raise ValueError("aggregate coverage or execution flags changed")
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

    def test_extra_missing_or_unanchored_exclusion_fails(self):
        for old, new in [
            (DENSE + "|" + GUIDED, DENSE + "|" + GUIDED + "|TestNativeTwoBinaryRoundTrip"),
            (DENSE + "|" + GUIDED, DENSE),
            ("-skip '^(", "-skip '("),
            (GUIDED + ")$'", GUIDED + ")'"),
            ("-race -json -p 1", "-json -p 1"),
            ("./... -skip", "./internal/... -skip"),
        ]:
            with self.subTest(change=new):
                self.assertNotEqual(self.source.replace(old, new, 1), self.source)
                with self.assertRaises(ValueError):
                    check_coverage(self.source.replace(old, new, 1))

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
