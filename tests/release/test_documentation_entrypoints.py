"""Inert documentation-navigation checks; no release download or acceptance claim.

The linked platform guides/manifests remain authoritative. This narrow drift
tripwire deliberately does not create another release/capability metadata source.
"""
from copy import deepcopy
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
HISTORY = '## Historical Windows packages\n'
RELEASE_URL = re.compile(r'https://github\.com/storminator89/Tracebolt/releases/(?:tag|download)/')
LINK = re.compile(r'\[[^\]]*\]\(([^)\s]+)\)')


def section(text, heading):
    marker = '## ' + heading + '\n'
    if text.count(marker) != 1:
        raise ValueError('Missing or duplicate documentation section')
    return text.split(marker, 1)[1].split('\n## ', 1)[0]


def check_entrypoints(documents):
    index, web = documents['docs/README.md'], documents['web/README.md']
    setup = section(index, 'Setup')
    enrollment = section(web, 'Conditional device enrollment')
    history = section(index, 'Historical Windows packages')
    required = ['windows-status.md', 'integrated-test-candidate.md',
                'macos-status.md', 'macos-prerelease.md']
    for body, prefix in [(setup, ''), (enrollment, '../docs/')]:
        links = set(LINK.findall(body))
        if any(prefix + target not in links for target in required) or RELEASE_URL.search(body):
            raise ValueError('Setup must use canonical platform guides, not a duplicate release pin')
    if index.count(HISTORY) != 1 or RELEASE_URL.search(index.split(HISTORY, 1)[0]):
        raise ValueError('Version-specific package links belong in historical references')
    historical_links = set(LINK.findall(history))
    if not {
        'https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-windows-preview.2',
        'https://github.com/storminator89/Tracebolt/releases/download/v0.1.0-windows-preview.2/windows-prerelease-install.md',
        'windows-prerelease-historical/windows-prerelease-install.md',
    }.issubset(historical_links):
        raise ValueError('Historical package provenance must remain discoverable')
    normalized = ' '.join(enrollment.lower().split())
    for obsolete in ['setup preview is unreleased', 'macos enrollment remains unavailable']:
        if obsolete in normalized:
            raise ValueError('Obsolete enrollment availability claim')
    # Validate local guide destinations and the changed demo fragment from the
    # actual supplied documents. No network or published-asset verification.
    for name, body in [('docs/README.md', index), ('web/README.md', enrollment)]:
        for target in LINK.findall(body):
            if '://' in target:
                continue
            file, _, fragment = target.partition('#')
            destination = (ROOT / name).parent / file
            if destination.suffix != '.md' or not destination.is_file():
                raise ValueError('Broken local guide link')
            if name == 'docs/README.md' and file == '../README.md':
                headings = re.findall(r'^#+ (.+)$', documents['README.md'], re.M)
                anchors = {re.sub(r'[^\w\- ]', '', heading.lower()).replace(' ', '-') for heading in headings}
                if fragment and fragment not in anchors:
                    raise ValueError('Broken project overview fragment')


class DocumentationEntrypoints(unittest.TestCase):
    def setUp(self):
        self.documents = {name: (ROOT / name).read_text() for name in
                          ['docs/README.md', 'web/README.md', 'README.md']}

    def test_current_entrypoints_use_canonical_guides_and_preserve_history(self):
        check_entrypoints(self.documents)

    def test_stale_release_recommendations_and_missing_guides_fail(self):
        for name, old, new in [
            ('docs/README.md', '(windows-status.md)', '(https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-windows-preview.2)'),
            ('docs/README.md', '(integrated-test-candidate.md)', '(windows-status.md)'),
            ('web/README.md', '(../docs/macos-status.md)', '(../docs/windows-status.md)'),
            ('web/README.md', '(../docs/macos-prerelease.md)', '(../docs/missing-guide.md)'),
            ('docs/README.md', '#try-the-dashboard-locally', '#try-the-local-dashboard'),
            ('docs/README.md', HISTORY, '## Old packages\n'),
        ]:
            with self.subTest(name=name, old=old):
                changed = deepcopy(self.documents)
                self.assertIn(old, changed[name])
                changed[name] = changed[name].replace(old, new)
                with self.assertRaises(ValueError):
                    check_entrypoints(changed)

    def test_obsolete_availability_claims_cannot_return_beside_correct_links(self):
        for claim in ['Setup preview is unreleased.', 'macOS enrollment remains unavailable.']:
            changed = deepcopy(self.documents)
            changed['web/README.md'] = changed['web/README.md'].replace(
                '## Conditional device enrollment\n', '## Conditional device enrollment\n\n' + claim + '\n')
            with self.subTest(claim=claim), self.assertRaises(ValueError):
                check_entrypoints(changed)

    def test_historical_packages_cannot_be_silently_removed_or_promoted(self):
        changed = deepcopy(self.documents)
        changed['docs/README.md'] = changed['docs/README.md'].replace(
            '/releases/tag/v0.1.0-windows-preview.2', '/releases/tag/unknown-history')
        with self.assertRaises(ValueError):
            check_entrypoints(changed)
        changed = deepcopy(self.documents)
        changed['docs/README.md'] = changed['docs/README.md'].replace(
            '## Setup\n', '## Setup\n\n- [Install](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-windows-preview.2)\n')
        with self.assertRaises(ValueError):
            check_entrypoints(changed)

    def test_existing_full_validation_discovers_this_inert_suite(self):
        workflow = (ROOT / '.github/workflows/validate.yml').read_text()
        self.assertEqual(workflow.count("python3 -B -m unittest discover -s tests/release -p 'test_*.py' -v"), 1)


if __name__ == '__main__':
    unittest.main()
