#!/usr/bin/env python3
"""Read-only, explicitly gated hosted verification of the published rc.3.

Only the independently pinned official gh verifier is executed. Tracebolt files
are downloaded privately, checked as bytes and never extracted or executed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import types

HERE = Path(__file__).resolve().parent
VERSION = "v0.1.0-rc.3"
SOURCE = "405f57f184e75736477cbd3af7a2536ddfe0e6f6"
REPOSITORY = "storminator89/Tracebolt"
TEMPLATE_SHA256 = 'e1e6c2657aebe6b15539961a42de10396438027bedb1189df408d7f867823b77'
PIN = {'version': 'v0.1.0-rc.3', 'sourceCommit': '405f57f184e75736477cbd3af7a2536ddfe0e6f6', 'manifestSHA256': '93db5f49635fd40e9ac81c5434aa0c7f1500b7920d2063d84eac621cd71f5c07', 'bundleSHA256': '0f4f51ab217d74b490ab6eb3800cd7c089171698a5aa4f1e49a172bda889c383'}
EXPECTED = {'bootstrap.py': (49246, '5071d6ecb5933c70c9ee9be8a2ff0b4c0b48fbd6084ea83065b8c5cf634cc231'),
 'manifest.json': (1486, '93db5f49635fd40e9ac81c5434aa0c7f1500b7920d2063d84eac621cd71f5c07'),
 'manifest.sigstore.json': (11222, '0f4f51ab217d74b490ab6eb3800cd7c089171698a5aa4f1e49a172bda889c383'),
 'tracebolt-v0.1.0-rc.3-linux-amd64-agent-service': (11609745,
                                                     'fe4a92623f2b697135f0842ba8982898936d85eb71c37a23dd5de7d9eff1682c'),
 'tracebolt-v0.1.0-rc.3-linux-amd64-enroll-agent': (11928297,
                                                    '6dcf5b8108958b4c2a638fb3d7a02fa2723099bee4a46fc981cea782a7d346b5'),
 'tracebolt-v0.1.0-rc.3-linux-amd64-lan-agent': (15284911,
                                                 '0f70903e349276abaee123be2e1939e81331757753ac70ac50f2452f1a54c91e'),
 'tracebolt-v0.1.0-rc.3-linux-amd64-socket-owner-reader': (5715931,
                                                           '21ea4df0a99f1f57e18ae4daea37d88aa34c5f3f7a538dbda70e6a5206e0de49'),
 'tracebolt-v0.1.0-rc.3-linux-arm64-agent-service': (10713799,
                                                     'c7d3aff5dc2016cca182264c47d4345ec8d37f57b3f06fefb0389d97ce871630'),
 'tracebolt-v0.1.0-rc.3-linux-arm64-enroll-agent': (11010990,
                                                    '2c3ccf9447e39aee554b597664d634419b38775373b54a8c1738d9e7a3e6e539'),
 'tracebolt-v0.1.0-rc.3-linux-arm64-lan-agent': (13989843,
                                                 'dc61cbd59def532694b3bf9156dfbbaad998f2028e2af6504ebeafda322d9b19'),
 'tracebolt-v0.1.0-rc.3-linux-arm64-socket-owner-reader': (5419210,
                                                           'a50ccb138ee341c585f0e80ea926ad38ab68ecda7c731e21ca1d20c5fb1dbe38'),
 'tracebolt-v0.1.0-rc.3-source.tar': (20572160,
                                      '6e8dee99b99d77ef61bf16fe4920beb105040b8b89400468dcfc4cfa8a427a98')}
PUBLIC_FILES = ("bootstrap.py", "manifest.json", "manifest.sigstore.json")
RESULT_FILE = "verification-result.json"
SCHEMA = "tracebolt.public-release-verification.v1"


class Failed(Exception):
    pass


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise Failed("FAIL_ARGUMENTS")


def require(value, failure):
    if not value:
        raise Failed(failure)


def check_context(output, opt_in):
    expected = {
        "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push",
        "GITHUB_JOB": "verify-published-release",
        "GITHUB_WORKFLOW_REF": REPOSITORY + "/.github/workflows/verify-published-release.yml@refs/heads/main",
        "TRACEBOLT_VERIFY_PUBLISHED_RC3": "1", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
    }
    require(opt_in and all(os.environ.get(k) == v for k, v in expected.items()) and
            os.getuid() != 0 and os.geteuid() == os.getuid(), "FAIL_CONTEXT")
    parent = Path(os.environ.get("RUNNER_TEMP", ""))
    require(parent.is_absolute() and parent == parent.resolve() and parent.is_dir() and
            parent.stat().st_uid == os.getuid() and not (parent.stat().st_mode & 0o022) and
            output == parent / "tracebolt-public-readback" and
            not output.exists() and not output.is_symlink(), "FAIL_OUTPUT")


def load_bootstrap():
    # This check belongs to the pinned rc.3 source, even after the reusable
    # template is corrected for a later release. Check both hashes before loading
    # the exact captured bytes, with its executable release pin disabled.
    path = HERE / "published" / f"{VERSION}.py"
    published = path.read_bytes()
    require((len(published), hashlib.sha256(published).hexdigest()) == EXPECTED["bootstrap.py"], "FAIL_TEMPLATE")
    configured = ("RELEASE_PIN = " + repr(PIN)).encode()
    require(published.count(configured) == 1, "FAIL_TEMPLATE")
    template = published.replace(configured, b"RELEASE_PIN = None", 1)
    require(hashlib.sha256(template).hexdigest() == TEMPLATE_SHA256, "FAIL_TEMPLATE")
    b = types.ModuleType("rc3_bootstrap")
    b.__file__ = str(path)
    exec(compile(template, str(path), "exec"), b.__dict__)
    original_url = b.asset_url

    def fixed_url(version, name):
        # The original install bootstrap does not download itself. Add only the
        # one exact published bootstrap URL to this verifier's private module.
        # All TLS, DNS, redirect, proxy, size/hash and deadline checks are intact.
        if version == VERSION and name == "bootstrap.py":
            return f"https://github.com/{REPOSITORY}/releases/download/{VERSION}/bootstrap.py"
        require((version == VERSION and name in EXPECTED) or
                (version == b.GH_VERSION and name == f"gh_{b.GH_VERSION}_linux_amd64.tar.gz"), "FAIL_DOWNLOAD")
        return original_url(version, name)

    b.asset_url = fixed_url
    return b, template


def check_file(b, path, expected):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
            stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == expected[0] and
            b.file_digest(path) == expected[1], "FAIL_ARTIFACT")


def verify(output, b, template):
    stage = "FAIL_DOWNLOAD"
    try:
        with tempfile.TemporaryDirectory(prefix="tracebolt-public-check-", dir=output.parent) as temporary:
            work = Path(temporary)

            def fetch(version, name, target, limit, expected_size=None, expected_digest=None):
                b.download(version, name, target, limit, expected_size=expected_size,
                           expected_digest=expected_digest, deadline_seconds=120)

            def asset(name):
                size, digest = EXPECTED[name]
                fetch(VERSION, name, work / name, size, expected_size=size, expected_digest=digest)
                check_file(b, work / name, EXPECTED[name])

            asset("manifest.json")
            asset("manifest.sigstore.json")
            verifier = b.prepare_verifier(work, "amd64", fetch=fetch)
            stage = "FAIL_PROVENANCE"
            b.verify_attestation(work, PIN, verifier)
            stage = "FAIL_MANIFEST"
            manifest = b.parse_manifest((work / "manifest.json").read_bytes(), PIN)
            require(manifest["assets"] == {name: {"size": EXPECTED[name][0], "sha256": EXPECTED[name][1]}
                                           for name in b.asset_names(VERSION)}, "FAIL_MANIFEST")
            stage = "FAIL_DOWNLOAD"
            for name in sorted(manifest["assets"]):
                asset(name)
            asset("bootstrap.py")
            stage = "FAIL_BOOTSTRAP"
            require(template.count(b"RELEASE_PIN = None") == 1 and
                    (work / "bootstrap.py").read_bytes() == template.replace(b"RELEASE_PIN = None", ("RELEASE_PIN = " + repr(PIN)).encode()),
                    "FAIL_BOOTSTRAP")
            for name, expected in EXPECTED.items():
                check_file(b, work / name, expected)
            stage = "FAIL_OUTPUT"
            # Only verified public metadata leaves private staging. Tracebolt
            # binaries and the source archive are never chmodded or executed.
            retained = work / "retained"
            retained.mkdir(mode=0o700)
            for name in PUBLIC_FILES:
                with b.open_private(retained / name) as stream:
                    stream.write((work / name).read_bytes())
                check_file(b, retained / name, EXPECTED[name])
            result = {"schema": SCHEMA, "status": "PASS", "version": VERSION, "sourceCommit": SOURCE,
                      "assetsVerified": 12, "traceboltProgramsExecuted": False, "installerExecuted": False,
                      "publicArtifacts": {name: {"size": EXPECTED[name][0], "sha256": EXPECTED[name][1]} for name in PUBLIC_FILES}}
            with b.open_private(retained / RESULT_FILE) as stream:
                stream.write((json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode())
            require((retained / RESULT_FILE).stat().st_size <= 4096 and
                    json.loads((retained / RESULT_FILE).read_bytes()) == result, "FAIL_OUTPUT")
            require({p.name for p in retained.iterdir()} == set(PUBLIC_FILES) | {RESULT_FILE}, "FAIL_OUTPUT")
            require(not output.exists() and not output.is_symlink(), "FAIL_OUTPUT")
            retained.rename(output)
        return result
    except Failed:
        raise
    except Exception:
        raise Failed(stage) from None


def main():
    parser = SafeParser(allow_abbrev=False, add_help=False)
    parser.add_argument("--verify-published-rc3", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    try:
        args = parser.parse_args()
        check_context(args.output, args.verify_published_rc3)
        b, template = load_bootstrap()
        verify(args.output, b, template)
    except Failed as error:
        print(str(error))
        return 1
    except KeyboardInterrupt:
        print("FAIL_INTERRUPTED")
        return 1
    except Exception:
        print("FAIL_INTERNAL")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
