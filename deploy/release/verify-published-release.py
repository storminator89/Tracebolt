#!/usr/bin/env python3
"""Read-only, explicitly gated hosted verification of the published rc.2.

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
VERSION = "v0.1.0-rc.2"
SOURCE = "a6368b0202b1efecdb6214dc34c4302d239854f7"
REPOSITORY = "storminator89/Tracebolt"
TEMPLATE_SHA256 = '0f0a510a4ebe71244c84cc0021a303171248c81d1028570bacd8762db7936df2'
PIN = {'version': 'v0.1.0-rc.2', 'sourceCommit': 'a6368b0202b1efecdb6214dc34c4302d239854f7', 'manifestSHA256': '5eae7faad1e9f3d15881c44d2c8878f5956f5ee5a91ca591a3c9dbba1e650559', 'bundleSHA256': '232f7ce69f24d8b9d78265e1b3d1379be5044b89b538341cc6951d31e6459fac'}
EXPECTED = {'bootstrap.py': (46739, '10b372ed31d0b2e04d901286ed477a9e7b4fc4d1efe7faea78a5ae8a284db4ea'),
 'manifest.json': (1486, '5eae7faad1e9f3d15881c44d2c8878f5956f5ee5a91ca591a3c9dbba1e650559'),
 'manifest.sigstore.json': (11394, '232f7ce69f24d8b9d78265e1b3d1379be5044b89b538341cc6951d31e6459fac'),
 'tracebolt-v0.1.0-rc.2-linux-amd64-agent-service': (11597203,
                                                     '2b4e8f3174ab831bab3522d7119c0973819e214d2800d9328e7be72282e207e0'),
 'tracebolt-v0.1.0-rc.2-linux-amd64-enroll-agent': (11928473,
                                                    '44a2235072459cc73fc918c9596e51fe441407b721f3d7cfc2b796fc1bbe645c'),
 'tracebolt-v0.1.0-rc.2-linux-amd64-lan-agent': (15274846,
                                                 '6e1ac6ca7b50ae11141b1d345dc69cd59e0ff97583aa3cefd52152b209509bb5'),
 'tracebolt-v0.1.0-rc.2-linux-amd64-socket-owner-reader': (5715931,
                                                           '5e360633dbc1acda24acd5b24317f3ce7619af7598dd7ed6119f5d5c4e5585f8'),
 'tracebolt-v0.1.0-rc.2-linux-arm64-agent-service': (10709241,
                                                     '8ba59e98864af6ff5bf57ba1912126b6fe7a4774ccd2bffaac16396e8d6460d1'),
 'tracebolt-v0.1.0-rc.2-linux-arm64-enroll-agent': (11011046,
                                                    '8186ec334d2afe6a221d4ef931984d5108be6f0c13fab8ed60d0059886e18f9a'),
 'tracebolt-v0.1.0-rc.2-linux-arm64-lan-agent': (13920986,
                                                 'd0a4d88a6ada430faf3a7fbe080ee8e308945ab18a18be691add111667fb2a39'),
 'tracebolt-v0.1.0-rc.2-linux-arm64-socket-owner-reader': (5419210,
                                                           'ef6cf510042f5f03b73556a264944dfd243793844391ea071c42881fd959a1d5'),
 'tracebolt-v0.1.0-rc.2-source.tar': (19763200,
                                      '3813b61b0565e9becd8c6921769b8448437d5c0adca4348ba4cbff8510356856')}
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
        "TRACEBOLT_VERIFY_PUBLISHED_RC2": "1", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
    }
    require(opt_in and all(os.environ.get(k) == v for k, v in expected.items()) and
            os.getuid() != 0 and os.geteuid() == os.getuid(), "FAIL_CONTEXT")
    parent = Path(os.environ.get("RUNNER_TEMP", ""))
    require(parent.is_absolute() and parent == parent.resolve() and parent.is_dir() and
            parent.stat().st_uid == os.getuid() and not (parent.stat().st_mode & 0o022) and
            output == parent / "tracebolt-public-readback" and
            not output.exists() and not output.is_symlink(), "FAIL_OUTPUT")


def load_bootstrap():
    # This check belongs to the pinned rc.2 source, even after the reusable
    # template is corrected for a later release. Check both hashes before loading
    # the exact captured bytes, with its executable release pin disabled.
    path = HERE / "published" / f"{VERSION}.py"
    published = path.read_bytes()
    require((len(published), hashlib.sha256(published).hexdigest()) == EXPECTED["bootstrap.py"], "FAIL_TEMPLATE")
    configured = ("RELEASE_PIN = " + repr(PIN)).encode()
    require(published.count(configured) == 1, "FAIL_TEMPLATE")
    template = published.replace(configured, b"RELEASE_PIN = None", 1)
    require(hashlib.sha256(template).hexdigest() == TEMPLATE_SHA256, "FAIL_TEMPLATE")
    b = types.ModuleType("rc2_bootstrap")
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
    parser.add_argument("--verify-published-rc2", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    try:
        args = parser.parse_args()
        check_context(args.output, args.verify_published_rc2)
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
