#!/usr/bin/env python3
"""Read-only, explicitly gated hosted verification of the published pilot.2.

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
VERSION = "v0.1.0-pilot.2"
SOURCE = "dbbcfe203c6c39169d9b426991848cd8e736dfd6"
REPOSITORY = "storminator89/Tracebolt"
TEMPLATE_SHA256 = "3f6f305e461a4c871b5db8447e6acfafdf2b1f8ace6f147af4d10dcf9d2e6d04"
PIN = {"version": VERSION, "sourceCommit": SOURCE,
       "manifestSHA256": "d893ca6c896e788a943be6c930321a3264d0d3e646a769da9a2531b585b89279",
       "bundleSHA256": "b7ae8fe0eb25baf44750af6cde5f3c38cdb64f5f9514c274f33ba7b37acb6778"}
EXPECTED = {
    "bootstrap.py": (32677, "ba0cf2b8bb25868782bbf9f7a2ae228a982895dd45f865314c6620af30731457"),
    "manifest.json": (1211, PIN["manifestSHA256"]),
    "manifest.sigstore.json": (11052, PIN["bundleSHA256"]),
    f"tracebolt-{VERSION}-linux-amd64-agent-service": (11461139, "3c1dcf359cd5a5f5ad6cd210ee770a6f0a7d36fc4f47b9815727e25dfade458a"),
    f"tracebolt-{VERSION}-linux-amd64-enroll-agent": (11762241, "841895906128368fa71099b91753a432cff2dd7ad12c7e1bb448328cc66933d4"),
    f"tracebolt-{VERSION}-linux-amd64-lan-agent": (12949390, "50f9f1308e177bc74a15889c5a880cb740cda8df73eab32486eb2353aa5a8906"),
    f"tracebolt-{VERSION}-linux-arm64-agent-service": (10614011, "66e0f34dbd4619ee1a0dd85a8a406c090d9eef156b4261ac16e4fe3809c8c4d2"),
    f"tracebolt-{VERSION}-linux-arm64-enroll-agent": (10911816, "e9c15a527c55870f71f08e02ad790f5ffbd3c78a64722e256ff343d3c098d372"),
    f"tracebolt-{VERSION}-linux-arm64-lan-agent": (11924015, "6f060c8c4ec3407da6ccff1833823462dc8ae78db5fab1dcab88d8bf44afebca"),
    f"tracebolt-{VERSION}-source.tar": (9543680, "7745052bfb8b08032286551d7c10accb7fef4adc89d275e3e9bc31253b374f59"),
}
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
        "TRACEBOLT_VERIFY_PUBLISHED_PILOT2": "1", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
    }
    require(opt_in and all(os.environ.get(k) == v for k, v in expected.items()) and
            os.getuid() != 0 and os.geteuid() == os.getuid(), "FAIL_CONTEXT")
    parent = Path(os.environ.get("RUNNER_TEMP", ""))
    require(parent.is_absolute() and parent == parent.resolve() and parent.is_dir() and
            parent.stat().st_uid == os.getuid() and not (parent.stat().st_mode & 0o022) and
            output == parent / "tracebolt-public-readback" and
            not output.exists() and not output.is_symlink(), "FAIL_OUTPUT")


def load_bootstrap():
    # This check belongs to the immutable pilot.2 source, even after the reusable
    # template is corrected for a later release. Check both hashes before loading
    # the exact captured bytes, with its executable release pin disabled.
    path = HERE / "published" / f"{VERSION}.py"
    published = path.read_bytes()
    require((len(published), hashlib.sha256(published).hexdigest()) == EXPECTED["bootstrap.py"], "FAIL_TEMPLATE")
    configured = ("RELEASE_PIN = " + repr(PIN)).encode()
    require(published.count(configured) == 1, "FAIL_TEMPLATE")
    template = published.replace(configured, b"RELEASE_PIN = None", 1)
    require(hashlib.sha256(template).hexdigest() == TEMPLATE_SHA256, "FAIL_TEMPLATE")
    b = types.ModuleType("pilot2_bootstrap")
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
                      "assetsVerified": 10, "traceboltProgramsExecuted": False, "installerExecuted": False,
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
    parser.add_argument("--verify-published-pilot2", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    try:
        args = parser.parse_args()
        check_context(args.output, args.verify_published_pilot2)
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
