"""PR201-only inert TLS CI configuration. Importing this has no native effect."""
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
from rust_gui_contract import need

ACK = "github-actions-pr201-tls-only-v1"
IMAGE = "windowssetupui-inert-tls-ci.test.exe"
DIRECTORY = "tracebolt-rust-gui-ci"
TEST_NAME = "TestRustNativeGUITLSCI"
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
NUMBER = re.compile(r"[1-9][0-9]{0,19}\Z")
OTHER_CI = {"GITLAB_CI", "BUILD_BUILDID", "TF_BUILD", "JENKINS_URL", "CONTINUOUS_INTEGRATION",
            "TEAMCITY_VERSION", "CIRCLECI", "BUILDKITE"}

def authorization(platform, acknowledged, source, values):
    need(acknowledged is True, "approval")
    need(platform == "nt", "platform")
    need(type(source) is str and COMMIT.fullmatch(source), "ci")
    env = {}
    for key, value in values.items():
        key = key.upper()
        need(key not in env, "ci")
        env[key] = value
    exact = {"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": "storminator89/Tracebolt", "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REF": "refs/pull/201/merge", "GITHUB_JOB": "rust-gui-tls",
        "GITHUB_WORKFLOW": "Build unsigned Windows Setup candidates",
        "GITHUB_WORKFLOW_REF": "storminator89/Tracebolt/.github/workflows/windows-setup-build.yml@refs/pull/201/merge",
        "GITHUB_SHA": source, "GITHUB_WORKFLOW_SHA": source,
        "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64",
        "TRACEBOLT_RUST_GUI_CI": ACK, "TRACEBOLT_RUST_GUI_CI_SOURCE": source}
    need(all(env.get(key) == value for key, value in exact.items()) and not OTHER_CI.intersection(env), "ci")
    need(all(COMMIT.fullmatch(env.get(key, "")) for key in ("TRACEBOLT_RUST_GUI_CI_HEAD", "TRACEBOLT_RUST_GUI_CI_BASE")), "ci")
    need(all(NUMBER.fullmatch(env.get(key, "")) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")), "ci")
    for key, value in {"TRACEBOLT_RUST_GUI_FIXTURE_CASE": "tls", "TRACEBOLT_RUST_GUI_FIXTURE_EXECUTE": "synthetic-window-only-v1"}.items():
        need(key not in env or env[key] == value, "ci")
    return env

def git(root, args):
    result = subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, timeout=15)
    need(len(result.stdout) <= 1024 * 1024, "source")
    return result.stdout

def source_state(root, source, env, run_git=git):
    root = Path(root)
    workspace = Path(env.get("GITHUB_WORKSPACE", ""))
    need(workspace.is_absolute() and os.path.normcase(str(root.resolve())) == os.path.normcase(str(workspace.resolve())), "source")
    need(run_git(root, ["rev-parse", "HEAD"]).strip() == source.encode(), "source")
    parents = run_git(root, ["rev-list", "--parents", "-n", "1", "HEAD"]).strip().split()
    need(parents == [source.encode(), env["TRACEBOLT_RUST_GUI_CI_BASE"].encode(), env["TRACEBOLT_RUST_GUI_CI_HEAD"].encode()], "source")
    need(not run_git(root, ["status", "--porcelain", "--untracked-files=all"]), "source")
    tree = run_git(root, ["rev-parse", "HEAD^{tree}"]).strip().decode("ascii")
    need(COMMIT.fullmatch(tree), "source")
    files = run_git(root, ["ls-files", "-z", "go.mod", "go.sum", "internal/windowssetupui", "rust/windows-setup",
                           "tests/windows_setup_rust_gui", ".github/workflows/windows-setup-build.yml"]).split(b"\0")
    need(files[-1:] == [b""] and 4 <= len(files) <= 257, "source")
    digest, total = hashlib.sha256(), 0
    for item in sorted(files[:-1]):
        name = item.decode("utf-8")
        path = root / name
        need(not path.is_symlink() and path.resolve().is_relative_to(root.resolve())
             and stat.S_ISREG(path.stat().st_mode), "source")
        size = path.stat().st_size
        total += size
        need(0 <= size <= 4 * 1024 * 1024 and total <= 4 * 1024 * 1024, "source")
        raw = path.read_bytes()
        need(len(raw) == size, "source")
        digest.update(item + b"\0" + hashlib.sha256(raw).digest())
    return {"sourceCommit": source, "sourceTree": tree, "sourceInputsSHA256": digest.hexdigest()}

def output_directory(env):
    temporary = Path(env.get("RUNNER_TEMP", ""))
    need(temporary.is_absolute() and temporary.is_dir() and not temporary.is_symlink(), "source")
    output = temporary / DIRECTORY
    workspace = Path(env.get("GITHUB_WORKSPACE", ""))
    need(workspace.is_absolute() and output.parent.resolve() == temporary.resolve()
         and not output.resolve().is_relative_to(workspace.resolve())
         and not workspace.resolve().is_relative_to(output.resolve()), "source")
    return output

def validate_build(value, state, tags, dependencies):
    keys = {"schema", "sourceCommit", "sourceTree", "sourceInputsSHA256", "case", "testName", "tags",
            "image", "rustArchive", "tools", "pe", "goBuild", "projectDependencies", "nativeExecution",
            "installerHostActionsAttempted"}
    need(type(value) is dict and set(value) == keys and value["schema"] == "tracebolt.rust-gui-ci-build.v1", "provenance")
    need(set(state) == {"sourceCommit", "sourceTree", "sourceInputsSHA256"}
         and COMMIT.fullmatch(state["sourceCommit"]) and COMMIT.fullmatch(state["sourceTree"])
         and DIGEST.fullmatch(state["sourceInputsSHA256"]), "provenance")
    need(all(value[key] == expected for key, expected in state.items())
         and value["case"] == "tls" and value["testName"] == TEST_NAME
         and value["tags"] == tags and value["projectDependencies"] == list(dependencies)
         and value["nativeExecution"] is False and value["installerHostActionsAttempted"] is False, "provenance")
    for key in ("image", "rustArchive"):
        item = value[key]
        expected_keys = {"sha256", "size", "repeatBuildIdentical"} | ({"file"} if key == "image" else set())
        need(type(item) is dict and set(item) == expected_keys and type(item["sha256"]) is str
             and DIGEST.fullmatch(item["sha256"]) and type(item["size"]) is int
             and 512 <= item["size"] <= 128 * 1024 * 1024 and item["repeatBuildIdentical"] is True, "provenance")
    need(value["image"]["file"] == IMAGE, "provenance")
    tools = value["tools"]
    need(type(tools) is dict and set(tools) == {"goVersion", "rustVersion", "gccTarget", "goSHA256", "rustcSHA256", "gccSHA256", "rustupSHA256"}
         and tools["goVersion"] == "go1.27.1" and tools["rustVersion"] == "1.99.1"
         and tools["gccTarget"] == "x86_64-w64-mingw32", "provenance")
    need(all(type(tools[key]) is str and DIGEST.fullmatch(tools[key])
             for key in ("goSHA256", "rustcSHA256", "gccSHA256", "rustupSHA256")), "provenance")
    return value

def parse_source_ack(raw, source):
    need(type(raw) is bytes and len(raw) <= 65536 and COMMIT.fullmatch(source or ""), "fixture-report")
    rows = [line.removeprefix(b"RUST_GUI_FIXTURE_CI_SOURCE ") for line in raw.split(b"\n")[:-1]
            if line.startswith(b"RUST_GUI_FIXTURE_CI_SOURCE ")]
    need(rows == [source.encode()], "fixture-report")
