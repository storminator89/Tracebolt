#!/usr/bin/env python3
"""Build one source-bound inert CI test EXE, never Setup/service or native acceptance."""
import sys
if not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Inert GUI CI build requires Python -I -B; no action attempted.")
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import types

HERE = Path(__file__).resolve().parent
path = HERE / "run_ci.py"
if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024:
    raise SystemExit("Local inert GUI build source unavailable; no action attempted.")
runner = types.ModuleType("rust_gui_ci_runner")
runner.__file__ = str(path)
sys.modules[runner.__name__] = runner
exec(compile(path.read_bytes(), str(path), "exec"), runner.__dict__)
contract, policy, provenance = runner.contract, runner.policy, runner.provenance
PLATFORM = os.name

def hash_file(path):
    path = Path(path)
    contract.need(path.is_file() and not path.is_symlink() and 512 <= path.stat().st_size <= 128 * 1024 * 1024, "provenance")
    size = path.stat().st_size
    raw = path.read_bytes()
    contract.need(len(raw) == size, "provenance")
    return hashlib.sha256(raw).hexdigest(), size

def linker_flags(source):
    contract.need(policy.COMMIT.fullmatch(source or ""), "source")
    return "-buildid= -s -w -linkmode=external -X localrmm/internal/windowssetupui.fixtureCIBuildSource=" + source

class Builder:
    def __init__(self, root, output, source, env, state):
        self.root, self.output, self.source, self.context, self.state = root, output, source, env, state
        self.stage, self.end = "toolchain", time.monotonic() + 12 * 60
        self.env = dict(os.environ)
        # Job-local caches and toolchain custody, not host configuration changes.
        for key in list(self.env):
            if key.upper().startswith("CARGO_PROFILE_") or key.upper() in {"RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"}:
                self.env.pop(key)
        self.env.update(GOTOOLCHAIN="local", GOENV="off", GOWORK="off", GOFLAGS="", GOOS="windows", GOARCH="amd64",
            CGO_ENABLED="1", GOAMD64="v1", GOEXPERIMENT="", GOPATH=str(output / "gopath"),
            GOCACHE=str(output / "gocache"), GOMODCACHE=str(output / "gopath/pkg/mod"),
            APPDATA=str(output / "appdata"), LOCALAPPDATA=str(output / "localappdata"),
            CARGO_HOME=str(output / "cargo"), RUSTUP_HOME=str(output / "rustup"), CARGO_TARGET_DIR=str(output / "target"),
            RUSTUP_TOOLCHAIN="1.99.1", RUSTUP_DIST_SERVER="https://static.rust-lang.org",
            RUSTUP_UPDATE_ROOT="https://static.rust-lang.org/rustup", RUSTFLAGS="", CARGO_ENCODED_RUSTFLAGS="",
            CGO_CFLAGS="", CGO_CPPFLAGS="", CGO_CXXFLAGS="", CGO_FFLAGS="")
        self.go, self.rustup, self.gcc = (self.tool(name) for name in ("go.exe", "rustup.exe", "gcc.exe"))
        self.env["PATH"] = str(Path(self.gcc).parent) + os.pathsep + self.env.get("PATH", "")
        self.env["CC"] = self.gcc
        self.env["CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER"] = self.gcc

    def tool(self, name):
        path = shutil.which(name)
        contract.need(path is not None and Path(path).is_absolute() and Path(path).suffix.lower() == ".exe"
                      and not Path(path).resolve().is_relative_to(self.root.resolve()), "provenance")
        hash_file(path)
        return path

    def run(self, argv, *, capture=False, limit=300):
        left = self.end - time.monotonic()
        contract.need(left > 0, "deadline")
        result = subprocess.run(argv, cwd=self.root, env=self.env, check=True,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=min(left, limit))
        raw = result.stdout if capture else b""
        contract.need(len(raw) <= 65536, "provenance")
        return raw

    def build(self):
        contract.need(self.run([self.go, "env", "GOVERSION"], capture=True).strip() == b"go1.27.1", "provenance")
        contract.need(self.run([self.gcc, "-dumpmachine"], capture=True).strip() == b"x86_64-w64-mingw32", "provenance")
        self.run([self.rustup, "toolchain", "install", "1.99.1", "--profile", "minimal", "--target", "x86_64-pc-windows-gnu", "--no-self-update"])
        version = self.run([self.rustup, "run", "1.99.1", "rustc", "--version"], capture=True)
        contract.need(version.startswith(b"rustc 1.99.1 (") and len(version) <= 128, "provenance")
        rustc = self.run([self.rustup, "which", "--toolchain", "1.99.1", "rustc"], capture=True).strip().decode("utf-8")
        self.env["RUSTC"] = rustc
        self.run([self.go, "mod", "download"])
        self.run([self.go, "mod", "verify"])
        self.stage = "rust-build"
        cargo = [self.rustup, "run", "1.99.1", "cargo"]
        build = [*cargo, "build", "--locked", "--manifest-path", "rust/windows-setup/Cargo.toml", "--target", "x86_64-pc-windows-gnu", "--release"]
        self.run(build)
        archive = self.output / "target/x86_64-pc-windows-gnu/release/libtracebolt_windows_setup.a"
        first_archive = hash_file(archive)
        self.run([*cargo, "clean", "--manifest-path", "rust/windows-setup/Cargo.toml", "--target", "x86_64-pc-windows-gnu", "--release"])
        self.run(build)
        contract.need(hash_file(archive) == first_archive, "provenance")
        self.stage = "go-link"
        self.env["CGO_LDFLAGS"] = "-L" + archive.parent.as_posix() + " -static -static-libgcc -Wl,--no-insert-timestamp"
        image, repeat = self.output / policy.IMAGE, self.output / "repeat.test.exe"
        prefix = [self.go, "test", "-c", "-trimpath", "-buildvcs=false", "-mod=readonly", "-ldflags=" + linker_flags(self.source), "-tags=" + provenance.TAGS]
        self.run([*prefix, "-o", str(image), "./internal/windowssetupui"])
        self.run([*prefix, "-o", str(repeat), "./internal/windowssetupui"])
        image_hash = hash_file(image)
        contract.need(image_hash == hash_file(repeat), "provenance")
        self.run([self.go, "vet", "-tags=" + provenance.TAGS, "./internal/windowssetupui"])
        self.stage = "provenance"
        raw = image.read_bytes()
        pe = provenance.inspect_pe(raw)
        contract.need(self.source.encode() in raw, "provenance")
        go_info = provenance.inspect_go_build_info(self.run([self.go, "version", "-m", str(image)], capture=True), self.source)
        dependencies = self.run([self.go, "list", "-deps", "-test", "-tags=" + provenance.TAGS, "./internal/windowssetupui"], capture=True).decode("utf-8").splitlines()
        dependencies = [item for item in dependencies if item.startswith("localrmm")]
        contract.need(dependencies == list(provenance.PROJECT_DEPENDENCIES), "provenance")
        contract.need(policy.source_state(self.root, self.source, self.context) == self.state, "source")
        tools = {"goVersion": "go1.27.1", "rustVersion": "1.99.1", "gccTarget": "x86_64-w64-mingw32",
            "goSHA256": hash_file(self.go)[0], "rustcSHA256": hash_file(rustc)[0],
            "gccSHA256": hash_file(self.gcc)[0], "rustupSHA256": hash_file(self.rustup)[0]}
        manifest = {"schema": "tracebolt.rust-gui-ci-build.v1", **self.state, "case": "tls", "testName": policy.TEST_NAME,
            "tags": provenance.TAGS.split(","), "image": {"file": policy.IMAGE, "sha256": image_hash[0], "size": image_hash[1], "repeatBuildIdentical": True},
            "rustArchive": {"sha256": first_archive[0], "size": first_archive[1], "repeatBuildIdentical": True},
            "tools": tools, "pe": pe, "goBuild": go_info, "projectDependencies": dependencies,
            "nativeExecution": False, "installerHostActionsAttempted": False}
        policy.validate_build(manifest, self.state, provenance.TAGS.split(","), provenance.PROJECT_DEPENDENCIES)
        (self.output / "build.json").write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="ascii")
        return manifest

def main(argv=None):
    parser = runner.manual.Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--build-inert-github-tls-fixture", action="store_true")
    parser.add_argument("--source")
    args = parser.parse_args(argv)
    stage, builder = "approval", None
    try:
        env = policy.authorization(PLATFORM, args.build_inert_github_tls_fixture, args.source, os.environ)
        stage = "source"
        state = policy.source_state(runner.ROOT, args.source, env)
        output = policy.output_directory(env)
        contract.need(not output.exists(), "source")  # No adoption, overwrite or cleanup fallback.
        output.mkdir()
        builder = Builder(runner.ROOT, output, args.source, env, state)
        manifest = builder.build()
        print(json.dumps({"schema": "tracebolt.rust-gui-ci-build-result.v1", "status": "built_not_executed", **state,
            "case": "tls", "imageSHA256": manifest["image"]["sha256"], "rustArchiveSHA256": manifest["rustArchive"]["sha256"],
            "nativeExecution": False, "installerHostActionsAttempted": False}, sort_keys=True))
        return 0
    except contract.Failure as error:
        stage = error.stage
    except Exception:
        stage = builder.stage if builder is not None else stage
    print(json.dumps({"schema": "tracebolt.rust-gui-ci-build-result.v1", "status": "not_built", "stage": stage,
                      "nativeExecution": False, "installerHostActionsAttempted": False}, sort_keys=True))
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
