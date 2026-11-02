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

PHASES = frozenset({"approval", "source", "toolchain", "rust-build", "go-link", "provenance"})
CHECKS = frozenset({"ci-context", "checkout-before", "output-directory", "build-environment",
    "tool-go-path", "tool-go-file", "tool-rustup-path", "tool-rustup-file", "tool-gcc-path", "tool-gcc-file",
    "go-version", "gcc-target", "rustup-install", "rust-version", "rustc-path", "go-mod-download", "go-mod-verify",
    "rust-first-build", "rust-first-archive", "rust-clean", "rust-second-build", "rust-repeat-equality",
    "go-first-link", "go-second-link", "go-first-image", "go-repeat-equality", "go-vet", "image-read",
    "compiled-source-presence", "go-build-info-read", "project-dependencies-read", "project-dependencies",
    "checkout-after", "tool-go-hash", "tool-rustc-hash", "tool-gcc-hash", "tool-rustup-hash",
    "manifest-contract", "manifest-write"}) | frozenset(provenance.PE_CHECKS) | frozenset(provenance.GO_INFO_CHECKS)

class Progress:
    """Fixed labels only: never carry command output, paths, names or values."""
    def __init__(self):
        self.phase, self.check = "approval", "ci-context"
    def mark(self, phase, check):
        contract.need(type(phase) is str and type(check) is str and phase in PHASES and check in CHECKS, "provenance")
        self.phase, self.check = phase, check
    def projection(self):
        return {"phase": self.phase if type(self.phase) is str and self.phase in PHASES else "unexpected",
                "check": self.check if type(self.check) is str and self.check in CHECKS else "unexpected"}

class Builder:
    def __init__(self, root, output, source, env, state, progress=None):
        self.root, self.output, self.source, self.context, self.state = root, output, source, env, state
        self.stage, self.end = "toolchain", time.monotonic() + 12 * 60
        self.progress = progress if progress is not None else Progress()
        self.check("build-environment")
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
        label = {"go.exe": "tool-go", "rustup.exe": "tool-rustup", "gcc.exe": "tool-gcc"}[name]
        self.check(label + "-path")
        path = shutil.which(name)
        contract.need(path is not None and Path(path).is_absolute() and Path(path).suffix.lower() == ".exe"
                      and not Path(path).resolve().is_relative_to(self.root.resolve()), "provenance")
        self.check(label + "-file")
        hash_file(path)
        return path

    def check(self, label):
        self.progress.mark(self.stage, label)

    def tool_hash(self, label, path):
        self.check(label)
        return hash_file(path)[0]

    def run(self, argv, *, capture=False, limit=300):
        left = self.end - time.monotonic()
        contract.need(left > 0, "deadline")
        result = subprocess.run(argv, cwd=self.root, env=self.env, check=True,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=min(left, limit))
        raw = result.stdout if capture else b""
        contract.need(len(raw) <= 65536, "provenance")
        return raw

    def crt_diagnostic(self, image, image_hash):
        # Evidence only after the original guard rejects a known CRT contract.
        # Any uncertainty discards both vectors; the caller always re-raises.
        evidence = runner.manual.source_only("rust_gui_crt_evidence", "ci_crt_evidence.py")
        result = evidence.unavailable()
        try:
            contract.need(self.context.get("IMAGEOS") in {"win25", "win25-vs2026"} and provenance.SYSTEM_DLLS == evidence.BASELINE, "provenance")
            contract.need(policy.source_state(self.root, self.source, self.context) == self.state, "source")
            tool = Path(self.gcc).with_name("objdump.exe")
            contract.need(tool.is_absolute() and not tool.resolve().is_relative_to(self.root.resolve())
                          and not tool.resolve().is_relative_to(self.output.resolve()), "provenance")
            tool_hash, gcc_hash = hash_file(tool), hash_file(self.gcc)
            native = evidence.Native()
            # Retain all read-only ancestor/file leases across independent inspection,
            # schema query and final source verification; no write/delete sharing.
            with native.lease(image, image_hash[0]), native.lease(tool, tool_hash[0]), native.lease(self.gcc, gcc_hash[0]):
                left = self.end - time.monotonic()
                contract.need(left > 0, "deadline")
                raw = evidence.run_bounded([str(tool), "-p", str(image)], self.root, self.env, limit=min(left, 20))
                required = evidence.inspect_objdump(raw, image)
                available = native.schema()
                contract.need(hash_file(image) == image_hash and hash_file(tool) == tool_hash
                              and hash_file(self.gcc) == gcc_hash, "provenance")
                contract.need(policy.source_state(self.root, self.source, self.context) == self.state, "source")
                observed = evidence.projection(required, available)
            # Cleanup must also succeed before any observation can be exported.
            result = {**observed, **self.state, "imageSHA256": image_hash[0], "imageSize": image_hash[1]}
        except Exception:
            pass  # No paths, raw tool output, import names or exception text.
        return result

    def inspect_image(self, raw, image, image_hash):
        try:
            return provenance.inspect_pe(raw, checkpoint=self.check)
        except ValueError:
            if self.progress.projection() == {"phase": "provenance", "check": "pe-import-rejected-known-crt-contract"}:
                self.crt_evidence = self.crt_diagnostic(image, image_hash)
            raise  # Diagnostic evidence never changes the original admission decision.

    def build(self):
        self.check("go-version")
        contract.need(self.run([self.go, "env", "GOVERSION"], capture=True).strip() == b"go1.27.1", "provenance")
        self.check("gcc-target")
        contract.need(self.run([self.gcc, "-dumpmachine"], capture=True).strip() == b"x86_64-w64-mingw32", "provenance")
        self.check("rustup-install")
        self.run([self.rustup, "toolchain", "install", "1.99.1", "--profile", "minimal", "--target", "x86_64-pc-windows-gnu", "--no-self-update"])
        self.check("rust-version")
        version = self.run([self.rustup, "run", "1.99.1", "rustc", "--version"], capture=True)
        contract.need(version.startswith(b"rustc 1.99.1 (") and len(version) <= 128, "provenance")
        self.check("rustc-path")
        rustc = self.run([self.rustup, "which", "--toolchain", "1.99.1", "rustc"], capture=True).strip().decode("utf-8")
        self.env["RUSTC"] = rustc
        self.check("go-mod-download")
        self.run([self.go, "mod", "download"])
        self.check("go-mod-verify")
        self.run([self.go, "mod", "verify"])
        self.stage = "rust-build"
        cargo = [self.rustup, "run", "1.99.1", "cargo"]
        build = [*cargo, "build", "--locked", "--manifest-path", "rust/windows-setup/Cargo.toml", "--target", "x86_64-pc-windows-gnu", "--release"]
        self.check("rust-first-build")
        self.run(build)
        archive = self.output / "target/x86_64-pc-windows-gnu/release/libtracebolt_windows_setup.a"
        self.check("rust-first-archive")
        first_archive = hash_file(archive)
        self.check("rust-clean")
        self.run([*cargo, "clean", "--manifest-path", "rust/windows-setup/Cargo.toml", "--target", "x86_64-pc-windows-gnu", "--release"])
        self.check("rust-second-build")
        self.run(build)
        self.check("rust-repeat-equality")
        contract.need(hash_file(archive) == first_archive, "provenance")
        self.stage = "go-link"
        self.env["CGO_LDFLAGS"] = "-L" + archive.parent.as_posix() + " -static -static-libgcc -Wl,--no-insert-timestamp"
        image, repeat = self.output / policy.IMAGE, self.output / "repeat.test.exe"
        prefix = [self.go, "test", "-c", "-trimpath", "-buildvcs=false", "-mod=readonly", "-ldflags=" + linker_flags(self.source), "-tags=" + provenance.TAGS]
        self.check("go-first-link")
        self.run([*prefix, "-o", str(image), "./internal/windowssetupui"])
        self.check("go-second-link")
        self.run([*prefix, "-o", str(repeat), "./internal/windowssetupui"])
        self.check("go-first-image")
        image_hash = hash_file(image)
        self.check("go-repeat-equality")
        contract.need(image_hash == hash_file(repeat), "provenance")
        self.check("go-vet")
        self.run([self.go, "vet", "-tags=" + provenance.TAGS, "./internal/windowssetupui"])
        self.stage = "provenance"
        self.check("image-read")
        raw = image.read_bytes()
        pe = self.inspect_image(raw, image, image_hash)
        self.check("compiled-source-presence")
        contract.need(self.source.encode() in raw, "provenance")
        self.check("go-build-info-read")
        go_info = provenance.inspect_go_build_info(self.run([self.go, "version", "-m", str(image)], capture=True), self.source, checkpoint=self.check)
        self.check("project-dependencies-read")
        dependencies = self.run([self.go, "list", "-deps", "-test", "-tags=" + provenance.TAGS, "./internal/windowssetupui"], capture=True).decode("utf-8").splitlines()
        dependencies = [item for item in dependencies if item.startswith("localrmm")]
        self.check("project-dependencies")
        contract.need(dependencies == list(provenance.PROJECT_DEPENDENCIES), "provenance")
        self.check("checkout-after")
        contract.need(policy.source_state(self.root, self.source, self.context) == self.state, "source")
        tools = {"goVersion": "go1.27.1", "rustVersion": "1.99.1", "gccTarget": "x86_64-w64-mingw32",
            "goSHA256": self.tool_hash("tool-go-hash", self.go), "rustcSHA256": self.tool_hash("tool-rustc-hash", rustc),
            "gccSHA256": self.tool_hash("tool-gcc-hash", self.gcc), "rustupSHA256": self.tool_hash("tool-rustup-hash", self.rustup)}
        manifest = {"schema": "tracebolt.rust-gui-ci-build.v1", **self.state, "case": "tls", "testName": policy.TEST_NAME,
            "tags": provenance.TAGS.split(","), "image": {"file": policy.IMAGE, "sha256": image_hash[0], "size": image_hash[1], "repeatBuildIdentical": True},
            "rustArchive": {"sha256": first_archive[0], "size": first_archive[1], "repeatBuildIdentical": True},
            "tools": tools, "pe": pe, "goBuild": go_info, "projectDependencies": dependencies,
            "nativeExecution": False, "installerHostActionsAttempted": False}
        self.check("manifest-contract")
        policy.validate_build(manifest, self.state, provenance.TAGS.split(","), provenance.PROJECT_DEPENDENCIES)
        self.check("manifest-write")
        (self.output / "build.json").write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="ascii")
        return manifest

def main(argv=None):
    parser = runner.manual.Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--build-inert-github-tls-fixture", action="store_true")
    parser.add_argument("--source")
    args = parser.parse_args(argv)
    stage, builder, progress = "approval", None, Progress()
    try:
        env = policy.authorization(PLATFORM, args.build_inert_github_tls_fixture, args.source, os.environ)
        stage = "source"
        progress.mark("source", "checkout-before")
        state = policy.source_state(runner.ROOT, args.source, env)
        progress.mark("source", "output-directory")
        output = policy.output_directory(env)
        contract.need(not output.exists(), "source")  # No adoption, overwrite or cleanup fallback.
        output.mkdir()
        builder = Builder(runner.ROOT, output, args.source, env, state, progress)
        manifest = builder.build()
        print(json.dumps({"schema": "tracebolt.rust-gui-ci-build-result.v1", "status": "built_not_executed", **state,
            "case": "tls", "imageSHA256": manifest["image"]["sha256"], "rustArchiveSHA256": manifest["rustArchive"]["sha256"],
            "nativeExecution": False, "installerHostActionsAttempted": False}, sort_keys=True))
        return 0
    except contract.Failure as error:
        stage = error.stage
    except Exception:
        stage = builder.stage if builder is not None else stage
    if type(stage) is not str or stage not in PHASES and stage not in contract.STAGES:
        stage = "unexpected"
    diagnostic = {}
    if builder is not None and getattr(builder, "crt_evidence", None) is not None:
        try:
            evidence = runner.manual.source_only("rust_gui_crt_evidence", "ci_crt_evidence.py")
            diagnostic["crtEvidence"] = evidence.public_report(builder.crt_evidence)
        except Exception:
            pass  # A diagnostic-loader failure must not export a traceback/path.
    print(json.dumps({"schema": "tracebolt.rust-gui-ci-build-result.v1", "status": "not_built", "stage": stage, **diagnostic,
                      **progress.projection(), "nativeExecution": False, "installerHostActionsAttempted": False}, sort_keys=True))
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
