"""Inert packaging contracts; no container, initializer or host action runs."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class OperatorAccountInitPackagingTests(unittest.TestCase):
    def test_standard_build_includes_factor_client_without_running_it(self):
        build = (ROOT / "Makefile").read_text().split("\nbuild:\n", 1)[1].split("\ntest:\n", 1)[0]
        self.assertRegex(
            build,
            r"(?m)^\tgo build -buildvcs=false -trimpath -o bin/operator-factor ./cmd/operator-factor$",
        )
        self.assertEqual(build.count("./cmd/operator-factor"), 1)
        self.assertNotRegex(build, r"(?m)^\t(?:\./)?bin/operator-factor\b")

    def test_container_copies_factor_client_without_activation_or_host_changes(self):
        builder, runtime = (ROOT / "Dockerfile").read_text().split("FROM scratch AS runtime\n", 1)
        self.assertRegex(
            builder,
            re.escape("CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build ")
            + r"[^\n]* -o /out/operator-factor ./cmd/operator-factor(?: \\\n|\n)",
        )
        self.assertEqual(builder.count("./cmd/operator-factor"), 1)
        self.assertEqual(runtime.splitlines().count("COPY --from=build /out/operator-factor /tracebolt/operator-factor"), 1)
        self.assertIn("USER 65532:65532\n", runtime)
        self.assertIn('ENTRYPOINT ["/tracebolt/manager"]\n', runtime)
        self.assertNotIn("RUN ", runtime)
        self.assertNotRegex(builder, r"(?:RUN|&&)\s+/out/operator-factor\b")

    def test_standard_build_includes_initializer(self):
        build = (ROOT / "Makefile").read_text().split("\nbuild:\n", 1)[1].split("\ntest:\n", 1)[0]
        self.assertRegex(
            build,
            r"(?m)^\tgo build -buildvcs=false -trimpath -o bin/operator-account-init ./cmd/operator-account-init$",
        )
        self.assertEqual(build.count("./cmd/operator-account-init"), 1)
        self.assertNotRegex(build, r"(?m)^\t(?:\./)?bin/operator-account-init\b")

    def test_container_builds_static_tool_and_copies_same_output(self):
        builder, runtime = (ROOT / "Dockerfile").read_text().split("FROM scratch AS runtime\n", 1)
        self.assertRegex(
            builder,
            re.escape("CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build ")
            + r"[^\n]* -o /out/operator-account-init ./cmd/operator-account-init(?: \\\n|\n)",
        )
        self.assertEqual(builder.count("./cmd/operator-account-init"), 1)
        self.assertEqual(
            runtime.splitlines().count(
                "COPY --from=build /out/operator-account-init /tracebolt/operator-account-init"
            ),
            1,
        )
        self.assertIn("USER 65532:65532\n", runtime)
        self.assertIn('ENTRYPOINT ["/tracebolt/manager"]\n', runtime)
        self.assertIn('CMD ["--lan-config", "/run/tracebolt/lan.json"]\n', runtime)
        self.assertNotIn("RUN ", runtime)
        self.assertNotRegex(builder, r"(?:RUN|&&)\s+/out/operator-account-init\b")


if __name__ == "__main__":
    unittest.main()
