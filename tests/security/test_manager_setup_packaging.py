"""Inert source contracts: these tests do not build or start a container."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


class ManagerSetupPackagingTests(unittest.TestCase):
    def test_standard_build_includes_manager_setup(self):
        makefile = (ROOT / "Makefile").read_text()
        build = makefile.split("\nbuild:\n", 1)[1].split("\ntest:\n", 1)[0]
        self.assertRegex(
            build,
            r"(?m)^\tgo build -buildvcs=false -trimpath -o bin/manager-setup ./cmd/manager-setup$",
        )

    def test_container_builds_and_copies_same_source_tool(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        builder, runtime = dockerfile.split("FROM scratch AS runtime\n", 1)
        self.assertRegex(
            builder,
            re.escape("CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build ")
            + r"[^\n]* -o /out/manager-setup ./cmd/manager-setup(?: \\\n|\n)",
        )
        self.assertEqual(
            runtime.splitlines().count(
                "COPY --from=build /out/manager-setup /tracebolt/manager-setup"
            ),
            1,
        )
        # Adding an inert CLI must not replace startup or elevate the runtime.
        self.assertIn("USER 65532:65532\n", runtime)
        self.assertIn('ENTRYPOINT ["/tracebolt/manager"]\n', runtime)
        self.assertIn('CMD ["--lan-config", "/run/tracebolt/lan.json"]\n', runtime)
        self.assertNotIn("RUN ", runtime)


if __name__ == "__main__":
    unittest.main()
