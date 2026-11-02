"""Portable synthetic-file negative tests; never Windows image execution."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("rust_gui_ci_provenance", HERE / "ci_provenance.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def pe_fixture(names=(b"KERNEL32.dll", b"kernel32.dll", b"user32.dll")):
    raw = bytearray(2048)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3C, 0x80)
    raw[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", raw, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x22)
    optional = 0x98
    struct.pack_into("<H", raw, optional, 0x20B)
    struct.pack_into("<II", raw, optional + 56, 0x2000, 0x200)
    struct.pack_into("<H", raw, optional + 68, 3)
    struct.pack_into("<I", raw, optional + 108, 16)
    struct.pack_into("<II", raw, optional + 120, 0x1000, 0x500)
    struct.pack_into("<8sIIIIIIHHI", raw, optional + 240,
                     b".idata\0\0", 0x600, 0x1000, 0x600, 0x200, 0, 0, 0, 0, 0xC0000040)
    for index, name in enumerate(names):
        name_offset = 0x300 + index * 96
        struct.pack_into("<IIIII", raw, 0x200 + index * 20,
                         0x1480, 0, 0, 0x1000 + name_offset - 0x200, 0x1488)
        raw[name_offset:name_offset + len(name) + 1] = name + b"\0"
    return raw


SOURCE = "a" * 40
FLAGS = "-buildid= -s -w -linkmode=external -X localrmm/internal/windowssetupui.fixtureCIBuildSource=" + SOURCE


def info_fixture(*, flags=None):
    return ("C:\\private-fixture\\gui.test.exe: go1.27.1\n"
            "\tpath\tlocalrmm/internal/windowssetupui.test\n"
            "\tmod\tlocalrmm\t(devel)\t\n"
            "\tdep\tgolang.org/x/sys\tv0.42.0\th1:invented\n"
            "\tbuild\t-buildmode=exe\n"
            "\tbuild\t-compiler=gc\n"
            + ("\tbuild\t-ldflags=" + flags + "\n" if flags is not None else "") +
            "\tbuild\t-tags=" + p.TAGS + "\n"
            "\tbuild\t-trimpath=true\n"
            "\tbuild\tCGO_ENABLED=1\n"
            "\tbuild\tGOARCH=amd64\n"
            "\tbuild\tGOOS=windows\n").encode()


class PEProvenanceTests(unittest.TestCase):
    def reject(self, raw):
        with self.assertRaisesRegex(ValueError, "^provenance$"):
            p.inspect_pe(raw)

    def test_actual_header_fields_and_imports_project_finite_values(self):
        self.assertEqual(p.inspect_pe(bytes(pe_fixture())), {
            "architecture": "amd64", "subsystem": "console", "timestamp": 0,
            "authenticode": "unsigned", "imports": ["kernel32.dll", "user32.dll"]})

    def test_hosted_ucrt_os_component_is_finite_not_a_runtime_wildcard(self):
        self.assertEqual(p.inspect_pe(bytes(pe_fixture((b"KERNEL32.dll", b"ucrtbase.dll"))))["imports"], ["kernel32.dll", "ucrtbase.dll"])
        for name in [b"api-ms-win-crt-conio-l1-1-0.dll", b"libgcc_s_seh-1.dll", b"libwinpthread-1.dll", b"libstdc++-6.dll"]:
            self.reject(bytes(pe_fixture((name,))))

    def test_exact_eight_hosted_contracts_extend_only_the_inert_import_policy(self):
        baseline = {"kernel32.dll", "msvcrt.dll", "ntdll.dll", "userenv.dll", "ws2_32.dll",
            "api-ms-win-core-synch-l1-2-0.dll", "bcryptprimitives.dll", "gdi32.dll",
            "user32.dll", "dbghelp.dll", "ucrtbase.dll"}
        observed = {
            "api-ms-win-crt-environment-l1-1-0.dll", "api-ms-win-crt-heap-l1-1-0.dll",
            "api-ms-win-crt-locale-l1-1-0.dll", "api-ms-win-crt-math-l1-1-0.dll",
            "api-ms-win-crt-private-l1-1-0.dll", "api-ms-win-crt-runtime-l1-1-0.dll",
            "api-ms-win-crt-stdio-l1-1-0.dll", "api-ms-win-crt-string-l1-1-0.dll"}
        self.assertEqual(p.SYSTEM_DLLS, frozenset(baseline))
        self.assertEqual(p.EVIDENCED_CRT_DLLS, frozenset(observed))
        self.assertEqual(p.ALLOWED_DLLS, frozenset(baseline | observed))
        self.assertEqual(len(p.ALLOWED_DLLS), 19)
        for name in observed:
            raw = bytes(pe_fixture((b"KERNEL32.dll", name.upper().encode())))
            seen = []
            self.assertEqual(p.inspect_pe(raw, checkpoint=seen.append)["imports"], sorted(["kernel32.dll", name]))
            self.assertFalse(any(label.startswith("pe-import-rejected-") for label in seen))
            for changed in [name.replace("l1-1-0", "l1-2-0"), name + ".other", "C:\\" + name,
                            "./" + name, "prefix-" + name, name.replace("api-ms-", "ext-ms-")]:
                self.reject(bytes(pe_fixture((changed.encode(),))))
        for family in ("conio", "convert", "filesystem", "multibyte", "process", "time", "utility"):
            self.reject(bytes(pe_fixture((("api-ms-win-crt-" + family + "-l1-1-0.dll").encode(),))))

    def test_approved_crt_prefix_does_not_hide_later_foreign_runtime(self):
        observed = sorted(name.encode() for name in p.EVIDENCED_CRT_DLLS)
        self.assertEqual(p.inspect_pe(bytes(pe_fixture(tuple(observed))))["imports"], sorted(p.EVIDENCED_CRT_DLLS))
        seen = []
        raw = bytes(pe_fixture((b"api-ms-win-crt-stdio-l1-1-0.dll", b"libwinpthread-1.dll")))
        with self.assertRaisesRegex(ValueError, "^provenance$"):
            p.inspect_pe(raw, checkpoint=seen.append)
        self.assertEqual(seen[-1], "pe-import-rejected-compiler-runtime-shaped")
        self.assertNotIn("pe-import-rejected-known-crt-contract", seen)

    def test_rejected_import_categories_never_admit_or_export_a_name(self):
        crt = [b"api-ms-win-crt-" + family.encode() + b"-l1-1-0.dll" for family in
               ("conio", "convert", "filesystem", "multibyte", "process", "time", "utility")]
        groups = [(crt, "pe-import-rejected-known-crt-contract"),
            ([b"bcrypt.dll", b"comdlg32.dll"], "pe-import-rejected-declared-system-link"),
            ([b"libgcc_s_seh-1.dll", b"libwinpthread-1.dll", b"libstdc++-6.dll", b"libssp-0.dll"], "pe-import-rejected-compiler-runtime-shaped"),
            ([b"api-ms-win-example-l1-1-0.dll", b"ext-ms-example-l9-9-9.dll"], "pe-import-rejected-api-set-shaped"),
            ([b"invented-private-marker.dll", b"C:\\invented-private-marker.dll", b"libgcc_private_marker.dll"], "pe-import-rejected-other")]
        for names, check in groups:
            for name in names:
                raw = bytes(pe_fixture((name,)))
                self.reject(raw)
                seen = []
                with self.assertRaisesRegex(ValueError, "^provenance$"):
                    p.inspect_pe(raw, checkpoint=seen.append)
                self.assertEqual(seen[-1], check)
                self.assertTrue(set(seen) <= set(p.PE_CHECKS))
                self.assertNotIn(name.decode(), json.dumps(seen))

    def test_first_rejected_import_ends_scan_without_a_fingerprint(self):
        seen = []
        raw = bytes(pe_fixture((b"api-ms-win-crt-conio-l1-1-0.dll", b"libwinpthread-1.dll")))
        with self.assertRaisesRegex(ValueError, "^provenance$"):
            p.inspect_pe(raw, checkpoint=seen.append)
        self.assertEqual(seen[-1], "pe-import-rejected-known-crt-contract")
        self.assertNotIn("pe-import-rejected-compiler-runtime-shaped", seen)

    def test_allowed_imports_do_not_generate_rejection_categories(self):
        seen = []
        raw = bytes(pe_fixture((b"kernel32.dll", b"ucrtbase.dll")))
        self.assertEqual(p.inspect_pe(raw), p.inspect_pe(raw, checkpoint=seen.append))
        self.assertFalse(any(label.startswith("pe-import-rejected-") for label in seen))

    def test_machine_timestamp_signature_and_subsystem_cannot_be_promoted(self):
        for offset, fmt, value in [(0x84, "<H", 0xAA64), (0x88, "<I", 1),
                (0x98, "<H", 0x10B), (0x98 + 68, "<H", 2),
                (0x98 + 112 + 4 * 8, "<I", 1800),
                (0x98 + 112 + 4 * 8 + 4, "<I", 4),
                (0x96, "<H", 0x2022)]:
            with self.subTest(offset=offset, value=value):
                raw = pe_fixture(); struct.pack_into(fmt, raw, offset, value); self.reject(bytes(raw))

    def test_malformed_truncated_and_out_of_bounds_headers_are_rejected(self):
        raw = pe_fixture()
        for length in [0, 1, 63, 511, 512, len(raw) - 1]:
            with self.subTest(length=length): self.reject(bytes(raw[:length]))
        for offset, fmt, value in [(0x3C, "<I", 0xFFFFFFFF), (0x86, "<H", 97),
                (0x94, "<H", 4097), (0x98 + 108, "<I", 13),
                (0x98 + 108, "<I", 17), (0x98 + 60, "<I", 1),
                (0x98 + 56, "<I", 0x1001)]:
            with self.subTest(offset=offset, value=value):
                changed = pe_fixture(); struct.pack_into(fmt, changed, offset, value); self.reject(bytes(changed))
        self.reject(bytearray(raw))

    def test_missing_bound_delay_or_managed_import_routes_are_rejected(self):
        for index in [1, 11, 13, 14]:
            with self.subTest(index=index):
                raw = pe_fixture()
                struct.pack_into("<II", raw, 0x98 + 112 + index * 8,
                                 *( (0, 0) if index == 1 else (0x1000, 40) ))
                self.reject(bytes(raw))

    def test_ambiguous_virtual_or_file_section_mapping_is_rejected(self):
        for address in [0x1000, 0x1100, 0x1600]:
            raw = pe_fixture(); struct.pack_into("<H", raw, 0x86, 2)
            struct.pack_into("<8sIIIIIIHHI", raw, 0x98 + 240 + 40,
                             b".other\0\0", 0x100, address, 0x100, 0x500, 0, 0, 0, 0, 0)
            self.reject(bytes(raw))

    def test_import_rva_must_be_unique_file_backed_and_complete(self):
        for offset, value in [(0x98 + 120, 0x1800), (0x98 + 124, 39),
                              (0x98 + 124, 0x601), (0x200 + 12, 0x15FF),
                              (0x200 + 16, 0), (0x200, 0x2000)]:
            raw = pe_fixture(); struct.pack_into("<I", raw, offset, value); self.reject(bytes(raw))

    def test_empty_foreign_path_unicode_and_unterminated_names_are_rejected(self):
        for name in [b"", b"libgcc_s_seh-1.dll", b"attack32.dll", b"C:\\kernel32.dll",
                     b" kernel32.dll", b"kernel32.dll ", b"kernel32.dl\xff", b"x" * 82]:
            with self.subTest(name=name): self.reject(bytes(pe_fixture((name,))))
        raw = pe_fixture((b"kernel32.dll",)); raw[0x300:0x352] = b"x" * 82
        self.reject(bytes(raw))

    def test_import_descriptor_terminator_and_metadata_are_mandatory(self):
        for offset in [0x204, 0x208]:
            raw = pe_fixture(); struct.pack_into("<I", raw, offset, 1); self.reject(bytes(raw))
        raw = pe_fixture(); struct.pack_into("<I", raw, 0x98 + 124, 60)
        self.reject(bytes(raw))
        raw = pe_fixture(()); self.reject(bytes(raw))

    def test_descriptor_count_is_bounded_even_when_names_are_duplicates(self):
        raw = pe_fixture()
        raw[0x200:0x500] = b"\0" * 0x300
        raw[0x600:0x60D] = b"kernel32.dll\0"
        for index in range(32):
            struct.pack_into("<IIIII", raw, 0x200 + index * 20,
                             0x1480, 0, 0, 0x1400, 0x1488)
        self.assertEqual(p.inspect_pe(bytes(raw))["imports"], ["kernel32.dll"])
        struct.pack_into("<IIIII", raw, 0x200 + 32 * 20, 0x1480, 0, 0, 0x1400, 0x1488)
        self.reject(bytes(raw))


class GoBuildInfoTests(unittest.TestCase):
    def reject(self, raw, source=SOURCE):
        with self.assertRaisesRegex(ValueError, "^provenance$"):
            p.inspect_go_build_info(raw, source)

    def test_exact_pinned_build_returns_no_input_path_or_raw_flags(self):
        result = p.inspect_go_build_info(info_fixture(), SOURCE)
        self.assertEqual(result, {"goVersion": "go1.27.1", "path": "localrmm/internal/windowssetupui.test",
            "tags": p.TAGS.split(","), "goos": "windows", "goarch": "amd64", "cgo": True, "embeddedSourceProven": False})
        self.assertNotIn("private-fixture", json.dumps(result))
        self.assertNotIn("ldflags", json.dumps(result))
        self.assertEqual(p.inspect_go_build_info(info_fixture().replace(b"\n", b"\r\n"), SOURCE), result)
        self.assertEqual(p.inspect_go_build_info(info_fixture(), "b" * 40), result)
        self.assertNotIn(SOURCE, json.dumps(result))

    def test_version_path_tags_target_and_cgo_are_exact(self):
        for before, after in [(b"go1.27.1", b"go1.27.2"),
                (b"localrmm/internal/windowssetupui.test", b"localrmm/cmd/windows-service"),
                (p.TAGS.encode(), b"tracebolt_setup_rust,tracebolt_setup_gui_fixture"),
                (p.TAGS.encode(), (p.TAGS + ",extra").encode()),
                (b"GOOS=windows", b"GOOS=linux"), (b"GOARCH=amd64", b"GOARCH=arm64"),
                (b"CGO_ENABLED=1", b"CGO_ENABLED=0"), (b"-trimpath=true", b"-trimpath=false")]:
            with self.subTest(before=before): self.reject(info_fixture().replace(before, after))

    def test_duplicate_settings_paths_and_missing_required_rows_are_rejected(self):
        for row in [b"\tbuild\tGOOS=windows\n", b"\tbuild\t-compiler=gc\n",
                    b"\tpath\tlocalrmm/internal/windowssetupui.test\n"]:
            self.reject(info_fixture() + row)
        for row in [b"\tbuild\tGOOS=windows\n", b"\tbuild\tCGO_ENABLED=1\n",
                    b"\tpath\tlocalrmm/internal/windowssetupui.test\n"]:
            self.reject(info_fixture().replace(row, b""))

    def test_trimpath_build_info_cannot_claim_recorded_source_linker_flags(self):
        for flags in ["", FLAGS, json.dumps(FLAGS), FLAGS.replace(SOURCE, "b" * 40),
                      FLAGS + " -X other.value=1", '"unterminated']:
            self.reject(info_fixture(flags=flags))
        for source in [None, "", "A" * 40, "a" * 39, "a" * 41]:
            self.reject(info_fixture(), source)

    def test_malformed_oversized_control_and_unknown_rows_are_finite_failures(self):
        for raw in [b"", b"x" * (p.MAX_BUILD_INFO + 1), bytearray(info_fixture()),
                    info_fixture()[:-1], info_fixture() + b"\n", info_fixture() + b"\tunknown\tvalue\n",
                    info_fixture().replace(b"GOOS=windows", b"GOOS=win\x00dows"),
                    info_fixture().replace(b"GOOS=windows", b"GOOS=windows\tother"),
                    info_fixture() + b"\xff\n"]:
            self.reject(raw)


if __name__ == "__main__":
    unittest.main()
