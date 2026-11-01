"""Portable fakes only: no Windows library, candidate image, tool or GUI execution."""
import ast
import ctypes
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from test_ci_diagnostics import isolated

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("crt_evidence_under_test", HERE / "ci_crt_evidence.py")
e = importlib.util.module_from_spec(spec); spec.loader.exec_module(e)
IMAGE = r"C:\fixture\own.test.exe"


def output(names=("KERNEL32.dll", "api-ms-win-crt-stdio-l1-1-0.dll")):
    result = "\n" + IMAGE + ":     file format pei-x86-64\n\nThe Import Tables (interpreted .idata section contents)\n"
    result += " vma:            Hint    Time      Forward  DLL       First\n                 Table   Stamp     Chain    Name      Thunk\n"
    for index, name in enumerate(names):
        result += f" {0x1000 + index * 20:08x}\t00002000 00000000 00000000 00003000 00004000\n\n\tDLL Name: {name}\n"
        result += "\tvma:     Ordinal  Hint  Member-Name  Bound-To\n\n"
    result += f" {0x1000 + len(names) * 20:08x}\t00000000 00000000 00000000 00000000 00000000\n"
    return result.encode()



class CRTTextTests(unittest.TestCase):
    def reject(self, raw):
        with self.assertRaises((ValueError, UnicodeError)):
            e.inspect_objdump(raw, IMAGE)

    def test_fixed_catalog_all_and_exact_subsets_only(self):
        self.assertEqual(len(e.CONTRACTS), 15)
        self.assertEqual(len(set(e.CONTRACTS)), 15)
        for index, name in enumerate(e.NAMES):
            vector = e.inspect_objdump(output(("KERNEL32.dll", name.upper())), IMAGE)
            self.assertEqual(vector, [position == index for position in range(15)])
            report = e.projection(vector, [False] * 15)
            self.assertEqual(report["schemaPresent"], [False] * 15)
            self.assertNotIn(name, json.dumps(report))
        self.assertEqual(e.inspect_objdump(output(e.NAMES), IMAGE), [True] * 15)

    def test_unknown_extra_names_and_malformed_rows_discard_all(self):
        for name in ("invented-private-marker.dll", "bcrypt.dll", "comdlg32.dll", "libgcc_s_seh-1.dll",
                     "api-ms-win-crt-stdio-l1-2-0.dll", "api-ms-win-crt-example-l1-1-0.dll", "C:\\kernel32.dll", ""):
            self.reject(output((e.NAMES[0], name)))
        for raw in (output().replace(b"DLL Name:", b"DLL Name :"),
                    output().replace(b"DLL Name: KERNEL32.dll", b"DLL Name: kernel32.dll trailing"),
                    output().replace(b"\tDLL Name:", b"DLL Name:")):
            self.reject(raw)

    def test_identity_empty_truncation_encoding_and_bounds(self):
        raw = output()
        for bad in (b"", raw[:-1], raw + b"\0\n", raw + b"\xff\n", bytearray(raw),
                    raw.replace(b"pei-x86-64", b"pei-i386"), raw.replace(IMAGE.encode(), b"other.exe"),
                    raw.replace(b"The Import Tables", b"Other Tables"),
                    raw + b"x" * (e.MAX_OUTPUT + 1), raw + b"x" * 4097 + b"\n",
                    output(()), output(("kernel32.dll",)), output((e.NAMES[0],) * 33)):
            self.reject(bad)
        self.reject(raw + raw)

    def test_complete_descriptor_framing_and_termination_are_mandatory(self):
        raw = output((e.NAMES[0], e.NAMES[11]))
        rows = raw.splitlines(keepends=True)
        for length in range(1, len(rows)):
            self.reject(b"".join(rows[:length]))
        for changed in (
                raw.replace(b"00001014", b"00001028", 1),
                raw.replace(b"00001028", b"0000103c", 1),
                raw.replace(b"00002000 00000000 00000000", b"00002000 00000001 00000000", 1),
                raw.replace(b"\tDLL Name: " + e.NAMES[11].encode() + b"\n", b""),
                raw.replace(b" vma:            Hint", b" vma: wrong      Hint", 1),
                raw + b"\tDLL Name: invented-private-marker.dll\n",
                raw + b"\tDLL Name: " + e.NAMES[1].encode() + b"\n"):
            self.reject(changed)

    def test_partial_wrong_type_and_nonboolean_projections_never_export(self):
        vector = [True] + [False] * 14
        for bad in (None, [], vector[:-1], vector + [False], tuple(vector), [1] * 15, ["invented-private-marker"] * 15):
            for args in ((bad, vector), (vector, bad)):
                with self.assertRaises(ValueError): e.projection(*args)
        with self.assertRaises(ValueError): e.projection([False] * 15, vector)
        self.assertEqual(e.unavailable(), {"catalog": e.CATALOG, "status": "unavailable", "requiredCRT": None,
            "schemaPresent": None, "candidateExecuted": False, "admissionChanged": False})


    def test_public_boundary_discards_corruption_and_copies_only_closed_values(self):
        report = {**e.projection([True] + [False] * 14, [True] * 15), "sourceCommit": "a" * 40,
                  "sourceTree": "b" * 40, "sourceInputsSHA256": "c" * 64, "imageSHA256": "d" * 64, "imageSize": 512}
        self.assertEqual(e.public_report(report), report)
        for value in (None, [], "invented-private-marker", {**report, "path": "invented-private-marker"},
                      {**report, "sourceCommit": "invented-private-marker"}, {**report, "imageSize": True},
                      {**report, "candidateExecuted": True}, {**report, "admissionChanged": True},
                      {**report, "schemaPresent": ["invented-private-marker"] * 15}, {"status": "unavailable", "path": "private"}):
            self.assertEqual(e.public_report(value), e.unavailable())


class CRTOrchestrationTests(unittest.TestCase):
    def check(self, body):
        self.assertEqual(isolated(body).returncode, 0, "isolated CRT diagnostic assertion failed")

    def test_successful_evidence_still_cannot_admit_a_crt_image(self):
        self.check('''
        from unittest.mock import Mock
        spec=importlib.util.spec_from_file_location('pe_fixture',b.HERE/'test_ci_provenance.py')
        f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
        x=object.__new__(b.Builder);x.stage='provenance';x.progress=b.Progress()
        x.crt_diagnostic=Mock(return_value={'status':'observed_read_only'})
        raw=bytes(f.pe_fixture((b'api-ms-win-crt-stdio-l1-1-0.dll',)))
        try: x.inspect_image(raw,'not-executed',('a'*64,512))
        except ValueError as error: assert str(error)=='provenance'
        else: raise AssertionError('CRT evidence admitted image')
        assert x.crt_diagnostic.call_count==1 and x.crt_evidence=={'status':'observed_read_only'}
        assert x.progress.projection()=={'phase':'provenance','check':'pe-import-rejected-known-crt-contract'}
        for name in [b'kernel32.dll',b'invented-private-marker.dll']:
            x.crt_diagnostic.reset_mock()
            try: x.inspect_image(bytes(f.pe_fixture((name,))),'not-executed',('a'*64,512))
            except ValueError: assert name!=b'kernel32.dll'
            assert x.crt_diagnostic.call_count==0
        ''')

    def test_same_hash_source_lease_tool_query_and_cleanup_required(self):
        self.check('''
        from unittest.mock import Mock
        e=b.runner.manual.source_only('diagnostic_fixture','ci_crt_evidence.py')
        state={'sourceCommit':'a'*40,'sourceTree':'b'*40,'sourceInputsSHA256':'c'*64}
        image=Path('/approved/output/own.test.exe'); image_hash=('d'*64,512)
        tool=Path('/approved/tools/objdump.exe'); gcc=Path('/approved/tools/gcc.exe')
        for fault in [None,'image-os','baseline','source-before','source-after','image-hash','tool-hash','gcc-hash','lease','tool','query','cleanup']:
            x=object.__new__(b.Builder);x.context={'IMAGEOS':'win25'};x.root=Path('/approved/source')
            x.output=image.parent;x.source='a'*40;x.state=state;x.gcc=str(gcc);x.env={};x.end=b.time.monotonic()+60
            events=[];counts={};source_calls=[]
            class Lease:
                def __init__(self,path,digest): self.path=Path(path);self.digest=digest
                def __enter__(self):
                    events.append(('open',self.path,self.digest))
                    if fault=='lease': raise ValueError('private')
                def __exit__(self,*args):
                    events.append(('close',self.path))
                    if fault=='cleanup' and self.path==gcc: raise ValueError('private')
            class Native:
                def __init__(self): events.append(('native',))
                def lease(self,path,digest): return Lease(path,digest)
                def schema(self):
                    events.append(('query',))
                    if fault=='query': raise ValueError('private')
                    return [True]*15
            def hashes(path):
                path=Path(path);counts[path]=counts.get(path,0)+1
                changed={'image-hash':image,'tool-hash':tool,'gcc-hash':gcc}.get(fault)
                if path==changed and counts[path]==(1 if path==image else 2): return ('e'*64,512)
                return image_hash
            def source(*args):
                source_calls.append(True)
                if fault=='source-before' or fault=='source-after' and len(source_calls)==2: return {}
                return state
            def run(argv,cwd,env,*,limit):
                events.append(('run',argv))
                assert argv==[str(tool),'-p',str(image)] and 0<limit<=20
                if fault=='tool': raise ValueError('private')
                sys.path.insert(0,str(b.HERE))
                spec=importlib.util.spec_from_file_location('crt_text_fixture',b.HERE/'test_ci_crt_evidence.py')
                fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
                return fixture.output((e.NAMES[0],)).replace(fixture.IMAGE.encode(),str(image).encode())
            if fault=='image-os': x.context['IMAGEOS']='not-accepted'
            baseline=e.BASELINE if fault!='baseline' else frozenset()
            with patch.object(b.runner.manual,'source_only',return_value=e),patch.object(b.policy,'source_state',side_effect=source),patch.object(b,'hash_file',side_effect=hashes),patch.object(e,'Native',Native),patch.object(e,'run_bounded',side_effect=run),patch.object(b.provenance,'SYSTEM_DLLS',baseline):
                result=x.crt_diagnostic(image,image_hash)
            if fault is None:
                assert result=={**e.projection([True]+[False]*14,[True]*15),**state,'imageSHA256':'d'*64,'imageSize':512}
                assert len(source_calls)==2
                assert [event[1] for event in events if event[0]=='open']==[image,tool,gcc]
                assert [event[1] for event in events if event[0]=='close']==[gcc,tool,image]
            else:
                assert result==e.unavailable() and 'private' not in json.dumps(result)
                if fault in ['image-os','baseline','source-before']: assert not events
        ''')


class Process:
    def __init__(self, *, stdout=None, stderr=b"", exit_code=0, timeout=False, kill_error=False):
        self.stdout = io.BytesIO(output() if stdout is None else stdout)
        self.stderr = io.BytesIO(stderr)
        self.exit_code, self.timeout, self.kill_error = exit_code, timeout, kill_error
        self.live, self.kills = timeout, 0
    def wait(self, timeout):
        if self.live: raise subprocess.TimeoutExpired("not-exported", timeout)
        return self.exit_code
    def poll(self): return None if self.live else self.exit_code
    def kill(self):
        self.kills += 1
        if self.kill_error: raise OSError("invented-private-marker")
        self.live = False


class CRTProcessTests(unittest.TestCase):
    def test_only_fixed_argv_no_shell_and_bounded_private_capture(self):
        process = Process()
        with patch.object(e.subprocess, "Popen", return_value=process) as create:
            raw = e.run_bounded(["owned-objdump.exe", "-p", IMAGE], "own-source", {"PATH": "own"})
        self.assertEqual(e.inspect_objdump(raw, IMAGE)[11], True)
        self.assertEqual(create.call_args.args[0], ["owned-objdump.exe", "-p", IMAGE])
        self.assertIs(create.call_args.kwargs["shell"], False)
        self.assertEqual(create.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_exit_stderr_overflow_timeout_and_kill_errors_fail_closed(self):
        cases = [Process(exit_code=1), Process(stderr=b"invented-private-marker"),
                 Process(stdout=b"x" * (e.MAX_OUTPUT + 1)), Process(stderr=b"x" * (e.MAX_OUTPUT + 1)),
                 Process(timeout=True), Process(timeout=True, kill_error=True)]
        for process in cases:
            with patch.object(e.subprocess, "Popen", return_value=process):
                with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                    e.run_bounded(["owned-objdump.exe", "-p", IMAGE], "own-source", {})
            self.assertTrue(process.stdout.closed and process.stderr.closed)
            if process.timeout: self.assertEqual(process.kills, 1)


class Function:
    def __init__(self, body): self.body = body
    def __call__(self, *args): return self.body(*args)



class CRTNativeFakes(unittest.TestCase):
    def test_schema_queries_exact_fixed_stems_and_false_is_not_admission(self):
        names = []
        def query(name): names.append(name); return len(names) % 2
        class API:
            IsApiSetImplemented = Function(query)
        native = object.__new__(e.Native)
        with patch.object(e.C, "WinDLL", return_value=API(), create=True) as bind:
            values = native.schema()
        bind.assert_called_once_with("api-ms-win-core-apiquery-l2-1-0.dll", use_last_error=True, winmode=0x800)
        self.assertEqual(names, [name.encode() for name in e.CONTRACTS])
        self.assertEqual(values, [index % 2 == 0 for index in range(15)])

    def test_absent_or_nonboolean_query_never_yields_partial_vector(self):
        for result in (-1, "private"):
            class API:
                IsApiSetImplemented = Function(lambda name: result)
            with patch.object(e.C, "WinDLL", return_value=API(), create=True):
                with self.assertRaises(ValueError): object.__new__(e.Native).schema()
        with patch.object(e.C, "WinDLL", side_effect=OSError("private"), create=True):
            with self.assertRaises(OSError): object.__new__(e.Native).schema()
        with patch.object(e.C, "WinDLL", return_value=object(), create=True):
            with self.assertRaises(AttributeError): object.__new__(e.Native).schema()

    def test_lease_cleanup_attempts_every_handle_despite_close_error(self):
        closed = []
        class Close:
            def CloseHandle(self, handle):
                closed.append(handle)
                if handle == 2: raise OSError("not-exported")
                return 1
        lease = e.Lease(Close(), IMAGE, "a" * 64); lease.handles = [1, 2, 3]
        with self.assertRaises(ValueError): lease.__exit__(None, None, None)
        self.assertEqual(closed, [3, 2, 1]); self.assertEqual(lease.handles, [])

    def test_readonly_path_and_lease_algorithm_matches_original_reviewed_guard(self):
        original = ast.parse((HERE / "windows.py").read_text())
        current = ast.parse((HERE / "ci_crt_evidence.py").read_text())
        def function(tree, name):
            return next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name)
        for name in ("path_chain", "_lease_image"):
            self.assertEqual(ast.dump(function(current, name)), ast.dump(function(original, name)))
        self.assertNotIn("LoadLibrary", (HERE / "ci_crt_evidence.py").read_text())


if __name__ == "__main__": unittest.main()
