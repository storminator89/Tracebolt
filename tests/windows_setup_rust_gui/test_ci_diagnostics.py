"""Finite projection tests only; no tools, GUI, network or host changes."""
import importlib.util
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest

HERE = Path(__file__).resolve().parent

def isolated(body):
    setup = f"""import importlib.util,sys,json,os,io,contextlib,tempfile
from pathlib import Path
from unittest.mock import patch
path=Path({str(HERE / 'build_ci.py')!r})
spec=importlib.util.spec_from_file_location('build_under_test',path)
b=importlib.util.module_from_spec(spec);sys.modules[spec.name]=b;spec.loader.exec_module(b)
"""
    return subprocess.run([sys.executable, "-I", "-B", "-c", setup + textwrap.dedent(body)], capture_output=True, timeout=15)

class DiagnosticTests(unittest.TestCase):
    def check(self, body):
        self.assertEqual(isolated(body).returncode, 0, "isolated finite diagnostic assertion failed")

    def test_only_fixed_strings_can_be_projected_even_on_corrupted_state(self):
        self.check('''
        p=b.Progress()
        p.mark('go-link','go-repeat-equality')
        assert p.projection()=={'phase':'go-link','check':'go-repeat-equality'}
        for bad in ['invented-private-marker',None,[],{}]:
            try: p.mark('toolchain',bad)
            except b.contract.Failure: pass
            else: raise AssertionError('unknown check accepted')
            p.phase,p.check=bad,bad
            assert p.projection()=={'phase':'unexpected','check':'unexpected'}
            assert 'invented-private-marker' not in json.dumps(p.projection())
        ''')

    def test_real_version_guard_is_unchanged_and_reports_its_subcheck(self):
        self.check('''
        x=object.__new__(b.Builder);x.stage='toolchain';x.progress=b.Progress();x.go='not-executed'
        x.run=lambda *args,**kwargs:b'invented-private-wrong-version'
        try: x.build()
        except b.contract.Failure as error: assert error.stage=='provenance'
        else: raise AssertionError('wrong version admitted')
        assert x.progress.projection()=={'phase':'toolchain','check':'go-version'}
        ''')

    def test_constructor_and_postconstructor_errors_keep_finite_context(self):
        self.check('''
        spec=importlib.util.spec_from_file_location('context_fixture',b.HERE/'test_ci_policy.py')
        f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
        b.PLATFORM='nt';state={'sourceCommit':'a'*40,'sourceTree':'b'*40,'sourceInputsSHA256':'c'*64}
        for during_init in [True,False]:
            with tempfile.TemporaryDirectory() as directory:
                env=f.context();env.update(RUNNER_TEMP=directory,GITHUB_WORKSPACE=str(b.runner.ROOT))
                class FakeBuilder:
                    stage='provenance'
                    def __init__(self,*args):
                        self.p=args[-1]
                        if during_init:
                            self.p.mark('toolchain','tool-gcc-file')
                            raise b.contract.Failure('provenance')
                    def build(self):
                        self.p.mark('provenance','pe-import-allowlist')
                        raise RuntimeError('invented-private-marker')
                with patch.dict(os.environ,env,clear=True),patch.object(b.policy,'source_state',return_value=state),patch.object(b,'Builder',FakeBuilder),contextlib.redirect_stdout(io.StringIO()) as output:
                    assert b.main(['--build-inert-github-tls-fixture','--source','a'*40])==2
                value=json.loads(output.getvalue())
                assert value['status']=='not_built' and value['stage']=='provenance'
                assert value['phase']==('toolchain' if during_init else 'provenance')
                assert value['check']==('tool-gcc-file' if during_init else 'pe-import-allowlist')
                assert value['nativeExecution'] is False and value['installerHostActionsAttempted'] is False
                assert 'invented-private-marker' not in output.getvalue() and directory not in output.getvalue()
        ''')

    def test_pe_and_buildinfo_callbacks_do_not_change_acceptance_or_export_values(self):
        self.check('''
        spec=importlib.util.spec_from_file_location('provenance_fixture',b.HERE/'test_ci_provenance.py')
        f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
        p=b.Progress();p.mark('provenance','image-read')
        def note(label): p.mark('provenance',label)
        raw=bytes(f.pe_fixture())
        assert b.provenance.inspect_pe(raw)==b.provenance.inspect_pe(raw,checkpoint=note)
        assert b.provenance.inspect_go_build_info(f.info_fixture(),'a'*40)==b.provenance.inspect_go_build_info(f.info_fixture(),'a'*40,checkpoint=note)
        assert p.projection()['check']=='go-info-source-claim'
        for name in [b'libgcc_s_seh-1.dll',b'invented-private-marker.dll']:
            raw=bytes(f.pe_fixture((name,)))
            for callback in [None,note]:
                try: b.provenance.inspect_pe(raw,checkpoint=callback)
                except ValueError as error: assert str(error)=='provenance'
                else: raise AssertionError('foreign runtime admitted')
            assert p.projection()=={'phase':'provenance','check':'pe-import-allowlist'}
            assert name.decode() not in json.dumps(p.projection())
        for raw,check in [(f.info_fixture().replace(b'GOOS=windows',b'GOOS=linux'),'go-info-required'),(f.info_fixture(flags=f.FLAGS),'go-info-source-claim')]:
            for callback in [None,note]:
                try: b.provenance.inspect_go_build_info(raw,'a'*40,checkpoint=callback)
                except ValueError as error: assert str(error)=='provenance'
                else: raise AssertionError('bad build-info admitted')
            assert p.projection()['check']==check
        ''')

    def test_every_helper_checkpoint_is_a_declared_finite_label(self):
        self.check('''
        assert set(b.provenance.PE_CHECKS)|set(b.provenance.GO_INFO_CHECKS)<=b.CHECKS
        for phase in b.PHASES:
            for check in b.CHECKS:
                p=b.Progress();p.mark(phase,check);assert p.projection()=={'phase':phase,'check':check}
        ''')

    def test_default_provenance_algorithm_is_ast_identical_to_reviewed_guard(self):
        class StripCheckpoints(ast.NodeTransformer):
            def visit_Assign(self, node):
                if any(isinstance(target, ast.Name) and target.id in {"PE_CHECKS", "GO_INFO_CHECKS"} for target in node.targets):
                    return None
                return self.generic_visit(node)
            def visit_If(self, node):
                if ast.dump(node.test) == ast.dump(ast.parse("checkpoint is not None", mode="eval").body):
                    return None
                return self.generic_visit(node)
            def visit_FunctionDef(self, node):
                node = self.generic_visit(node)
                if node.args.args and node.args.args[-1].arg == "checkpoint":
                    self_outer.assertEqual(len(node.args.defaults), 1)
                    self_outer.assertIsNone(node.args.defaults[0].value)
                    node.args.args.pop(); node.args.defaults.pop()
                return node
        self_outer = self
        tree = StripCheckpoints().visit(ast.parse((HERE / "ci_provenance.py").read_text()))
        digest = hashlib.sha256(ast.dump(tree).encode()).hexdigest()
        self.assertEqual(digest, "4a6c7ea41c1307a2e188941b8fd950e06443712a4d2d320b7652051e4ef94636")

if __name__ == "__main__":
    unittest.main()
