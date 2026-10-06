"""Verified bootstrap wiring only; no host operations or downloads."""
import contextlib
import importlib.util
import io
from pathlib import Path
import tarfile
import unittest
from unittest import mock

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("upgrade_release_base", HERE / "test_read_admin_bootstrap.py")
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
b=f.b

class Tests(unittest.TestCase):
    setUp = f.Tests.setUp
    package = f.Tests.package
    def package_upgrade(self):
        self.package()
        with tarfile.open(self.archive,"a:") as archive:
            raw=(f.ROOT / b.UPGRADE_SOURCE).read_bytes()
            info=tarfile.TarInfo(b.UPGRADE_SOURCE);info.size=len(raw)
            archive.addfile(info,io.BytesIO(raw))
        self.manifest["assets"][self.archive.name]=dict(sha256=b.digest(self.archive.read_bytes()),size=self.archive.stat().st_size)

    def test_upgrade_flags_reject_fresh_resume_and_unrelated_operations(self):
        self.package_upgrade()
        args=b.parse_args(["--action","upgrade","--upgrade-read-admin","--apply","--insecure-http-test"])
        self.assertTrue(args.upgrade_read_admin)
        command=b.installer_command(args,self.root,self.manifest,"amd64")
        self.assertIn("--insecure-http-test",command)
        self.assertNotIn("--read-admin",command)
        for flags in (["--action","install"],["--action","revoke-socket-owners"],
                      ["--action","upgrade","--read-admin"],["--action","upgrade","--resume"],
                      ["--action","upgrade","--resume-read-admin"],["--action","upgrade","--pending-service"],
                      ["--action","upgrade","--manager-origin","https://example.invalid"]):
            with self.subTest(flags=flags),self.assertRaises(b.Rejected):b.parse_args([*flags,"--upgrade-read-admin"])

    def test_upgrade_source_must_be_in_same_verified_archive(self):
        self.package()
        with self.assertRaisesRegex(b.Rejected,"does not contain"):
            b.read_admin_sources(self.root,self.manifest,upgrade=True)
        self.package_upgrade()
        with mock.patch.object(b.subprocess,"Popen",side_effect=AssertionError("unexpected child")),mock.patch.object(tarfile.TarFile,"extractall",side_effect=AssertionError("unexpected extraction")):
            modules=b.read_admin_sources(self.root,self.manifest,upgrade=True)
        self.assertEqual(modules[-1].VERSION,"tracebolt.read-admin-upgrade-transaction.v1")
        self.assertEqual(len(modules),8)

    def test_dispatch_preserves_actual_terminal_approval_and_result(self):
        self.package_upgrade()
        args=b.parse_args(["--action","upgrade","--upgrade-read-admin","--apply"])
        workflow,inventory,setup,amendment,socket,upgrade=(mock.Mock() for _ in range(6))
        upgrade.run.return_value=dict(completed=True,canceled=False)
        with mock.patch.object(b,"read_admin_sources",return_value=(workflow,inventory,setup,amendment,None,socket,{},upgrade)) as loader, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(b.run_upgrade_read_admin(args,self.root,self.manifest,"amd64"),0)
        loader.assert_called_once_with(self.root,self.manifest,upgrade=True)
        upgrade.run.assert_called_once_with(upgrade.real_adapter.return_value,inventory.confirm_terminal,inventory.emit_terminal)
        command=upgrade.real_adapter.call_args.args[-1]
        self.assertEqual(command[1:4],["--action","upgrade","--apply"])

    def test_main_upgrade_stages_all_roles_and_uses_coordinator(self):
        pin=dict(version=f.VERSION,sourceCommit="a"*40,manifestSHA256="b"*64,bundleSHA256="c"*64)
        with contextlib.ExitStack() as stack:
            for owner,name,value in ((b,"RELEASE_PIN",pin),(b,"inspect_host",mock.Mock(return_value="amd64")),(b.os,"getuid",mock.Mock(return_value=0)),(b.os,"geteuid",mock.Mock(return_value=0)),(b,"inspect_terminal",mock.Mock()),(b,"inspect_staging",mock.Mock()),(b.tempfile,"mkdtemp",mock.Mock(return_value=str(self.root))),(b,"cleanup_release",mock.Mock(return_value=True))):
                stack.enter_context(mock.patch.object(owner,name,value))
            prepare=stack.enter_context(mock.patch.object(b,"prepare_release",return_value=self.manifest))
            upgrade=stack.enter_context(mock.patch.object(b,"run_upgrade_read_admin",return_value=0))
            installer=stack.enter_context(mock.patch.object(b,"run_installer",side_effect=AssertionError("unguarded installer")))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            self.assertEqual(b.main(["--action","upgrade","--upgrade-read-admin","--apply"]),0)
        prepare.assert_called_once_with(self.root,pin,"amd64",read_admin=True)
        upgrade.assert_called_once();installer.assert_not_called()

