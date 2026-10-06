import copy
import io
import unittest
from pathlib import Path
import hashlib
import json
from guide import SOURCE_FILES
from common import Rejected
from guide import make_plan, confirm_and_apply

class Fixture:
    def __init__(self):
        self.facts = {"state": "fresh", "publicBundle": {"transportProfile": "production-tls"}, "scope": "demo.service"}
        self.inspections = 0
        self.applied = []
        self.change = False
    def inspect(self, request):
        self.inspections += 1
        if self.change and self.inspections > 1:
            return dict(self.facts, scope="changed.service")
        return copy.deepcopy(self.facts)
    def apply(self, plan, bundle=None):
        self.applied.append((plan, bundle))
        return {"configured": True}

class GuideTests(unittest.TestCase):
    def test_exact_source_manifest(self):
        root = Path(__file__).resolve().parents[2]
        manifest = json.loads((root / "deploy/actions/source-manifest.json").read_bytes())
        self.assertEqual(manifest["schemaVersion"], "tracebolt.action-setup-source.v1")
        self.assertEqual(set(manifest["files"]), set(SOURCE_FILES))
        for name in SOURCE_FILES:
            self.assertEqual(manifest["files"][name], "sha256:" + hashlib.sha256((root/name).read_bytes()).hexdigest())

    def test_default_plan_and_cancel_no_effects(self):
        fx = Fixture()
        confirm_and_apply("endpoint", {}, fx, output=lambda _: None)
        self.assertEqual(fx.applied, [])
        with self.assertRaises(Rejected):
            confirm_and_apply("endpoint", {}, fx, apply=True, terminal=True, input_fn=lambda: "no", output=lambda _: None)
        self.assertEqual(fx.applied, [])
    def test_no_noninteractive_approval(self):
        fx = Fixture()
        with self.assertRaises(Rejected):
            confirm_and_apply("endpoint", {}, fx, apply=True, terminal=False, output=lambda _: None)
        self.assertEqual(fx.applied, [])
    def test_one_exact_confirmation_and_recheck(self):
        fx = Fixture()
        token = "APPLY " + make_plan("endpoint", fx.facts)["planDigest"]
        confirm_and_apply("endpoint", {}, fx, apply=True, terminal=True, input_fn=lambda: token, output=lambda _: None)
        self.assertEqual(len(fx.applied), 1)
        self.assertEqual(fx.inspections, 2)
    def test_changed_plan_rejected(self):
        fx = Fixture(); fx.change = True
        token = "APPLY " + make_plan("endpoint", fx.facts)["planDigest"]
        with self.assertRaises(Rejected):
            confirm_and_apply("endpoint", {}, fx, apply=True, terminal=True, input_fn=lambda: token, output=lambda _: None)
        self.assertEqual(fx.applied, [])
    def test_complete_is_inspection_only(self):
        fx = Fixture(); fx.facts["state"] = "complete"
        confirm_and_apply("endpoint", {}, fx, apply=True, output=lambda _: None)
        self.assertEqual(fx.applied, [])

if __name__ == "__main__":
    unittest.main()
