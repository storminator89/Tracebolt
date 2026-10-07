import importlib.util
import json
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location("source_gate",Path(__file__).with_name("run_windows_service_source.py"))
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
class GateTests(unittest.TestCase):
    def test_exact_required_cases(self):
        records=[dict(Package=p,Test=t,Action="pass") for p,t in gate.REQUIRED]
        raw=lambda rows:b"\n".join(json.dumps(x).encode() for x in rows)
        gate.check_events(raw(records))
        for rows in (records[:-1],records+[dict(records[0],Action="skip")]):
            with self.assertRaises(ValueError):gate.check_events(raw(rows))
    def test_volume_mocks_are_mandatory_without_native_scope(self):
        self.assertIn("./internal/windowsvolumes",gate.PACKAGES)
        for name in ("TestNativeInjectedEnumeration","TestNativeRejectMalformedRoots"):
            required=("localrmm/internal/windowsvolumes",name)
            self.assertIn(required,gate.REQUIRED)
            rows=[dict(Package=p,Test=t,Action="pass") for p,t in gate.REQUIRED if (p,t)!=required]
            with self.assertRaises(ValueError):gate.check_events(b"\n".join(json.dumps(x).encode() for x in rows))
        source=Path(gate.__file__).read_text()
        self.assertIn('env.pop("TRACEBOLT_WINDOWS_READONLY_NATIVE", None)',source)
        self.assertNotIn("run_windows_readonly.py",source)
        self.assertNotIn("run_acceptance.py",source)
    def test_malformed_stream(self):
        for raw in (b"[]",b"not json",b"",b" "*(32*1024*1024+1)):
            with self.assertRaises(ValueError):gate.check_events(raw)
if __name__=="__main__":unittest.main()
