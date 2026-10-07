"""Synthetic journal setup only; no native account/helper/journal operation."""
import json
import unittest
from test_setup import s, Fixture

class RetainedBrowsingSetup(unittest.TestCase):
    def test_new_explicit_grant_is_bounded_and_create_only(self):
        f = Fixture()
        _, plan = s.preflight(f, [], f.templates, all_system_services=True, retained_browsing=True)
        self.assertFalse(f.actions)
        self.assertEqual(plan["schemaVersion"], "tracebolt.journal-helper-plan.v3")
        self.assertEqual(plan["browsingContract"], s.BROWSING_CONTRACT)
        self.assertEqual((plan["pageRows"], plan["sourceRows"], plan["timeoutMilliseconds"], plan["minimumPageIntervalSeconds"]), (500, 4096, 4000, 2))
        self.assertEqual((plan["maxWindowSeconds"], plan["maxLookbackSeconds"]), (0, 0))
        self.assertFalse(plan["externalAIExport"])
        digest = s.digest(s.canonical(plan))
        with self.assertRaisesRegex(s.Rejected, "retained-browsing-acknowledgement-required"):
            s.apply(f, [], f.templates, digest, True, False, all_system_services=True, retained_browsing=True)
        self.assertFalse(f.actions)
        result = s.apply(f, [], f.templates, digest, True, False, all_system_services=True, retained_browsing=True, retained_browsing_ack=True)
        self.assertTrue(result["configured"])
        self.assertTrue(result["activationCommitted"])
        policy = json.loads(f.files[s.POLICY])
        self.assertEqual(f.files[s.POLICY], f.files[s.CLIENT_POLICY])
        self.assertEqual(policy["schemaVersion"], "tracebolt.journal-content-policy.v4")
        self.assertEqual(policy["scope"], s.SCOPE_V4)
        self.assertEqual(policy["browsingContract"], s.BROWSING_CONTRACT)
        self.assertEqual(policy["allowedUnits"], [])
        self.assertEqual(policy["serviceAuthorization"], "all-system-services")
        self.assertFalse(result["contentRead"])
        self.assertEqual(result["policyGeneration"]["policyDigest"], "sha256:" + result["policySHA256"])
        with self.assertRaises(s.Rejected):
            s.preflight(f, [], f.templates, all_system_services=True, retained_browsing=True)

    def test_existing_profile_is_not_promoted_and_flags_cannot_be_confused(self):
        f = Fixture()
        _, old = s.preflight(f, [], f.templates, all_system_services=True)
        self.assertEqual(old["scope"], s.SCOPE_V3)
        self.assertEqual(old["maxWindowSeconds"], 3600)
        with self.assertRaisesRegex(s.Rejected, "explicit-retained-service-profile"):
            s.preflight(f, ["example.service"], f.templates, retained_browsing=True)
        with self.assertRaisesRegex(s.Rejected, "retained-browsing-acknowledgement-required"):
            s.apply(f, [], f.templates, s.digest(s.canonical(old)), True, False, all_system_services=True, retained_browsing_ack=True)
        self.assertFalse(f.actions)

    def test_old_agent_rejected_before_any_setup_effect(self):
        f = Fixture()
        f.command = lambda *args, **kwargs: s.canonical(dict(schemaVersion="tracebolt.journal-runtime-capabilities.v1", policyVersions=["tracebolt.journal-content-policy.v3"], requestVersions=["tracebolt.journal-request.v2"], helperProtocols=["TBJ2"]))
        with self.assertRaisesRegex(s.Rejected, "retained-browsing-agent-upgrade-required"):
            s.preflight(f, [], f.templates, all_system_services=True, retained_browsing=True)
        self.assertFalse(f.actions)

if __name__ == '__main__': unittest.main()
