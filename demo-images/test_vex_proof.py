"""Offline guardrails for the NON-PRODUCTION VEX showcase."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("vex_proof", Path(__file__).with_name("vex_proof.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def match(id="CVE-2021-44228", pkg="log4j-core", version="2.14.1", purl=None):
    return {"vulnerability": {"id": id}, "artifact": {
        "name": pkg, "version": version,
        "purl": purl or f"pkg:maven/org.apache.logging.log4j/{pkg}@{version}"}}


def ignored(m):
    return {**m, "appliedIgnoreRules": [{"namespace": "vex", "vexStatus": "not_affected"}]}


class VexProofTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.before, self.after, self.vex, self.proof, self.decision = (
            root / n for n in ("before.json", "after.json", "vex.json", "proof.json", "decision.json"))
        self.targets = [match(cve) for cve in (
            "CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832")]
        self.other = match("CVE-OS-FIXTURE", "busybox", "1.0", "pkg:apk/alpine/busybox@1.0")
        self.prepare()

    def prepare(self):
        self.before.write_text(json.dumps({"matches": self.targets + [self.other]}))
        module.create(self.before, "policy-showcase:log4shell-public-fixture", self.vex)
        self.after.write_text(json.dumps({"matches": [self.other], "ignoredMatches": list(map(ignored, self.targets))}))
        self.decision.write_text(json.dumps({"admission": "ALLOW"}))

    def check(self):
        module.check(self.before, self.after, self.vex, self.proof, self.decision)

    def test_all_log4j_advisories_suppressed_and_allow(self):
        self.check()
        proof = json.loads(self.proof.read_text())
        self.assertEqual(proof["suppressed_count"], 4)
        self.assertEqual(proof["admission"], "ALLOW")
        self.assertEqual(proof["active_after"], 1)
        doc = json.loads(self.vex.read_text())
        self.assertEqual(len(doc["statements"]), 4)
        self.assertTrue(all(p.get("subcomponents") for s in doc["statements"] for p in s["products"]))

    def test_ghsa_primary_id_uses_cve_alias(self):
        self.targets[0]["vulnerability"]["id"] = "GHSA-jfh8-c2jp-5v3q"
        self.targets[0]["relatedVulnerabilities"] = [{"id": "CVE-2021-44228"}]
        self.prepare()
        self.check()
        self.assertIn("GHSA-jfh8-c2jp-5v3q", self.vex.read_text())

    def test_reject_unrelated_suppression(self):
        self.after.write_text(json.dumps({"matches": [], "ignoredMatches": list(map(ignored, self.targets + [self.other]))}))
        with self.assertRaises(ValueError): self.check()

    def test_reject_partial_suppression(self):
        self.after.write_text(json.dumps({"matches": [self.other, self.targets[-1]], "ignoredMatches": list(map(ignored, self.targets[:-1]))}))
        with self.assertRaises(ValueError): self.check()

    def test_reject_missing_vex_evidence(self):
        self.after.write_text(json.dumps({"matches": [self.other], "ignoredMatches": self.targets}))
        with self.assertRaises(ValueError): self.check()

    def test_reject_non_allow_decisions(self):
        for admission in ("BLOCK", "REVIEW_REQUIRED", None):
            with self.subTest(admission=admission):
                self.decision.write_text(json.dumps({"admission": admission}))
                with self.assertRaises(ValueError): self.check()
        self.assertFalse(self.proof.exists())

    def test_other_version_and_namespace_remain_active(self):
        for other in (match("CVE-2021-45046", version="2.15.0"),
                      match("CVE-2021-45046", purl="pkg:maven/other/log4j-core@2.14.1")):
            self.other = other
            self.prepare()
            self.check()

    def test_reject_non_demo_image(self):
        with self.assertRaises(ValueError):
            module.create(self.before, "production:latest", self.vex)

    def test_require_log4shell_baseline(self):
        self.before.write_text(json.dumps({"matches": self.targets[1:]}))
        with self.assertRaises(ValueError):
            module.create(self.before, "policy-showcase:log4shell-public-fixture", self.vex)


if __name__ == "__main__":
    unittest.main()
