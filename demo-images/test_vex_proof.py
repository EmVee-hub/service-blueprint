"""Offline guardrails for our NON-PRODUCTION VEX showcase."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

file = Path(__file__).with_name("vex_proof.py")
spec = importlib.util.spec_from_file_location("vex_proof", file)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def match(id="CVE-2021-44228", pkg="log4j-core", version="2.14.1", purl=None):
    return {"vulnerability": {"id": id},
            "artifact": {"name": pkg, "version": version,
                         "purl": purl or f"pkg:maven/org.apache.logging.log4j/{pkg}@{version}"}}


class VexProofTests(unittest.TestCase):
    def test_precise_vex_document_and_match_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            before = root / "before.json"
            after = root / "after.json"
            vex = root / "fixture.json"
            proof = root / "proof.json"
            targeted = match()
            unrelated = match("CVE-2021-45046")
            before.write_text(json.dumps({"matches": [targeted, unrelated]}))
            module.create(before, "policy-showcase:log4shell-public-fixture", vex)
            doc = json.loads(vex.read_text())
            self.assertEqual(len(doc["statements"]), 1)
            self.assertEqual(doc["statements"][0]["status"], "not_affected")
            self.assertTrue(all(p.get("subcomponents") for p in doc["statements"][0]["products"]))
            after.write_text(json.dumps({"matches": [unrelated], "ignoredMatches": [
                {**targeted, "appliedIgnoreRules": [{"namespace": "vex", "vexStatus": "not_affected"}]}
            ]}))
            module.check(before, after, vex, proof)
            self.assertTrue(json.loads(proof.read_text())["verified"])

    def test_reject_unrelated_suppression(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            before, after, vex, proof = (root / name for name in
                                         ("before.json", "after.json", "vex.json", "proof.json"))
            target = match()
            other = match("CVE-2021-45046")
            before.write_text(json.dumps({"matches": [target, other]}))
            module.create(before, "policy-showcase:log4shell-public-fixture", vex)
            after.write_text(json.dumps({"matches": [], "ignoredMatches": [
                {**target, "appliedIgnoreRules": [{"namespace": "vex"}]},
                {**other, "appliedIgnoreRules": [{"namespace": "vex"}]},
            ]}))
            with self.assertRaises(ValueError):
                module.check(before, after, vex, proof)


if __name__ == "__main__":
    unittest.main()
