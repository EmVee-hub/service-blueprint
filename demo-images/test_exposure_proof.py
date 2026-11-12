"""Deterministic tests for explicit-vs-omitted exposure behavior."""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("exposure_proof", Path(__file__).with_name("exposure_proof.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def sample(exposure, source, matches=1):
    return {
        "image": "cae-live:ci-test-sha",
        "exposure_input": exposure,
        "publicly_exposed": "Y",
        "exposure_source": source,
        "admission": "ALLOW",
        "findings": [{
            "vulnerability_id": "CVE-2026-99999",
            "package": "nginx",
            "installed_version": "1.2.3",
            "publicly_exposed": "Y",
            "exposure_source": source,
        }] if matches else [],
    }


class ExposureProofTests(unittest.TestCase):
    def test_missing_input_defaults_to_public(self):
        proof = module.verify(
            sample("public", "PROJECT_DECLARATION"),
            sample("unknown", "UNKNOWN_DEFAULT_PUBLIC"),
        )
        self.assertTrue(proof["verified"])
        self.assertEqual(proof["explicit"]["publicly_exposed"], "Y")
        self.assertEqual(proof["omitted"]["publicly_exposed"], "Y")
        self.assertEqual(proof["omitted"]["exposure_source"], "UNKNOWN_DEFAULT_PUBLIC")
        self.assertEqual(proof["findings"], 1)

    def test_no_findings_still_proves_default(self):
        proof = module.verify(
            sample("public", "PROJECT_DECLARATION", matches=0),
            sample("unknown", "UNKNOWN_DEFAULT_PUBLIC", matches=0),
        )
        self.assertTrue(proof["verified"])
        self.assertEqual(proof["findings"], 0)

    def test_rejects_omitted_input_treated_internal(self):
        bad = sample("unknown", "UNKNOWN_DEFAULT_PUBLIC")
        bad["publicly_exposed"] = "N"
        with self.assertRaises(ValueError):
            module.verify(sample("public", "PROJECT_DECLARATION"), bad)

    def test_rejects_false_source(self):
        with self.assertRaises(ValueError):
            module.verify(sample("public", "PROJECT_DECLARATION"),
                          sample("unknown", "PROJECT_DECLARATION"))

    def test_rejects_different_images(self):
        bad = sample("unknown", "UNKNOWN_DEFAULT_PUBLIC")
        bad["image"] = "cae-live:ci-another"
        with self.assertRaises(ValueError):
            module.verify(sample("public", "PROJECT_DECLARATION"), bad)


if __name__ == "__main__":
    unittest.main()
