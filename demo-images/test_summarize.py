"""Combined report must not repeat the workflow-level legend."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("summarize", Path(__file__).with_name("summarize.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class SummaryTests(unittest.TestCase):
    def test_scan_sections_without_embedded_legend(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "showcase-minimal-scratch-internal"
            folder.mkdir()
            (folder / "grype.json").write_text(json.dumps({"matches": []}))
            (folder / "decision.json").write_text(json.dumps({
                "counts": {}, "admission": "ALLOW", "findings": [], "vex_ignored_count": 0
            }))
            md = module.report(Path(tmp))
            self.assertNotIn("## 1. Legend", md)
            self.assertNotIn("Decision-rule legend", md)
            self.assertLess(md.index("## 1. Scan overview"), md.index("## 2. Individual scan sections"))
            self.assertLess(md.index("## 2. Individual scan sections"), md.index("## 3. OpenVEX"))
            self.assertLess(md.index("## 3. OpenVEX"), md.index("## 4. cae-live"))
            self.assertIn("### `minimal-scratch-internal`", md)
            self.assertIn("VEX ignored", md)
            self.assertIn("Decision rule", md)
            self.assertIn("NO_REPORT", md)

    def test_shared_legend_is_a_single_prerequisite_job(self):
        repo = Path(__file__).resolve().parents[1]
        legend = (repo / "security" / "report-legend.md").read_text(encoding="utf-8")
        self.assertEqual(legend.count("# Legend — How to read vulnerability scan reports"), 1)
        for key in ("KEV_GUARD", "AMPLIFIED", "EPSS_UNAVAILABLE_NEUTRAL", "VEX ignored"):
            self.assertIn(key, legend)
        for workflow in (
            repo / ".github" / "workflows" / "demo-policy-showcase.yml",
            repo / ".github" / "workflows" / "ci.yml",
        ):
            source = workflow.read_text(encoding="utf-8")
            self.assertEqual(source.count("cat security/report-legend.md"), 1)
            self.assertIn("needs: [legend]", source)

if __name__ == "__main__":
    unittest.main()
