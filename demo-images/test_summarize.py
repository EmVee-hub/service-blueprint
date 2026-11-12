"""Combined report must explain its tables before listing scan results."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("summarize", Path(__file__).with_name("summarize.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class SummaryTests(unittest.TestCase):
    def test_legend_precedes_scan_overview_and_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "showcase-minimal-scratch-internal"
            folder.mkdir()
            (folder / "grype.json").write_text(json.dumps({"matches": []}))
            (folder / "decision.json").write_text(json.dumps({
                "counts": {}, "admission": "ALLOW", "findings": [], "vex_ignored_count": 0
            }))
            md = module.report(Path(tmp))
            self.assertLess(md.index("## 1. Legend"), md.index("## 2. Scan overview"))
            self.assertLess(md.index("## 2. Scan overview"), md.index("## 3. Individual scan sections"))
            self.assertLess(md.index("## 3. Individual scan sections"), md.index("## 4. OpenVEX"))
            self.assertIn("### `minimal-scratch-internal`", md)
            for label in ("KEV_GUARD", "EPSS_UNAVAILABLE_NEUTRAL", "VEX ignored", "Base / Final"):
                self.assertIn(label, md)
            self.assertIn("NO_REPORT", md)

if __name__ == "__main__":
    unittest.main()
