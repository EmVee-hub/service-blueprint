import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import showcase as s


class CloudVexTests(unittest.TestCase):
    def setUp(self):
        self.vex = s.load(s.FIXTURES / 'openvex.json')
        self.identity = s.load(s.FIXTURES / 'demo-identities.json')['azure']['synthetic-assessment-log4shell-scoped']

    def result(self, cve='CVE-2021-44228'):
        return s.disposition(cve, self.identity, self.vex)[0]

    def test_exact_scope_suppressed(self):
        self.assertEqual(self.result(), 'SUPPRESSED')

    def test_wrong_image_retained(self):
        self.identity['image_digest'] = 'sha256:' + 'b' * 64
        self.assertEqual(self.result(), 'ACTIVE')

    def test_wrong_version_retained(self):
        self.identity['package_purl'] = self.identity['package_purl'].replace('2.14.1', '2.14.0')
        self.assertEqual(self.result(), 'ACTIVE')

    def test_other_cve_retained(self):
        self.assertEqual(self.result('CVE-2021-44832'), 'ACTIVE')

    def test_affected_and_investigating_retained(self):
        for cve in ['CVE-2021-45046', 'CVE-2021-45105']:
            with self.subTest(cve=cve): self.assertEqual(self.result(cve), 'ACTIVE')

    def test_missing_identity_requires_review(self):
        for field in ['image_digest', 'package_purl']:
            with self.subTest(field=field):
                identity = {**self.identity, field: None}
                self.assertEqual(s.disposition('CVE-2021-44228', identity, self.vex)[0], 'REVIEW_REQUIRED')

    def test_missing_evidence_requires_review(self):
        del self.vex['statements'][0]['impact_statement']
        self.assertEqual(self.result(), 'REVIEW_REQUIRED')

    def test_conflicting_statements_require_review(self):
        conflict = copy.deepcopy(self.vex['statements'][0])
        conflict['status'] = 'affected'
        self.vex['statements'].append(conflict)
        self.assertEqual(self.result(), 'REVIEW_REQUIRED')

    def test_product_without_component_does_not_match(self):
        del self.vex['statements'][0]['products'][0]['subcomponents']
        self.assertEqual(self.result(), 'ACTIVE')

    def test_report_marks_unexpected_disposition_failed(self):
        row = {'case': 'log4shell-scoped', 'cve': 'CVE-2021-44228',
               'severity': 'Critical', 'provider_status': 'ACTIVE',
               'before_vex': 'ACTIVE', 'after_vex': 'ACTIVE',
               'vex_status': 'NO_MATCH', 'reason': 'No match', 'policy': 'NOT_EVALUATED'}
        md = s.report({'azure': [row]}, [])
        self.assertIn('Goal of test | Expected behavior | Actual result', md)
        self.assertIn('| SUPPRESSED | FAIL: ACTIVE |', md)
        self.assertIn('**Actual result:** FAIL', md)
        self.assertNotIn('PASS', md)

    def test_annotations_escape_commands(self):
        self.assertEqual(s.annotation('a%\n::error::x\r'), 'a%25%0A::error::x%0D')

    def test_both_collectors_and_vex_end_to_end_without_cloud(self):
        shared = Path(os.environ.get('SHARED_ACTIONS', '../github-actions')).resolve()
        with tempfile.TemporaryDirectory() as tmp, patch('subprocess.run', side_effect=AssertionError('No cloud commands allowed')):
            out = Path(tmp) / 'report'
            results = s.run(shared, out)
            self.assertEqual(len(results['azure']), 8)
            self.assertEqual(len(results['aws']), 8)
            provider = next(r for r in results['aws'] if r['case'] == 'provider-suppressed')
            self.assertEqual(provider['provider_status'], 'SUPPRESSED')
            self.assertEqual(provider['after_vex'], 'ACTIVE')
            markdown = (out / 'summary.md').read_text()
            self.assertEqual(markdown.count('## Legend'), 1)
            self.assertIn('CVE-2021-44228', markdown)
            self.assertIn('ACTIVE → SUPPRESSED', markdown)
            self.assertIn('NOT_EVALUATED', markdown)
            self.assertEqual(markdown.count('PASS:'), 16)
            self.assertLess(markdown.index('Goal of test'), markdown.index('| Test case | CVE |'))
            manifest = s.load(out / 'aws/manifest.json')
            self.assertFalse(manifest['live_aws_data'])
            self.assertFalse(manifest['policy_evaluated'])


if __name__ == '__main__':
    unittest.main()

