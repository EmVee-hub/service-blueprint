#!/usr/bin/env python3
"""Offline collector + scoped VEX proof. Not a production OpenVEX engine or gate."""
import argparse
import importlib.util
import json
from pathlib import Path

FIXTURES = Path(__file__).parent / 'fixtures'


def load(path):
    return json.loads(path.read_text())


def module(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def disposition(cve, identity, vex):
    """Conservative demo subset: exact CVE + digest product + versioned component."""
    digest, purl = identity.get('image_digest'), identity.get('package_purl')
    if not digest or not purl:
        return 'REVIEW_REQUIRED', 'NOT_EVALUATED', 'Missing image digest or package identity'
    matching = []
    for statement in vex['statements']:
        if statement['vulnerability']['name'] != cve:
            continue
        for product in statement['products']:
            if product['@id'] == 'urn:demo:container:' + digest and any(
                    c.get('@id') == purl for c in product.get('subcomponents', [])):
                matching.append(statement)
                break
    if not matching:
        return 'ACTIVE', 'NO_MATCH', 'No exact CVE/product/component statement'
    if len(matching) != 1:
        return 'REVIEW_REQUIRED', 'CONFLICT', 'Multiple matching statements; review required'
    stmt = matching[0]
    if stmt['status'] == 'not_affected':
        if not stmt.get('justification') or not stmt.get('impact_statement'):
            return 'REVIEW_REQUIRED', 'INVALID_EVIDENCE', 'Demo requires justification and impact evidence'
        return 'SUPPRESSED', 'not_affected', stmt['justification'] + ': ' + stmt['impact_statement']
    return 'ACTIVE', stmt['status'], 'Retained for review/remediation; no not_affected assertion'


def assess(provider, observations, identities, vex):
    rows = []
    for finding in observations:
        key = finding['assessment_id'] if provider == 'azure' else finding['finding_arn']
        identity = dict(identities.get(key, {}))
        # Inspector's digest is read from collector output, never replaced by the fixture map.
        if provider == 'aws':
            identity['image_digest'] = finding['asset']['image_digest']
        result, status, reason = disposition(finding['vulnerability_id'], identity, vex)
        rows.append({'source': provider, 'case': identity.get('case', key),
                     'cve': finding['vulnerability_id'], 'severity': finding['severity'],
                     'provider_status': finding['provider_status'], **identity,
                     'before_vex': 'ACTIVE', 'after_vex': result,
                     'vex_status': status, 'reason': reason, 'policy': 'NOT_EVALUATED'})
    return rows


def escape(value):
    return str(value or '—').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('|', '\\|').replace('\r', ' ').replace('\n', ' ')


def report(results, unresolved):
    lines = ['# Azure Defender and AWS Inspector — offline VEX showcase', '',
             '**Synthetic fixtures, not live cloud findings.** Real collector normalization is exercised. '
             'Image/component mappings are explicit test inputs; Azure does not yet discover these identities. '
             'This demonstrates a limited VEX matcher, not Grype matching or production cloud enforcement.', '',
             '## Legend', '',
             '| Column | Meaning |', '|---|---|',
             '| CVE / severity | Identifier and severity supplied by the synthetic provider fixture; not current vulnerability intelligence. |',
             '| Provider status | Original cloud status. Provider SUPPRESSED is not project VEX. |',
             '| Package / image | Exact versioned component PURL and digest from test evidence. |',
             '| Before → after | ACTIVE → SUPPRESSED only for exact not_affected scope with evidence. |',
             '| VEX status / reason | Matching statement and justification, NO_MATCH, or missing identity requiring review. |',
             '| Policy | NOT_EVALUATED: no BOD deadline, admission verdict, or runtime coverage claim. |', '']
    for provider, rows in results.items():
        suppressed = sum(r['after_vex'] == 'SUPPRESSED' for r in rows)
        review = sum(r['after_vex'] == 'REVIEW_REQUIRED' for r in rows)
        lines += ['## ' + ('Azure Defender' if provider == 'azure' else 'AWS Inspector'), '',
                  f'**{len(rows)} CVE observations · {len(set(r["cve"] for r in rows))} unique CVEs · {suppressed} VEX-suppressed · {review} need identity review.**', '',
                  '| Test case | CVE | Severity | Provider status | Package / image | Before → after | VEX status / reason | Policy |',
                  '|---|---|---|---|---|---|---|---|']
        for row in rows:
            cells = [row['case'], row['cve'], row['severity'], row['provider_status'],
                     (row.get('package_purl') or 'unknown') + ' / ' + (row.get('image_digest') or 'unknown'),
                     row['before_vex'] + ' → ' + row['after_vex'], row['vex_status'] + ': ' + row['reason'], row['policy']]
            lines.append('| ' + ' | '.join(escape(x) for x in cells) + ' |')
        lines += ['']
    lines += ['## Unresolved Azure evidence', '',
              f'{len(unresolved)} assessment(s) could not be normalized; retained in azure/unresolved.json. This is not a clean scan.', '']
    return '\n'.join(lines)


def annotation(value):
    return str(value).replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')


def run(shared, output, emit_annotations=False):
    output.mkdir(parents=True, exist_ok=False)
    azure = module(shared / 'scripts/read_azure.py')
    aws = module(shared / 'scripts/collect_inspector.py')
    validator = module(shared / 'scripts/validate_vex.py')
    validator.validate(FIXTURES / 'openvex.json')
    raw = azure.load_input(FIXTURES / 'defender.json')
    observations, unresolved = azure.normalize(raw)
    (output / 'azure').mkdir()
    for name, data in [('input.raw.json', raw), ('observations.json', observations), ('unresolved.json', unresolved)]:
        azure.write(output / 'azure' / name, data)
    aws.collect(None, output / 'aws', FIXTURES / 'inspector.json')
    inspector = load(output / 'aws/normalized-findings.json')['findings']
    identities, vex = load(FIXTURES / 'demo-identities.json'), load(FIXTURES / 'openvex.json')
    results = {p: assess(p, data, identities[p], vex) for p, data in [('azure', observations), ('aws', inspector)]}
    (output / 'proof.json').write_text(json.dumps({'synthetic': True, 'policy_evaluated': False, 'results': results}, indent=2)+'\n')
    (output / 'openvex.json').write_text(json.dumps(vex, indent=2)+'\n')
    (output / 'summary.md').write_text(report(results, unresolved))
    expected = load(FIXTURES / 'expected.json')
    for provider, rows in results.items():
        actual = {r['case']: r['after_vex'] for r in rows}
        if actual != expected or len(rows) != len(expected):
            raise AssertionError(f'{provider}: expected {expected}, got {actual}')
        if emit_annotations:
            for row in rows:
                message = f"SYNTHETIC {provider} / {row['case']}: {row['cve']} ({row['severity']}), {row.get('package_purl')}; {row['before_vex']} -> {row['after_vex']}; VEX={row['vex_status']}; {row['reason']}. Policy NOT_EVALUATED."
                print('::notice title=Cloud VEX test::' + annotation(message))
    if len(unresolved) != 1:
        raise AssertionError('Expected one retained unresolved Azure assessment')
    if emit_annotations:
        print('::notice title=Unresolved Azure fixture::1 assessment lacks recognized CVE details; retained for review, not a clean scan.')
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shared', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--annotations', action='store_true')
    args = parser.parse_args()
    run(args.shared, args.output, args.annotations)
