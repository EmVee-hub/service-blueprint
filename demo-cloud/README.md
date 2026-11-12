# Cloud findings and VEX showcase

Run **Actions → Cloud findings and VEX showcase**. It also runs on relevant
pushes and pull requests. No cloud credentials, cloud API calls, image builds,
or vulnerable services are needed.

The workflow imports the actual Azure Defender and AWS Inspector collectors
from a pinned revision of `EmVee-hub/github-actions`, normalizes checked-in
synthetic provider payloads, and applies a limited demonstration OpenVEX matcher.
It emits one annotation per CVE observation and one combined job summary with
a single legend, followed by Azure and AWS result sections. Download the
`cloud-vex-showcase` artifact for raw/normalized findings, unresolved Azure
evidence, VEX, JSON proof and Markdown summary.

## Expected cases — exercised for both providers

| Case | CVE | Expected after VEX |
|---|---|---|
| Exact image digest and component version | CVE-2021-44228 | SUPPRESSED; not_affected with evidence |
| Different image digest | CVE-2021-44228 | ACTIVE |
| Different component version | CVE-2021-44228 | ACTIVE |
| Explicit affected statement | CVE-2021-45046 | ACTIVE |
| Under investigation | CVE-2021-45105 | ACTIVE |
| No matching statement | CVE-2021-44832 | ACTIVE |
| Missing image/component identity | CVE-2021-44228 | REVIEW_REQUIRED |
| AWS provider suppression (Azure control is Unhealthy) | CVE-2021-44832 | ACTIVE; provider suppression is not VEX |

Azure also includes one unresolved assessment with missing CVE details. Tests
verify it remains visible. Unit tests cover conflicting statements, missing
impact evidence, product-only scope, and annotation escaping.

## Scope and limits

These are synthetic findings using real CVE identifiers, not current severity,
fix-version, coverage, or vulnerability-intelligence claims. The not_affected
assertion describes an inert test fixture; never reuse it for a real service.
The service's `vex/openvex.json` is unchanged.

`fixtures/demo-identities.json` explicitly supplies demo-only identity mapping.
Azure currently emits unknown image/component identities; these fixture
identities were not discovered from Azure. Inspector's digest comes from the
normalized provider data; its versioned PURL mapping is fixture-supplied.
Production requires validated asset, image, architecture and package mapping.

The matcher requires exact CVE + digest product + versioned subcomponent. Only
one unambiguous not_affected statement with justification and impact evidence
can suppress a finding. Other statuses stay active; multiple matches require
review. This is not a full OpenVEX implementation, performs no signature/trust
verification, and does not replace the separate Grype VEX proof. Production
collectors are unchanged. Cloud BOD/EPSS and admission remain **NOT_EVALUATED**.

## Local verification

With both repositories as siblings, run from `service-blueprint`:

```bash
python3 -m unittest discover -s demo-cloud -p 'test_*.py' -v
python3 demo-cloud/showcase.py --shared ../github-actions --output /tmp/cloud-showcase --annotations
```

The output directory must not exist. Set `SHARED_ACTIONS` for a different test
checkout location. The CLI asserts all 16 expected dispositions; incorrect
suppression or missing cases fail the job.
