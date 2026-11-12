# Vulnerability policy showcase

**Warning: intentionally old dependencies. Demonstration images must never be published or deployed.**
All sample images contain only package inventories and start no vulnerable applications.
The workflow builds them locally on GitHub-hosted runners, never runs a container
or exposes a network port, never logs into a registry, and never pushes anything.

Run: **Actions → Vulnerability policy showcase → Run workflow** on the showcase branch.
A pull request touching this directory also runs the demo. The action always uses
**shadow** mode, so a computed BLOCK is reported but does not stop the showcase.

## Demo matrix

| Name | Base / packages | Exposure input | Goal |
|---|---|---|---|
| Log4Shell public | log4j-core 2.14.1 | public | Critical / KEV example |
| Log4Shell internal | same exact Log4j package inventory | internal | Compare the same CVE under a different asset exposure |
| React2Shell public | react-server-dom-webpack 19.0.0 | public | Critical RCE CVE-2025-55182 (sometimes called Node2Shell in our discussions) |
| Tomcat + Spring public | tomcat-embed-core 9.0.55, spring-webmvc 5.3.13 | public | Several Java advisories |
| Mixed Java internal | commons-compress 1.21, snakeyaml 1.29, commons-lang3 3.12.0 | internal | Mixed vulnerabilities, potentially including Medium |
| Legacy Alpine internal | Alpine 3.18 | internal | OS package findings |
| Minimal scratch internal | scratch + one text file | internal | Clean/very-low baseline |

The exact number and severity of Grype findings, KEV status, EPSS bins and decision
outcomes are **dynamic**. The mixed example cannot guarantee a Medium vulnerability,
and even a Critical CVE does not guarantee a BLOCK when all contextual inputs
and the BOD/EPSS mapping are considered.

## How the workflow works

Each example builds a local image, scans it with Grype, applies the **existing**
project VEX document at `vex/openvex.json` (currently empty: no suppression),
fetches CISA Vulnrichment for CVEs, evaluates BOD 26-04 + the EPSS quartile
amplifier, and uploads a JSON/Markdown report.

The comparison job downloads those reports and creates a matrix including
Grype severity counts, each final outcome count and admission (ALLOW / BLOCK /
REVIEW_REQUIRED). The workflow also writes this summary to the job summary.

Actual packages are never used by a running Java/React server. Setting
`exposure: public` is a simulated input for **demonstrating** prioritisation,
not evidence that a public service is running. These images intentionally
contain vulnerable software but are not designed to demonstrate exploitability.
They also do not establish an appropriate `not_affected` VEX justification.

The BOD + EPSS unit tests in `github-actions` remain the authoritative,
deterministic regression tests. This demo is a live-data showcase, not a
fixed-output test suite.

## Sources
- Log4Shell: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- React2Shell: https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components
- CISA BOD 26-04 table: https://github.com/CERTCC/SSVC/blob/main/data/json/decision_tables/cisa/cisa_bod_26_04_1_0_0.json
