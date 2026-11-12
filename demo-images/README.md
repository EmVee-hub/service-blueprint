# Vulnerability policy showcase

**Warning: intentionally old dependencies. Demonstration images must never be published or deployed.**
Most vulnerable-package examples are inert inventories; `cae-live` is a plain Nginx image that **would** start Nginx if deployed, but our CI only builds and scans it. No containers are run by the workflow.
The workflow builds them locally on GitHub-hosted runners, never runs a container
or exposes a network port, never logs into a registry, and never pushes anything.

While the PR is open, the showcase runs automatically via the **pull_request** event.
After the workflow is merged into the default branch, you can also use
**Actions → Vulnerability policy showcase → Run workflow** manually. The action always uses
**shadow** mode, so a computed BLOCK is reported but does not stop the showcase.

## Demo matrix

| Name | Base / packages | Exposure input | Goal |
|---|---|---|---|
| Log4Shell public | log4j-core 2.14.1 | public | Critical / KEV example |
| Log4Shell internal | same exact Log4j package inventory | internal | Compare the same CVE under a different asset exposure |
| React2Shell public | react-server-dom-webpack 19.0.0 | public | Critical RCE CVE-2025-55182 (sometimes called Node2Shell in our discussions) |
| Tomcat + Spring public | tomcat-embed-core 9.0.55, spring-webmvc 5.3.13 | public | Several Java advisories |
| Mixed Java internal | commons-compress 1.21, snakeyaml 1.29, commons-lang3 3.12.0 | internal | Known Medium example CVE-2024-26308 plus mixed other severities |
| Legacy Alpine internal | Alpine 3.18 | internal | OS package findings |
| Minimal scratch internal | scratch + one text file | internal | Clean/very-low baseline |
| `cae-live` public | Plain `nginx:stable-alpine` image | **public** | Explicit PE=Y project declaration |
| `cae-live` no exposure | **Same** Nginx image, same job | **omitted (not even `unknown`)** | Action defaults to `unknown`, effective PE=Y with `UNKNOWN_DEFAULT_PUBLIC` |

The exact number and severity of Grype findings, KEV status, EPSS bins and decision
outcomes are **dynamic**. The mixed example cannot guarantee a Medium vulnerability,
and even a Critical CVE does not guarantee a BLOCK when all contextual inputs
and the BOD/EPSS mapping are considered.

## `cae-live`: public vs missing exposure

The showcase builds a plain `nginx:stable-alpine` image locally tagged `cae-live:ci-<commit>`.
The `cae-live-public` scan explicitly passes `exposure: public` to the shared action.
Immediately afterwards, a second scan of **the same built image** intentionally
omits the `exposure` input entirely. The composite-action default becomes `unknown`,
which the evaluator conservatively maps to publicly exposed (`PE=Y`).

An automated assertion checks the actual JSON results for both cases:

- Explicit input: `exposure_input=public`, `publicly_exposed=Y`, `exposure_source=PROJECT_DECLARATION`.
- Omitted input: `exposure_input=unknown`, `publicly_exposed=Y`, `exposure_source=UNKNOWN_DEFAULT_PUBLIC`.
- Both report the **same image reference** and all individual findings use the expected PE and source.
- Even if a modern Nginx image has **zero CVEs**, the exposure result is still visible at report level.

The combined report includes the comparison and uploads `exposure-proof.json`.
Setting `exposure: public` is a **policy declaration**, not proof the image
is deployed, reachable from the internet, or automatically exposed by Nginx.
No image is pushed or deployed by this demo.

## Report layout: one legend per workflow run

Each workflow run publishes `security/report-legend.md` **once** in a dedicated
`legend` job. Scan jobs depend on that job via `needs: [legend]`, so the legend
is published before any scan starts. The shared Grype action produces **scan
results only**, without repeating the legend in each image section or artifact.

The combined comparison contains only scan overview, per-image findings, VEX
proof, and run summary. The regular application CI workflow uses the same
one-time legend job before its scan.

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

## OpenVEX before/after demonstration

Unlike the other matrix cases (which use the project's empty `vex/openvex.json`),
the **log4shell-public** case runs a second scan of the **same local image**
with a generated, tightly scoped OpenVEX document:

1. First scan: Grype finds Log4Shell without any suppression.
2. `vex_proof.py create` creates one statement for **every detected advisory**
   on the exact `log4j-core:2.14.1` Maven PURL, including scanner-primary IDs
   such as GHSA IDs. Log4Shell must be present as a primary ID or CVE alias.
   Each statement uses `vulnerable_code_not_in_execute_path`: the final
   training image contains inert JARs, with no JVM or Java application.
3. Second scan: the shared action applies this generated demo VEX.
4. The test **fails** unless every targeted finding moves into `ignoredMatches`
   with VEX evidence, all unrelated findings remain active, and the second
   policy decision is **ALLOW**. Missing/incomplete decisions cannot pass.
5. Both reports, the generated VEX and `proof.json` are uploaded. The baseline
   `log4shell-public` remains visible for comparison; `vex-proof` is its passing
   after-VEX result, including all suppressed advisory IDs and counts.

This covers all Log4j findings in the fixture, rather than only CVE-2021-44228.
OS packages and other components are not covered by the no-JVM justification;
if they block admission, the proof fails for investigation instead of hiding them.

**Critical:** this is a controlled educational fixture, not an automated
vulnerability disposition. Never copy this `not_affected` assertion to a
running application, where Log4Shell may actually be exploitable. Real VEX
requires project-specific evidence, identity matching, review and approval.

## Decision-rule definitions

The legend appears only in the prerequisite `legend` job; per-image reports contain scan results and VEX evidence without repeating it.


The BOD + EPSS unit tests in `github-actions` remain the authoritative,
deterministic regression tests. This demo is a live-data showcase, not a
fixed-output test suite.

## Sources
- Log4Shell: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- React2Shell: https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components
- CISA BOD 26-04 table: https://github.com/CERTCC/SSVC/blob/main/data/json/decision_tables/cisa/cisa_bod_26_04_1_0_0.json

