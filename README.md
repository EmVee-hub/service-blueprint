# service-blueprint — Container security PoC integration

This is a **demonstration scaffold**, not your actual application. Replace the
sample Dockerfile and add the application's real source code and tests.

## Connect to the central action

1. Use the shared `EmVee-hub/github-actions` PoC security action.
2. `.github/workflows/ci.yml` uses the reviewed immutable action commit
   `d9755233a90b93aec872719323db289d2651af77`. Update this pin
   intentionally after compatibility tests, not automatically.
3. Permit access to the shared action from this repository if the central repo is private.
4. Choose `exposure`: `public`, `internal` or `unknown`. Missing/unknown is treated as public.
5. Keep the VEX file in this repo. Its initial `statements: []` is intentional;
   **no vulnerabilities are suppressed** until statements have been reviewed and scoped.
6. Start with `mode: shadow`; review `security-reports/report.md` and
   `security-reports/decision.json` from Actions artifacts.
7. Only later switch to `mode: enforce` to block 3D/3DF and incomplete decisions.

## Not implemented in this scaffold

- Publishing to ACR/ECR or GitOps promotion.
- Real application build/test steps.
- Production digest attestation or deployment admission verification.
- Live Defender/Inspector cloud integrations (not part of this service PoC).
- Full OpenVEX signature or schema validation.

The CI action must run **after image build and before any production promotion**.

## CISA Vulnrichment lookup

The central CI action fetches CISA-ADP SSVC `Automatable` and `Technical Impact`
for CVEs detected by Grype, then applies the BOD 26-04 + EPSS policy.
The job needs outbound HTTPS access to `cveawg.mitre.org`.
An absent CISA assessment uses our documented defaults; an API failure
produces `REVIEW_REQUIRED` rather than a misleading clean decision.

The workflow intentionally stays in `shadow` mode until the actual GitHub
runner and CVE Services lookup have been smoke-tested. Security reports are
uploaded as Actions artifacts; the sample Dockerfile is not production code.

## Running container security — AKS, EKS and CI/CD

Our security scope is **running AKS/EKS Pod containers only**, alongside pre-deployment
CI/CD image scanning, including image packages and CVEs.

The synthetic runtime correlation demonstration lives in the central
[manual PoC showcase](https://github.com/EmVee-hub/github-actions/blob/main/.github/workflows/poc-showcase.yml) (select `runtime` or `all`).
It joins Inspector/Defender evidence to confirmed RUNNING containers using
immutable image digests and evaluates CISA BOD 26-04 + EPSS and project OpenVEX.
Unmatched/non-running registry images, Azure VM/EC2 hosts and node OS findings
are **not active runtime vulnerabilities**.

The older service-level `demo-cloud` suite only demonstrated standalone,
synthetic registry finding/VEX parsing without a runtime join. It is removed
from this scaffold to prevent it being confused with the running-container
pipeline. See the [central PoC architecture and limitations](https://github.com/EmVee-hub/github-actions/blob/main/docs/runtime-poc.md).

The normal application CI (`.github/workflows/ci.yml`) builds and scans the
candidate image and now also runs the lightweight vulnerability showcase unit
tests. The full `.github/workflows/demo-policy-showcase.yml` image matrix is
**manual-only**, for security walkthroughs rather than every pull request.

## PoC status

The image-scan and VEX/SSVC demonstrations are a **technical PoC**.
The shared AKS/EKS runtime join is validated with **synthetic evidence**, not
live-cluster coverage. Production cloud validation, trusted VEX and disposition
tracking are future operational MVP work.
