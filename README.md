# service-blueprint — CI integration starter

This is a **demonstration scaffold**, not your actual application. Replace the
sample Dockerfile and add the application's real source code and tests.

## Connect to the central action

1. Create `github-actions` and push the corresponding starter repository there.
2. `.github/workflows/ci.yml` is pinned to `EmVee-hub/github-actions` commit
   `893b850d923a8aee93715245dddd07cfc3eda1c3` (Vulnrichment PR branch).
   Keep that commit reachable; update the SHA deliberately after reviewing changes.
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
- Runtime Defender/Inspector readers (a separate MVP workflow).
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

The active end-to-end cloud correlation showcase now lives in the central
[container runtime policy CI](https://github.com/EmVee-hub/github-actions/blob/main/.github/workflows/runtime-demo.yml).
It joins Inspector/Defender evidence to confirmed RUNNING containers using
immutable image digests and evaluates CISA BOD 26-04 + EPSS and project OpenVEX.
Unmatched/non-running registry images, Azure VM/EC2 hosts and node OS findings
are **not active runtime vulnerabilities**.

The older service-level `demo-cloud` suite only demonstrated standalone,
synthetic registry finding/VEX parsing without a runtime join. It is removed
from this scaffold to prevent it being confused with the running-container
pipeline. See the [central runtime pilot documentation](https://github.com/EmVee-hub/github-actions/blob/main/docs/runtime-mvp.md).

The application CI Grype and OpenVEX showcase remains in this repository.
