# service-blueprint — CI integration starter

This is a **demonstration scaffold**, not your actual application. Replace the
sample Dockerfile and add the application's real source code and tests.

## Connect to the central action

1. Create `github-actions` and push the corresponding starter repository there.
2. Update `.github/workflows/ci.yml`: replace `YOUR_ORG` and
   `REPLACE_WITH_FULL_COMMIT_SHA` with the organisation and an actual full commit SHA.
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
