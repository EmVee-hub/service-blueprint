# Legend — How to read vulnerability scan reports

This is the **single legend for the entire workflow run**. Scan sections below
show the actual Grype findings and policy decisions without repeating these definitions.

## Scan result columns

| Column | Meaning |
|---|---|
| CVE/advisory | Vulnerability identifier reported by Grype, mapped to CVE when possible. |
| Package | Software package in the scanned image. |
| Severity | Grype Critical / High / Medium / Low; **not** the security gate. |
| KEV | CISA Known Exploited Vulnerabilities: Y = known exploited; N = provisional absence in Grype's refreshed data; UNKNOWN = unresolved. |
| PE | Publicly Exposed: Y = public or unknown default, N = declared internal; this is workflow context, not measured exposure. |
| A / Automatable | SSVC attribute for automatable exploitation: Y or N. Prefer CISA Vulnrichment, otherwise conservative Y default. |
| TI | SSVC Technical Impact: P = partial, T = total. Prefer CISA Vulnrichment, otherwise local heuristic/default. |
| SSVC lookup | FOUND = CISA assessment; NO_SSVC / NO_RECORD = fallback; FETCH_ERROR / INVALID_SSVC = review required. |
| EPSS / EPSS bin | **Exploit probability percentile** quartiles, not exploit probability or CVSS: Q1 below 25th, Q2 25–below 50th, Q3 50–below 75th, Q4 75–100th. Missing EPSS uses neutral Q2. |
| Base | Unmodified CISA BOD 26-04 outcome from KEV, PE, A, and TI. |
| Final | Base outcome after our local EPSS quartile mapping and guards. |
| Decision rule | Explains how the final priority was computed or preserved. |

## Decision rules

| Rule | Meaning |
|---|---|
| `AMPLIFIED` | Local EPSS mapping applied; output may remain unchanged. |
| `KEV_GUARD` | KEV=Y: preserve original BOD outcome regardless of EPSS. |
| `URGENT_BASE_GUARD` | BOD already returned 3D/3DF; EPSS cannot downgrade it. |
| `EPSS_UNAVAILABLE_NEUTRAL` | EPSS missing: use neutral Q2, not evidence of low risk. |
| `KEV_UNKNOWN` | Unresolved CVE/KEV mapping: review required. |
| `VULNRICHMENT_LOOKUP_FAILED` | CISA SSVC lookup invalid/unavailable: review required. |

## Outcomes and admission

| Value | Meaning |
|---|---|
| FSU | Fix on the next scheduled major upgrade/rebuild **and deploy**. |
| 60D, 14D, 3D | Remediation deadline within 60, 14 or 3 days. |
| 3DF | Three-day urgency plus forensic investigation/triage; **not** proof of compromise. |
| ALLOW | No 3D/3DF and no incomplete findings. |
| BLOCK | At least one 3D/3DF outcome; in this showcase, reported only (shadow mode). |
| REVIEW_REQUIRED | Incomplete inputs with no evaluated 3D/3DF already causing BLOCK. |
| VEX ignored | Finding moved to Grype `ignoredMatches` due to matching OpenVEX; retained as evidence. |

## Showcase comparison columns

| Column | Meaning |
|---|---|
| Example / Exposure | Demo image and simulated public/internal exposure. |
| Findings / C-H-M-L | Active findings and Grype severity distribution. |
| FSU / 60D / 14D / 3D / 3DF | Finding counts by **final** policy outcome. |
| Incomplete | Findings requiring policy review. |
| VEX ignored | Applicability-suppressed findings, not deleted. |
| Admission | ALLOW, BLOCK or REVIEW_REQUIRED from the shared evaluator. |

**Source vs rule:** Grype discovers findings, CISA can provide SSVC values,
and our decision rule explains prioritisation. EPSS amplification is **local policy**, not CISA's table.
