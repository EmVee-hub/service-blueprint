#!/usr/bin/env python3
"""Compare real Grype findings and BOD/EPSS priorities without fixed assumptions."""
import json
import sys
from collections import Counter
from pathlib import Path

CASES = [
    ("log4shell-public", "public"),
    ("log4shell-internal", "internal"),
    ("react2shell-public", "public"),
    ("tomcat-spring-public", "public"),
    ("library-mix-internal", "internal"),
    ("legacy-alpine-internal", "internal"),
    ("minimal-scratch-internal", "internal"),
]

def report(root):
    lines = ["# CI vulnerability policy showcase", ""] + ["## 1. Legend — read this before the scan results","","**Scan overview columns**","","| Column | Meaning |","|---|---|","| Example | Image and simulated deployment scenario. |","| Exposure | Public or internal declaration, not a measured network exposure. |","| Findings | Active Grype matches after applicability filtering. |","| C / H / M / L | Grype Critical / High / Medium / Low counts; severity alone does **not** decide admission. |","| FSU | Findings to fix on the next scheduled major upgrade/rebuild **and deployment**. |","| 60D / 14D / 3D | Findings assigned final 60-day / 14-day / 3-day remediation outcomes. |","| 3DF | Findings assigned 3-day remediation **plus forensic triage**; not proof of compromise. |","| Incomplete | Findings missing trustworthy decision inputs; require review. |","| VEX ignored | Findings moved into Grype `ignoredMatches` by a matching OpenVEX statement, retained for evidence. |","| Admission | `ALLOW`: no 3D/3DF and no incomplete findings; `BLOCK`: at least one 3D/3DF; `REVIEW_REQUIRED`: incomplete without BLOCK. In this showcase all decisions run in shadow mode. |","","**Individual scan columns**","","| Column | Meaning |","|---|---|","| CVE/advisory | Vulnerability ID reported or mapped by Grype. |","| Package | Detected vulnerable software component. |","| Severity | Grype's severity rating, separate from our policy deadline. |","| KEV | CISA Known Exploited Vulnerabilities `Y` / `N` / `UNKNOWN`; Grype-absence `N` is provisional. |","| PE | Publicly Exposed `Y` or `N`; unknown is conservatively treated as `Y`. |","| A | SSVC Automatable `Y` or `N`, from CISA Vulnrichment or our documented default. |","| TI | SSVC Technical Impact `P` = partial, `T` = total. |","| SSVC lookup | `FOUND`: official CISA SSVC; `NO_SSVC`/`NO_RECORD`: fallback; `FETCH_ERROR`/`INVALID_SSVC`: review. |","| EPSS | Percentile quartile: Q1 below 25th, Q2 25–below 50th, Q3 50–below 75th, Q4 75–100th; missing = neutral Q2. |","| Base / Final | CISA BOD 26-04 base result / result after our EPSS quartile amplifier and guards. |","| Decision rule | Why the final outcome was computed or preserved. |","","**Decision-rule legend**","","| Rule | Meaning |","|---|---|","| `AMPLIFIED` | Applied the EPSS quartile mapping; it may leave the outcome unchanged. |","| `KEV_GUARD` | Known exploited (KEV=Y); keep original BOD outcome. |","| `URGENT_BASE_GUARD` | BOD already returned 3D or 3DF; cannot downgrade. |","| `EPSS_UNAVAILABLE_NEUTRAL` | EPSS absent; use neutral Q2 and record uncertainty. |","| `KEV_UNKNOWN` | Unresolved KEV mapping; review required. |","| `VULNRICHMENT_LOOKUP_FAILED` | CISA SSVC lookup failed or was invalid; review required. |","","**Data source vs rule:** Grype discovers findings, CISA may supply SSVC inputs, and the decision rule explains our policy. OpenVEX changes *applicability* only when an exact statement matches.",""] + ["## 2. Scan overview","","**Shadow mode only. No images are pushed, executed, or deployed.**","","| Example | Exposure | Findings | C / H / M / L | FSU | 60D | 14D | 3D | 3DF | Incomplete | VEX ignored | Admission |","|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---|"]
    ready = 0
    scan_sections = []
    for case, exposure in CASES:
        folder = root / ("showcase-" + case)
        try:
            decision = json.loads((folder / "decision.json").read_text())
            grype = json.loads((folder / "grype.json").read_text())
        except (OSError, ValueError):
            lines.append(f"| {case} | {exposure} | — | — | — | — | — | — | — | — | — | NO_REPORT |")
            scan_sections += ["### `" + case + "`", "", "_No scan report was uploaded._", ""]
            continue
        ready += 1
        severity = Counter(
            str((m.get("vulnerability") or {}).get("severity", "unknown")).lower()
            for m in grype.get("matches", [])
        )
        counts = decision.get("counts", {})
        fields = [
            case, exposure, str(len(grype.get("matches", []))),
            " / ".join(str(severity.get(k, 0)) for k in ("critical", "high", "medium", "low")),
            *(str(counts.get(k, 0)) for k in ("FSU", "60D", "14D", "3D", "3DF", "INCOMPLETE")),
            str(decision.get("vex_ignored_count", 0)),
            str(decision.get("admission", "UNKNOWN")),
        ]
        lines.append("| " + " | ".join(fields) + " |")
        scan_sections += ["### `" + case + "`", "",
                          "- Exposure: `" + exposure + "`",
                          "- Admission: **" + str(decision.get("admission", "UNKNOWN")) + "**",
                          "- Active findings: " + str(len(grype.get("matches") or [])),
                          "- VEX ignored: " + str(decision.get("vex_ignored_count", 0)),
                          "",
                          "| CVE/advisory | Package | Severity | KEV | PE | A | TI | SSVC lookup | EPSS | Base | Final | Decision rule |",
                          "|---|---|---|---|---|---|---|---|---|---|---|---|"]
        urgency = {"INCOMPLETE": -1, "3DF": 0, "3D": 1, "14D": 2, "60D": 3, "FSU": 4}
        findings = sorted(decision.get("findings") or [],
                          key=lambda f: urgency.get(f.get("final_outcome") or "INCOMPLETE", 5))
        for finding in findings[:5]:
            fields = [finding.get("cve") or finding.get("vulnerability_id"),
                      finding.get("package"), finding.get("severity"), finding.get("kev"),
                      finding.get("publicly_exposed"), finding.get("automatable"),
                      finding.get("technical_impact"), finding.get("vulnrichment_status"),
                      finding.get("epss_bin"), finding.get("base_outcome"),
                      finding.get("final_outcome"), finding.get("rule")]
            scan_sections.append("| " + " | ".join(
                str(x if x is not None else "—").replace("|", "\\|").replace("\n", " ")
                for x in fields) + " |")
        if not findings:
            scan_sections.append("| No active findings | — | — | — | — | — | — | — | — | — | — | — |")
        elif len(findings) > 5:
            scan_sections.append("_Five highest-priority findings shown; see the individual report.md for all "
                                 + str(len(findings)) + " findings._")
        scan_sections.append("")
    lines += ["", "## 3. Individual scan sections", ""] + scan_sections

    proof_file = root / "showcase-vex-proof" / "proof.json"
    lines += ["", "## 4. OpenVEX: before vs. after", ""]
    if proof_file.is_file():
        try:
            proof = json.loads(proof_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            proof = {}
        if proof.get("verified") is True:
            lines += [
                f"- Scoped example: `{proof['vulnerability_id']}` in `{proof['package']}`.",
                f"- Active findings before VEX: **{proof['active_before']}**.",
                f"- Active findings after VEX: **{proof['active_after']}**.",
                f"- VEX-suppressed matching finding(s): **{proof['suppressed_count']}**.",
                f"- Remaining active findings are still evaluated; VEX did not waive other CVEs.",
                "",
            ]
        else:
            lines.append("VEX proof report exists, but verification failed. Review job logs.")
    else:
        lines.append("No verified VEX evidence was uploaded. The VEX demonstration is incomplete.")

    lines += [
        "",
        "## 5. Run summary",
        "",
        f"Reports generated: **{ready}/{len(CASES)}**.",
        "",
        "Read each decision.json for KEV, CISA SSVC source, EPSS bin, BOD baseline and guard.",
        "Severity alone does not determine admission. Actual findings change as intelligence is updated.",
    ]
    return "\n".join(lines) + "\n"

if __name__ == "__main__":
    print(report(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("showcase-results")), end="")
