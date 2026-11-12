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
    ("cae-live-public", "public"),
    ("cae-live-no-exposure", "omitted"),
]

# Live scans demonstrate capabilities; exact CVE counts and admission are dynamic.
GOALS = {
    "log4shell-public": ("Demonstrate KEV-aware prioritization of vulnerable Log4j with public exposure.", "Scan Log4j and report BOD/EPSS decisions with PE=Y; admission depends on current intelligence."),
    "log4shell-internal": ("Show how internal exposure affects the same Log4j inventory.", "Evaluate with PE=N for comparison with log4shell-public; a different verdict is not guaranteed."),
    "react2shell-public": ("Demonstrate JavaScript dependency vulnerability detection.", "Scan the React Server Components inventory and report contextual decisions with PE=Y."),
    "tomcat-spring-public": ("Demonstrate decisions for multiple vulnerable Java dependencies.", "Report individual Tomcat/Spring findings and their BOD/EPSS outcomes."),
    "library-mix-internal": ("Show prioritization across a mixed Java dependency inventory.", "Evaluate findings with internal exposure; severity alone does not determine admission."),
    "legacy-alpine-internal": ("Demonstrate OS and base-image package scanning.", "Report findings detected in the Alpine inventory with internal exposure."),
    "minimal-scratch-internal": ("Demonstrate the minimal-image baseline and empty-finding handling.", "Produce a valid report even when no vulnerable packages are detected."),
    "cae-live-public": ("Demonstrate an explicit public-exposure declaration for Nginx.", "Record PE=Y and PROJECT_DECLARATION, even with zero findings."),
    "cae-live-no-exposure": ("Verify the conservative default when exposure is omitted.", "Record unknown input, PE=Y and UNKNOWN_DEFAULT_PUBLIC for the same Nginx image."),
}


def intent(case):
    goal, expected = GOALS[case]
    return ["**Goal of test:** " + goal, "", "**Expected behavior:** " + expected, ""]


def report(root):
    lines = [
        "# CI vulnerability policy showcase",
        "",
        "## 1. Scan overview",
        "",
        "**Shadow mode only. No images are pushed, executed, or deployed.**",
        "A test can succeed by correctly producing BLOCK. Image admission is separate from test success. Live scans have no fixed admission expectation.",
        "",
        "| Example | Exposure | Findings | C / H / M / L | FSU | 60D | 14D | 3D | 3DF | Incomplete | VEX ignored | Admission |",
        "|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    ready = 0
    scan_sections = []
    for case, exposure in CASES:
        folder = root / ("showcase-" + case)
        try:
            decision = json.loads((folder / "decision.json").read_text())
            grype = json.loads((folder / "grype.json").read_text())
        except (OSError, ValueError):
            lines.append(f"| {case} | {exposure} | — | — | — | — | — | — | — | — | — | NO_REPORT |")
            scan_sections += ["### `" + case + "`", ""] + intent(case) + ["**Actual result:** NO_REPORT — missing or unreadable scan evidence; test outcome unverified.", ""]
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
        input_label = "omitted" if case == "cae-live-no-exposure" else decision.get("exposure_input", exposure)
        pe_label = decision.get("publicly_exposed", "?")
        source_label = decision.get("exposure_source", "UNKNOWN")
        display_exposure = str(input_label) + " -> PE=" + str(pe_label)
        fields[1] = display_exposure
        # Show declared/default exposure clearly in the overview.
        lines[-1] = "| " + " | ".join(fields) + " |"
        scan_sections += ["### `" + case + "`", ""] + intent(case) + [
                          "**Actual result:** Scan evidence received; observed values below (not a test-pass assertion).", "",
                          "- Exposure: `" + str(input_label) + "` → PE=`" + str(pe_label) + "`",
                          "- Exposure source: `" + str(source_label) + "`",
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
    lines += ["", "## 2. Individual scan sections", ""] + scan_sections

    proof_candidates = sorted((root / "showcase-vex-proof").rglob("proof.json"))
    proof_file = proof_candidates[0] if proof_candidates else (root / "showcase-vex-proof" / "proof.json")
    lines += ["", "## 3. OpenVEX: before vs. after", "",
              "**Goal of test:** Demonstrate scoped VEX suppression on the same image.", "",
              "**Expected behavior:** All scoped Log4j findings move to ignoredMatches with VEX evidence; unrelated components remain active and after-VEX admission is ALLOW.", ""]
    if proof_file.is_file():
        try:
            proof = json.loads(proof_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            proof = {}
        if proof.get("verified") is True:
            lines += [
                "**Actual result:** PASS — verified VEX proof.", "",
                f"- Scoped example: `{proof['vulnerability_id']}` in `{proof['package']}`.",
                f"- Active findings before VEX: **{proof['active_before']}**.",
                f"- Active findings after VEX: **{proof['active_after']}**.",
                f"- VEX-suppressed matching finding(s): **{proof['suppressed_count']}**.",
                f"- After-VEX admission: **{proof.get('admission', 'UNKNOWN')}**.",
                "- Unrelated components remain active and are still evaluated.",
                "",
            ]
        else:
            lines.append("**Actual result:** UNVERIFIED — VEX proof does not confirm success. Review job logs.")
    else:
        lines.append("**Actual result:** NO_REPORT — no verified VEX evidence was uploaded; demonstration incomplete.")

    lines += ["", "## 4. cae-live: explicitly public vs omitted exposure", "",
              "**Goal of test:** Verify explicit and omitted exposure handling on the same Nginx image.", "",
              "**Expected behavior:** Both use PE=Y, with PROJECT_DECLARATION versus UNKNOWN_DEFAULT_PUBLIC recorded as the source.", ""]
    exposure_files = sorted((root / "showcase-cae-live-no-exposure").rglob("exposure-proof.json"))
    if exposure_files:
        try:
            exposure_proof = json.loads(exposure_files[0].read_text(encoding="utf-8"))
        except (OSError, ValueError):
            exposure_proof = {}
        if exposure_proof.get("verified") is True:
            lines += [
                "**Actual result:** PASS — verified exposure proof.", "",
                "- Same locally built image: `" + str(exposure_proof["image"]) + "`",
                "- Explicitly public: input=`public`, PE=`Y`, source=`PROJECT_DECLARATION`.",
                "- Exposure input omitted: action default=`unknown`, PE=`Y`, source=`UNKNOWN_DEFAULT_PUBLIC`.",
                "- Active matches in both reports: **" + str(exposure_proof["findings"]) + "**.",
                "- Matching vulnerability inventories: **verified**.",
                "- Admission — declared: **" + str(exposure_proof["explicit"]["admission"]) +
                  "**; omitted: **" + str(exposure_proof["omitted"]["admission"]) + "**.",
            ]
            if not exposure_proof.get("same_admission"):
                lines.append("_Admission differs; review changes in live vulnerability intelligence between scans._")
        else:
            lines.append("**Actual result:** UNVERIFIED — exposure proof does not confirm success; review the cae-live scan job.")
    else:
        lines.append("**Actual result:** NO_REPORT — no cae-live exposure proof artifact found.")

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

