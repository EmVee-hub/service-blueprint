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
    lines = [
        "# CI vulnerability policy showcase",
        "",
        "**Shadow mode only. No images are pushed, executed, or deployed.**",
        "",
        "| Example | Exposure | Findings | C / H / M / L | FSU | 60D | 14D | 3D | 3DF | Incomplete | VEX ignored | Admission |",
        "|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    ready = 0
    for case, exposure in CASES:
        folder = root / ("showcase-" + case)
        try:
            decision = json.loads((folder / "decision.json").read_text())
            grype = json.loads((folder / "grype.json").read_text())
        except (OSError, ValueError):
            lines.append(f"| {case} | {exposure} | — | — | — | — | — | — | — | — | — | NO_REPORT |")
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
    proof_file = root / "showcase-vex-proof" / "proof.json"
    lines += ["", "## OpenVEX: before vs. after", ""]
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
        f"Reports generated: **{ready}/{len(CASES)}**.",
        "",
        "Read each decision.json for KEV, CISA SSVC source, EPSS bin, BOD baseline and guard.",
        "Severity alone does not determine admission. Actual findings change as intelligence is updated.",
    ]
    return "\n".join(lines) + "\n"

if __name__ == "__main__":
    print(report(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("showcase-results")), end="")
