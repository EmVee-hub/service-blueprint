#!/usr/bin/env python3
"""Educational ONLY: verify a real OpenVEX finding is moved into ignoredMatches.

This is NOT a general-purpose VEX authoring tool. It only works with the
non-serving Log4Shell demo image (no JVM, network listener, or application).
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

TARGET_CVE = "CVE-2021-44228"
TARGET_PACKAGE = "log4j-core"
TARGET_VERSION = "2.14.1"


def key(match: dict) -> tuple[str, str]:
    return (
        str((match.get("vulnerability") or {}).get("id") or ""),
        str((match.get("artifact") or {}).get("purl") or ""),
    )


def target_matches(data: dict) -> list[dict]:
    """All advisories on the inert, exact Log4j core fixture component."""
    expected_purl = f"pkg:maven/org.apache.logging.log4j/{TARGET_PACKAGE}@{TARGET_VERSION}"
    matches = [m for m in data.get("matches", [])
               if (m.get("artifact") or {}).get("name") == TARGET_PACKAGE
               and (m.get("artifact") or {}).get("version") == TARGET_VERSION
               and (m.get("artifact") or {}).get("purl", "").split("?")[0] == expected_purl
               and key(m)[0]]
    ids = {key(m)[0] for m in matches}
    aliases = {v.get("id") for m in matches for v in m.get("relatedVulnerabilities", [])}
    if TARGET_CVE not in ids | aliases:
        raise ValueError("Expected the Log4Shell baseline finding (primary ID or CVE alias)")
    return list({key(m): m for m in matches}.values())


def create(baseline: Path, image: str, output: Path) -> None:
    if not image.startswith("policy-showcase:log4shell-public-"):
        raise ValueError("Only the Log4Shell non-serving demonstration image is supported")
    data = json.loads(baseline.read_text())
    found = target_matches(data)
    # The same image may be matched by its tag or its OCI PURL depending on
    # the Grype/Syft versions. Always scope BOTH to the exact package PURL.
    doc = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://example.invalid/vex/scan-only-log4shell-fixture",
        "author": "EmVee-hub training example (NOT FOR PRODUCTION USE)",
        "version": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "statements": [{
            "vulnerability": {"name": key(match)[0]},
            "products": [
                {"@id": image, "subcomponents": [{"@id": key(match)[1], "identifiers": {"purl": key(match)[1]}}]},
                {"@id": "pkg:oci/policy-showcase",
                 "identifiers": {"purl": "pkg:oci/policy-showcase"},
                 "subcomponents": [{"@id": key(match)[1], "identifiers": {"purl": key(match)[1]}}]},
            ],
            "status": "not_affected",
            "justification": "vulnerable_code_not_in_execute_path",
            "impact_statement": "Not in use by application - Showcase",
        } for match in found]
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"Created demo-only OpenVEX for {len(found)} exact Log4j advisory/package pairs")


def check(baseline: Path, with_vex: Path, vex: Path, proof: Path, decision: Path) -> None:
    before = json.loads(baseline.read_text())
    after = json.loads(with_vex.read_text())
    doc = json.loads(vex.read_text())
    expected = {key(m) for m in target_matches(before)}
    statements = doc.get("statements", [])
    actual = {(s["vulnerability"]["name"], p["@id"])
              for s in statements for product in s["products"]
              for p in product.get("subcomponents", [])}
    if actual != expected or len(statements) != len(expected):
        raise ValueError("VEX must cover exactly the inert Log4j advisory/package pairs")
    if any(s.get("status") != "not_affected" or
           s.get("justification") != "vulnerable_code_not_in_execute_path" for s in statements):
        raise ValueError("Unexpected VEX assessment")
    active_before = {key(x) for x in before.get("matches", [])}
    active_after = {key(x) for x in after.get("matches", [])}
    if active_before - expected != active_after:
        raise ValueError("VEX failed to suppress all intended findings or changed unrelated findings")
    for target in expected:
        ignored = [m for m in after.get("ignoredMatches", []) if key(m) == target]
        if not ignored or not all(any(
            str(rule.get("namespace", "")).lower() == "vex"
            or "vex" in str(rule.get("reason", "")).lower()
            or rule.get("vexStatus") == "not_affected"
            for rule in m.get("appliedIgnoreRules", []) if isinstance(rule, dict)
        ) for m in ignored):
            raise ValueError(f"Missing ignoredMatches VEX evidence for {target}")
    admission = json.loads(decision.read_text()).get("admission")
    if admission != "ALLOW":
        raise ValueError(f"Expected ALLOW after demo VEX, got {admission!r}")
    result = {
        "verified": True,
        "vulnerability_id": ", ".join(sorted({k[0] for k in expected})),
        "vulnerability_ids": sorted({k[0] for k in expected}),
        "admission": admission,
        "package": TARGET_PACKAGE + "@" + TARGET_VERSION,
        "package_purls": sorted({k[1] for k in expected}),
        "active_before": len(before.get("matches", [])),
        "active_after": len(after.get("matches", [])),
        "suppressed_count": len(expected),
        "reason": "vulnerable_code_not_in_execute_path",
        "scope": "non-serving local training image only",
    }
    proof.parent.mkdir(parents=True, exist_ok=True)
    proof.write_text(json.dumps(result, indent=2) + "\n")
    print(f"VEX VERIFIED: {len(expected)} scoped findings suppressed; admission ALLOW; unrelated findings remain active")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["create", "check"])
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--image")
    parser.add_argument("--with-vex", type=Path)
    parser.add_argument("--vex", required=True, type=Path)
    parser.add_argument("--proof", type=Path)
    parser.add_argument("--decision", type=Path)
    args = parser.parse_args()
    if args.command == "create":
        if not args.image:
            parser.error("create requires --image")
        create(args.baseline, args.image, args.vex)
    else:
        if not args.with_vex or not args.proof or not args.decision:
            parser.error("check requires --with-vex, --proof and --decision")
        check(args.baseline, args.with_vex, args.vex, args.proof, args.decision)


if __name__ == "__main__":
    main()


