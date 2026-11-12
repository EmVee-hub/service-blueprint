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


def target_match(data: dict) -> dict:
    matches = [
        match for match in data.get("matches", [])
        if (match.get("vulnerability") or {}).get("id") == TARGET_CVE
        and (match.get("artifact") or {}).get("name") == TARGET_PACKAGE
        and (match.get("artifact") or {}).get("version") == TARGET_VERSION
        and (match.get("artifact") or {}).get("purl")
    ]
    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one {TARGET_CVE} / {TARGET_PACKAGE}@{TARGET_VERSION} "
            f"baseline finding with PURL, found {len(matches)}"
        )
    return matches[0]


def create(baseline: Path, image: str, output: Path) -> None:
    if not image.startswith("policy-showcase:log4shell-public-"):
        raise ValueError("Only the Log4Shell non-serving demonstration image is supported")
    data = json.loads(baseline.read_text())
    found = target_match(data)
    purl = found["artifact"]["purl"]
    sub = {"@id": purl, "identifiers": {"purl": purl}}
    # The same image may be matched by its tag or its OCI PURL depending on
    # the Grype/Syft versions. Always scope BOTH to the exact package PURL.
    doc = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://example.invalid/vex/scan-only-log4shell-fixture",
        "author": "EmVee-hub training example (NOT FOR PRODUCTION USE)",
        "version": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "statements": [{
            "vulnerability": {"name": TARGET_CVE},
            "products": [
                {"@id": image, "subcomponents": [sub]},
                {"@id": "pkg:oci/policy-showcase",
                 "identifiers": {"purl": "pkg:oci/policy-showcase"},
                 "subcomponents": [sub]},
            ],
            "status": "not_affected",
            "justification": "vulnerable_code_not_in_execute_path",
            "impact_statement": (
                "TRAINING FIXTURE ONLY: final image contains Log4j JAR files "
                "as inert scan data, but no JVM or Java application executes "
                "them. This assessment does NOT apply to deployed applications."
            ),
        }]
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"Created demo-only OpenVEX for {TARGET_CVE}, package {purl}")


def check(baseline: Path, with_vex: Path, vex: Path, proof: Path) -> None:
    before = json.loads(baseline.read_text())
    after = json.loads(with_vex.read_text())
    doc = json.loads(vex.read_text())
    expected = key(target_match(before))

    if len(doc.get("statements", [])) != 1:
        raise ValueError("Expected a single, constrained demonstration VEX statement")
    if doc["statements"][0]["vulnerability"]["name"] != TARGET_CVE:
        raise ValueError("Wrong VEX vulnerability")
    active_before = {key(x) for x in before.get("matches", [])}
    active_after = {key(x) for x in after.get("matches", [])}
    if expected not in active_before or expected in active_after:
        raise ValueError("VEX did not move the intended vulnerability out of active matches")

    # All other findings must remain active; VEX must not broadly waive Log4j.
    if active_before - {expected} != active_after:
        raise ValueError("VEX changed findings beyond the one scoped advisory/package")

    ignored = [item for item in after.get("ignoredMatches", []) if key(item) == expected]
    if len(ignored) != 1:
        raise ValueError("The intended finding was not recorded in ignoredMatches")
    rules = ignored[0].get("appliedIgnoreRules") or []
    if not any(
        str(rule.get("namespace", "")).lower() == "vex"
        or "vex" in str(rule.get("reason", "")).lower()
        or rule.get("vexStatus") == "not_affected"
        for rule in rules if isinstance(rule, dict)
    ):
        raise ValueError("Grype ignored the finding but did not provide VEX rule evidence")
    result = {
        "verified": True,
        "vulnerability_id": expected[0],
        "package": TARGET_PACKAGE + "@" + TARGET_VERSION,
        "package_purl": expected[1],
        "active_before": len(before.get("matches", [])),
        "active_after": len(after.get("matches", [])),
        "suppressed_count": 1,
        "reason": "vulnerable_code_not_in_execute_path",
        "scope": "non-serving local training image only",
    }
    proof.parent.mkdir(parents=True, exist_ok=True)
    proof.write_text(json.dumps(result, indent=2) + "\n")
    print(f"VEX VERIFIED: {expected[0]} {expected[1]} suppressed; all others remain active")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["create", "check"])
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--image")
    parser.add_argument("--with-vex", type=Path)
    parser.add_argument("--vex", required=True, type=Path)
    parser.add_argument("--proof", type=Path)
    args = parser.parse_args()
    if args.command == "create":
        if not args.image:
            parser.error("create requires --image")
        create(args.baseline, args.image, args.vex)
    else:
        if not args.with_vex or not args.proof:
            parser.error("check requires --with-vex and --proof")
        check(args.baseline, args.with_vex, args.vex, args.proof)


if __name__ == "__main__":
    main()
