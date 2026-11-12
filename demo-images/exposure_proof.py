#!/usr/bin/env python3
"""Demonstrate how an omitted exposure input defaults to publicly exposed.

This checks real output from two shared-action scans of the SAME locally built
cae-live Nginx image. Works even when the image has no vulnerability matches.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def identity(finding: dict) -> tuple:
    return (
        finding.get("vulnerability_id"),
        finding.get("package"),
        finding.get("installed_version"),
    )


def verify(explicit: dict, omitted: dict) -> dict:
    image = explicit.get("image")
    if not isinstance(image, str) or not image.startswith("cae-live:ci-"):
        raise ValueError("Expected the locally built cae-live image")
    if omitted.get("image") != image:
        raise ValueError("Both reports must scan the exact same image tag")
    for name, report, exposure_input, source in [
        ("explicit", explicit, "public", "PROJECT_DECLARATION"),
        ("omitted", omitted, "unknown", "UNKNOWN_DEFAULT_PUBLIC"),
    ]:
        if report.get("exposure_input") != exposure_input:
            raise ValueError(f"{name}: expected exposure_input={exposure_input}")
        if report.get("publicly_exposed") != "Y":
            raise ValueError(f"{name}: effective publicly_exposed should be Y")
        if report.get("exposure_source") != source:
            raise ValueError(f"{name}: expected source={source}")
        for finding in report.get("findings") or []:
            if finding.get("publicly_exposed") != "Y" or finding.get("exposure_source") != source:
                raise ValueError(f"{name}: individual finding does not match the exposure source")
    left = Counter(identity(f) for f in (explicit.get("findings") or []))
    right = Counter(identity(f) for f in (omitted.get("findings") or []))
    if left != right:
        raise ValueError("Two reports contain different vulnerability/package sets")
    return {
        "verified": True,
        "image": image,
        "explicit": {
            "exposure_input": "public",
            "publicly_exposed": "Y",
            "exposure_source": "PROJECT_DECLARATION",
            "admission": explicit.get("admission"),
        },
        "omitted": {
            "exposure_input": "unknown",
            "publicly_exposed": "Y",
            "exposure_source": "UNKNOWN_DEFAULT_PUBLIC",
            "admission": omitted.get("admission"),
        },
        "findings": sum(left.values()),
        "same_vulnerability_inventory": True,
        "same_admission": explicit.get("admission") == omitted.get("admission"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--explicit", type=Path, required=True)
    parser.add_argument("--omitted", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(
        json.loads(args.explicit.read_text(encoding="utf-8")),
        json.loads(args.omitted.read_text(encoding="utf-8")),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("CA E-LIVE EXPOSURE DEFAULT VERIFIED: public / declared -> Y; omitted / default -> Y")


if __name__ == "__main__":
    main()
