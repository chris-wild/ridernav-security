#!/usr/bin/env python3
"""Check RiderNav's resolved dependencies against the OSV vulnerability database.

Covers both ecosystems:
  - Maven: the Android app's RESOLVED releaseRuntimeClasspath (this script invokes gradlew and
    parses the resolution arrows, so version-catalog requests upgraded by Gradle are checked at the
    version that actually ships).
  - SwiftURL: the pinned Swift packages in the Xcode workspace's Package.resolved.

Exit code 1 when any known vulnerability is found (CI-gating). Writes a JSON summary when
--out is given, for the report generator.
"""
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def resolved_maven_artifacts() -> list[str]:
    out = subprocess.run(
        ["./gradlew", "-q", ":app:dependencies", "--configuration", "releaseRuntimeClasspath"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout
    resolved: set[str] = set()
    for line in out.splitlines():
        m = re.search(r"--- ([a-z0-9.\-]+):([a-zA-Z0-9._\-]+):([^ ]+?)(?: \(\*\)| \(c\))?\s*$", line)
        if m:
            group, artifact, version = m.groups()
            if " -> " in line:
                version = re.search(r"-> ([^ ]+?)(?: \(\*\)| \(c\))?\s*$", line).group(1)
            resolved.add(f"{group}:{artifact}:{version}")
            continue
        m2 = re.search(r"--- ([a-z0-9.\-]+):([a-zA-Z0-9._\-]+) -> ([^ ]+?)(?: \(\*\)| \(c\))?\s*$", line)
        if m2:
            resolved.add(":".join(m2.groups()))
    return sorted(resolved)


def swift_packages() -> list[tuple[str, str]]:
    resolved_file = REPO / "ios/RiderNav.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved"
    if not resolved_file.exists():
        return []
    data = json.loads(resolved_file.read_text())
    packages = []
    for pin in data.get("pins", data.get("object", {}).get("pins", [])):
        location = pin.get("location") or pin.get("repositoryURL") or ""
        name = re.sub(r"^https?://", "", location).removesuffix(".git")
        version = (pin.get("state") or {}).get("version")
        if name and version:
            packages.append((name, version))
    return packages


def osv_query(queries: list[dict]) -> list[dict]:
    body = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch", data=body, headers={"Content-Type": "application/json"}
    )
    # Retry transient OSV outages (a 503 failed a CI run on day one); a real finding is stable
    # across retries, so this cannot mask one.
    for attempt in range(4):
        try:
            # The URL is the literal https endpoint above; no dynamic scheme can reach urlopen.
            return json.load(urllib.request.urlopen(req, timeout=120))["results"]  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        except (urllib.error.HTTPError, urllib.error.URLError):
            if attempt == 3:
                raise
            time.sleep(10 * (attempt + 1))
    raise RuntimeError("unreachable")


def main() -> int:
    out_path = None
    if "--out" in sys.argv:
        out_path = Path(sys.argv[sys.argv.index("--out") + 1])

    maven = resolved_maven_artifacts()
    swift = swift_packages()
    queries = [
        {"package": {"name": a.rsplit(":", 1)[0], "ecosystem": "Maven"}, "version": a.rsplit(":", 1)[1]}
        for a in maven
    ] + [
        {"package": {"name": name, "ecosystem": "SwiftURL"}, "version": version}
        for name, version in swift
    ]
    results = osv_query(queries)

    subjects = maven + [f"{n}:{v}" for n, v in swift]
    vulns = [
        {"artifact": subjects[i], "ids": [v["id"] for v in r["vulns"]]}
        for i, r in enumerate(results) if r.get("vulns")
    ]

    print(f"osv-check: {len(maven)} resolved Maven artifacts + {len(swift)} Swift packages checked")
    for v in vulns:
        print(f"VULN: {v['artifact']} {v['ids']}")
    if not vulns:
        print("osv-check: no known vulnerabilities")

    if out_path:
        out_path.write_text(json.dumps({
            "maven_checked": len(maven), "swift_checked": len(swift), "vulnerabilities": vulns,
        }, indent=2))
    return 1 if vulns else 0


if __name__ == "__main__":
    sys.exit(main())
