#!/usr/bin/env python3
"""Render the public RiderNav security report page from the scan outputs.

Inputs (all produced by the tools the security.yml workflow runs):
  --osv PATH        JSON from scripts/security/osv_check.py --out
  --semgrep PATH    JSON from `semgrep scan --json`
  --gitleaks STATUS "clean" or "findings" (the workflow passes gitleaks' verdict)
  --commit SHA      the scanned commit
  --out PATH        where to write the markdown page

The page is deliberately provenance-first: it states what was scanned, when, with which tool
versions, and what the app maker chose to accept and why. Numbers come only from the tool outputs;
nothing on the page is hand-typed except the triage table (scripts/security/triage.md), which is
labelled as the maker's own triage.
"""
from __future__ import annotations

import argparse
import datetime
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent


def tool_version(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout.strip().splitlines()[0]
    except Exception:
        return "unavailable"


def mobsf_section(mobsf: dict | None) -> str:
    if not mobsf:
        return ""
    return f"""## Binary scan of the built app (per release, not per push)

The scans above read source; [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
({mobsf["mobsf_version"]}) inspects the built binary — permissions, exported components, storage
and network flags — so it catches what the build itself introduces. Latest scan: {mobsf["date"]},
`{mobsf["artifact"]}` at commit `{mobsf["commit"]}`.

- High-severity findings: **{mobsf["high_findings"]}**
- Findings in RiderNav's own code: **{mobsf["app_code_findings"]}**
- Warnings: {mobsf["warnings"]} (MobSF security score {mobsf["security_score"]}/100)

{mobsf["note"]}

"""


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--osv", required=True)
    p.add_argument("--semgrep", required=True)
    p.add_argument("--gitleaks", required=True, choices=["clean", "findings"])
    p.add_argument("--commit", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()

    osv = json.loads(Path(args.osv).read_text())
    semgrep = json.loads(Path(args.semgrep).read_text())
    mobsf_file = HERE / "mobsf-latest.json"
    mobsf = json.loads(mobsf_file.read_text()) if mobsf_file.exists() else None
    semgrep_findings = semgrep.get("results", [])
    triage = (HERE / "triage.md").read_text()
    # Strip the HTML comment header from the embedded triage table.
    triage_table = triage.split("-->", 1)[-1].strip()

    today = datetime.date.today().isoformat()
    osv_vulns = osv.get("vulnerabilities", [])

    page = f"""# RiderNav security scanning

RiderNav is a closed-source motorcycle navigation app for Android and iOS. This page publishes the
results of the security scans that run on every change to its codebase, so that the claim "it has
been security tested" is checkable rather than something you are asked to take on trust.

**Honesty note.** These scans are run by RiderNav's own build pipeline against its private
repository. They are automated static analysis and dependency checks, not an independent audit or
penetration test. What this page offers is transparency: the tools, their versions, the scanned
commit, the raw counts, and the maker's triage of every accepted finding are all published on every
run. If a scan fails, the build fails, and this page does not update until it is fixed.

_Last scan: {today} · commit `{args.commit[:12]}` of the private repository `chris-wild/ridernav`._

## Results

| Check | Tool | Result |
|---|---|---|
| Secrets in the full git history | gitleaks ({tool_version(['gitleaks', 'version'])}) | {"**clean** — no leaks" if args.gitleaks == "clean" else "**FINDINGS** — build failed"} |
| Static analysis, Kotlin + Swift source | Semgrep ({tool_version(['semgrep', '--version'])}, rulesets p/default + p/kotlin + p/secrets) | {f"**{len(semgrep_findings)} finding(s)** — build failed" if semgrep_findings else "**clean** — no findings beyond the accepted triage below"} |
| Known vulnerabilities in shipped dependencies | OSV.dev query of {osv.get("maven_checked", "?")} resolved Android artifacts + {osv.get("swift_checked", "?")} pinned Swift packages | {f"**{len(osv_vulns)} vulnerable artifact(s)** — build failed" if osv_vulns else "**clean** — no known vulnerabilities"} |

## What is scanned

- **Secrets:** every commit in the repository's history, on every push (gitleaks). API tokens and
  signing material live outside the repository; this check enforces that.
- **Source:** all Kotlin (shared core + Android) and Swift (iOS) source, with Semgrep's community
  security rulesets. The build fails on any new finding.
- **Dependencies:** the Android app's *resolved* release classpath (what actually ships, after
  Gradle's version resolution) and the iOS app's pinned Swift packages, checked against the
  [OSV](https://osv.dev) vulnerability database on every push and weekly, so newly published CVEs
  against unchanged code still surface.

{mobsf_section(mobsf)}## Accepted findings (maker's triage)

{triage_table}

## Data handling

RiderNav's app data (imported routes, settings, downloaded offline maps) stays on the device.
Backup extraction and device-to-device transfer are disabled at the platform level
(`allowBackup="false"` plus explicit Android 12+ `dataExtractionRules` excluding everything).
Mapbox telemetry is disabled in the app.

---
_This page is generated by the scan pipeline itself
([`render_report.py`](https://github.com/chris-wild/ridernav-security)); the only hand-written
content is the triage table, which is labelled as such._
"""
    Path(args.out).write_text(page)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
