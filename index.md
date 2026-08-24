# RiderNav security scanning

RiderNav is a closed-source motorcycle navigation app for Android and iOS. This page publishes the
results of the security scans that run on every change to its codebase, so that the claim "it has
been security tested" is checkable rather than something you are asked to take on trust.

**Honesty note.** These scans are run by RiderNav's own build pipeline against its private
repository. They are automated static analysis and dependency checks, not an independent audit or
penetration test. What this page offers is transparency: the tools, their versions, the scanned
commit, the raw counts, and the maker's triage of every accepted finding are all published on every
run. If a scan fails, the build fails, and this page does not update until it is fixed.

_Last scan: 2026-08-24 · commit `6862363ac04e` of the private repository `chris-wild/ridernav`._

## Results

| Check | Tool | Result |
|---|---|---|
| Secrets in the full git history | gitleaks (8.30.1) | **clean** — no leaks |
| Static analysis, Kotlin + Swift source | Semgrep (1.153.0, rulesets p/default + p/kotlin + p/secrets) | **clean** — no findings beyond the accepted triage below |
| Known vulnerabilities in shipped dependencies | OSV.dev query of 221 resolved Android artifacts + 13 pinned Swift packages | **clean** — no known vulnerabilities |

## What is scanned

- **Secrets:** every commit in the repository's history, on every push (gitleaks). API tokens and
  signing material live outside the repository; this check enforces that.
- **Source:** all Kotlin (shared core + Android) and Swift (iOS) source, with Semgrep's community
  security rulesets. The build fails on any new finding.
- **Dependencies:** the Android app's *resolved* release classpath (what actually ships, after
  Gradle's version resolution) and the iOS app's pinned Swift packages, checked against the
  [OSV](https://osv.dev) vulnerability database on every push and weekly, so newly published CVEs
  against unchanged code still surface.

## Binary scan of the built app (per release, not per push)

The scans above read source; [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
(v4.5.2) inspects the built binary — permissions, exported components, storage
and network flags — so it catches what the build itself introduces. Latest scan: 2026-08-24,
`app-arm64-v8a-beta.apk (minified beta build)` at commit `6862363`.

- High-severity findings: **0**
- Findings in RiderNav's own code: **0**
- Warnings: 9 (MobSF security score 62/100)

All warnings trace to third-party SDK internals (Mapbox common/maps classes and minified library code) or entropy-based false positives (localised Mapbox UI strings, hex lookup tables). The exported Android Auto service is the documented Car App Library contract. No finding is in RiderNav's own code.

## Accepted findings (maker's triage)

| Tool | Finding | Status | Why |
|---|---|---|---|
| Semgrep | `exported_activity` on `MainActivity` | Accepted | It is the launcher activity and the GPX/KML file-open target; Android requires both to be exported. It carries no privileged interface. |
| Android Lint | `ExportedService` on `RiderNavCarAppService` | Accepted | The Android Auto host binds this service; the Car App Library contract requires it exported with the `androidx.car.app.CarAppService` intent filter. |
| Android Lint | `DataExtractionRules` deprecation warning | Fixed 2026-08-24 | `allowBackup="false"` was already set; explicit `dataExtractionRules` (all backup and device-transfer excluded) added for Android 12+. |
| OSV | `com.google.guava:guava:31.1-android` (CVE-2020-8908, CVE-2023-2976) | Fixed 2026-08-24 | Transitive via `androidx.car.app:1.7.0`; constrained to `32.0.1-android`, where both are fixed. |
| Semgrep | `dynamic-urllib-use-detected` in `scripts/security/osv_check.py` | Accepted (inline `nosemgrep`) | The flagged call fetches the literal `https://api.osv.dev` endpoint declared two lines above; no dynamic scheme can reach it. This is scan tooling, not app code. |
| MobSF | 9 warnings on the beta APK (hardcoded strings, insecure RNG, raw SQL, external storage, unprotected AndroidX components) | Accepted | Every flagged file is third-party SDK code (Mapbox `com.mapbox.common`/`com.mapbox.maps` classes and minified library classes), or the Android Auto service covered above. The "hardcoded secrets" list is entropy false positives: localised Mapbox UI strings and hex lookup tables. Zero findings are in RiderNav's own code. |
| MobSF | The Mapbox public access token ships in the app | Accepted by design | Mapbox client apps authenticate with a public (`pk.`) token that is intended to be embedded; the account's secret (`sk.`) token is not in the app or the repository, which the secrets scan enforces. |

## Data handling

RiderNav's app data (imported routes, settings, downloaded offline maps) stays on the device.
Backup extraction and device-to-device transfer are disabled at the platform level
(`allowBackup="false"` plus explicit Android 12+ `dataExtractionRules` excluding everything).
Mapbox telemetry is disabled in the app.

---
_This page is generated by the scan pipeline itself
([`render_report.py`](https://github.com/chris-wild/ridernav-security)); the only hand-written
content is the triage table, which is labelled as such._
