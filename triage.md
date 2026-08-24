<!-- Hand-curated triage of accepted findings, embedded verbatim into the published security report
     by render_report.py. Every accepted finding needs: the tool, the finding, why it is accepted.
     Anything NOT listed here that a tool reports is a failure of the CI gate, not an acceptance. -->

| Tool | Finding | Status | Why |
|---|---|---|---|
| Semgrep | `exported_activity` on `MainActivity` | Accepted | It is the launcher activity and the GPX/KML file-open target; Android requires both to be exported. It carries no privileged interface. |
| Android Lint | `ExportedService` on `RiderNavCarAppService` | Accepted | The Android Auto host binds this service; the Car App Library contract requires it exported with the `androidx.car.app.CarAppService` intent filter. |
| Android Lint | `DataExtractionRules` deprecation warning | Fixed 2026-08-24 | `allowBackup="false"` was already set; explicit `dataExtractionRules` (all backup and device-transfer excluded) added for Android 12+. |
| OSV | `com.google.guava:guava:31.1-android` (CVE-2020-8908, CVE-2023-2976) | Fixed 2026-08-24 | Transitive via `androidx.car.app:1.7.0`; constrained to `32.0.1-android`, where both are fixed. |
| Semgrep | `dynamic-urllib-use-detected` in `scripts/security/osv_check.py` | Accepted (inline `nosemgrep`) | The flagged call fetches the literal `https://api.osv.dev` endpoint declared two lines above; no dynamic scheme can reach it. This is scan tooling, not app code. |
