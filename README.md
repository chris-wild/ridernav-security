# RiderNav security scanning

The published results live at **https://chris-wild.github.io/ridernav-security/** (rendered from
[index.md](index.md)).

RiderNav's application source is private. This repository exists so that the security scanning of
that source is public: every push to the app repository runs the scans, and the pipeline publishes
the page here with the scanned commit, tool versions, raw counts and the maker's triage of every
accepted finding.

For methodology transparency the scanning scripts themselves are mirrored here:

- [osv_check.py](osv_check.py) — dependency vulnerability check (resolved Android release classpath
  plus pinned Swift packages) against [OSV.dev](https://osv.dev).
- [render_report.py](render_report.py) — renders the published page from the raw tool outputs.
- [triage.md](triage.md) — the hand-curated acceptance table, embedded into the page verbatim.

These scans are automated static analysis, run by the app's own build pipeline. They are not an
independent audit; the page says so prominently.
