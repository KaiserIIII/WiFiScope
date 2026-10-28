# Contributing

Use Python 3.12 or 3.13 and the standard library. Runtime and tests require no third-party packages. Keep contributions independent of private projects, identifiers, field data and source history. Do not add real captures, generated local reports, case databases, secrets or binaries.

Write a failing regression before a behavior fix. Use invented fixtures and loopback only. Tests must never contact unknown networks/devices, launch external scanners, or install packages. Keep unknown evidence unknown, preserve partial coverage and source/original-time provenance, and separate detection status from local triage.

```console
python -m unittest discover -s tests
python -m compileall -q wifiscope tests
python -m wifiscope demo --out NEW_SYNTHETIC_DIRECTORY
git diff --check
```

If Ruff or coverage is already available, optional checks are `python -m ruff check --isolated --select E4,E7,E9,F wifiscope tests` and `python -m coverage run -m unittest discover -s tests`. Do not install them just to run the core project. Report native-display skips separately. Review the GUI at default/minimum sizes and the self-contained HTML using synthetic data before changing presentation.

Use worker-owned CaseStore connections, queue delivery to the Tk main thread, bounded input reads, and the shared privacy projection. Ordinary workstation exports must not include local notes or untrusted finding prose, even when raw identity export is selected. Preserve exclusive new-directory bundle creation and HTML/CSV safety.

Changes to external dependencies or CI actions require review, a full pinned commit and an entry in `docs/dependencies.md` with source, license, commit and date. No automatic cloning, recursive skill installation or dependency updates. Before publication, request a whole-tree code/security review and remove private work notes and generated evidence from the public source tree.
