# Validation and limits

All committed tests use invented evidence, local temporary files/databases, mocked OS adapters or loopback sockets. No unknown real network/device is a test target. Test count is not coverage percentage, and this document makes no numerical coverage claim.

## Reproduce offline checks

From the extracted source root with Python 3.12 or 3.13:

```console
python -m unittest discover -s tests
python -m compileall -q wifiscope tests
python -m wifiscope demo --out NEW_SYNTHETIC_DIRECTORY
```

Use a fresh standard-library environment if desired; no pip step is needed:

```console
python -m venv .venv
.venv/Scripts/python -m unittest discover -s tests
.venv/Scripts/python -m wifiscope demo --out NEW_VENV_DEMO_DIRECTORY
```

On Linux replace `.venv/Scripts/python` with `.venv/bin/python`. GUI smoke tests skip if Tk/display is unavailable; this skip must be reported as a native UI gap. Controller tests still exercise worker queues, cancellation, imports, case persistence/triage overlays and default export privacy without a display. The native test constructs actual widgets, renders a demo and imported asset, selects finding details, filters findings and checks export privacy/footer reachability at 1180×730 and 900×620.

Optional existing tools: `python -m coverage run -m unittest discover -s tests`, `python -m coverage report -m`, `python -m ruff check --isolated --select E4,E7,E9,F wifiscope tests`. They are not required dependencies and CI does not install them. Keep coverage evidence separate from display/platform claims.

## Fixture coverage

- Wi-Fi parsing in English/Chinese, escaped nmcli fields, absent/invalid configuration, firewall unknown state and local command failures/timeouts.
- Explicit target validation, DNS pinning/limits, IPv4/IPv6, loopback TCP/HTTP fixtures, normal TLS verification errors, header-only policy observations, redirect refusal, rate budgets, cancellation and deadlines.
- Batch scope bounds, exact quick-plan counts including TLS, shared deadline, boundary waiting, retained partial rows, Ctrl+C cooperation and unresolved DNS accounting.
- Nmap/Greenbone supported XML, source/original/import times, entity/shape/budget rejection, imported-unverified evidence and multi-source correlation without fabricated identity matches.
- Classic PCAP/PCAPNG endian/section/options/length/limit cases, common Ethernet/VLAN/IP/ARP metadata, HTTP/DNS hints, fragmentation/unsupported gaps, aggregate caps and no payload/URI/DNS-name retention.
- Shared privacy projection, per-export identities, CSV/HTML safety, no-overwrite bundles, static HTML sections and synthetic labeling, comparison counts/assets/coverage/time retention through redaction, refusal to restore identity flags from pseudonyms.
- Local case persistence/reopen, streamed chain verification, trusted receipts, tampering/corruption, concurrent worker-owned connections, bounded history paging, persisted finding ID association, local-only notes and distinct triage overlays.
- More than 100 persisted finding states survive case reopen and CLI/GUI exports through bounded overlay pages; notes remain local. Invalid investigation coverage is rejected before model replacement, and native Tk polling recovers to display a subsequent demo after rejected input or a render failure. Comparison tests preserve each side's synthetic marker, prominently label mixed/all-synthetic evidence and use before/after counts instead of single-snapshot zeros.
- CLI subprocess demo/analyze/import/probe/audit/merge/compare/case flows, malformed/invalid arguments, stdout privacy and missing-Tk fallback; collection adapters are patched in-process for offline tests.

## Native and presentation evidence

Windows native read-only collection and the Tk 8.6 interface with synthetic evidence were exercised on 2026-10-28. Collection succeeded under Python 3.12; available outputs and permissions still depend on the actual host. Fresh-environment/coverage evidence is recorded separately from platform claims. No generated real collection evidence belongs in this repository. Native file-dialog automation was limited by the computer-use surface; import/case paths also have CLI, controller and actual-widget integration tests.

The novice guidance was independently inspected in a native Windows Tk window with synthetic evidence on 2026-10-28: concrete Chinese coverage labels, unknown unified run status, findings/next steps/glossary, outer scrolling, persistent mode/status/cancel/export, professional-to-novice state retention, literal loopback target preview without probing, and blocked start without authorization. Native resize gestures did not change that reviewer window, so minimum-size visual inspection remains unverified; actual Tk layout tests establish footer/start/mode reachability and scrolling at 1180×730 and 900×620. These are synthetic smoke/layout checks, not a novice user study. Headless explanation tests cover the shipped rule catalog, imported/unknown/partial/comparison cases and privacy; actual-button tests deliver work through the real controller queue with patched collection/probe boundaries. No unknown device was contacted.

Linux adapters are fixture-tested until native collection evidence exists. An Ubuntu job that runs only fixtures/loopback does not establish native Wi-Fi, firewall or DNS support. macOS native collection is unsupported. Headless CI cannot substitute for GUI visual review. The pinned CI workflow is configured for Windows/Ubuntu and Python 3.12/3.13; no hosted-run success is claimed until a run actually occurs.

HTML uses static inline CSS, responsive metric cards, readable finding cards, explicit source/original times and collapsible typed evidence with no scripts/external resources. Final browser visual inspection on 2026-10-28 was not completed because Work settings disabled local browser use; the restriction was not bypassed or changed. HTML structure, escaping and CSS source checks and native Tk visual inspection were completed. These checks do not establish every font/zoom/browser combination.

## Interpretation limits

An audit is bounded TCP exposure observation, not comprehensive vulnerability scanning or security assurance. Imported results need independent verification. Unknown capture scope, unsupported protocols, offload/checksum uncertainty, incomplete retests, unavailable commands and unknown original times remain gaps. Partial or differently scoped comparisons never establish removal or remediation. Hash-chain verification is local and unsigned; trusted external receipts are needed for stronger history comparisons.

## Security tool integration checks (2026-10-29)

The local audit engine, capture engine and survey engine are shipped with CLI
and dedicated Tk panels. Tests use actual buttons and the real shared Controller
queue, fake capture/collector boundaries, and real offline matching/IDW/packet
parsing. Opening/mode/tab/position actions perform no collection or catalog
loading. Capture tests cover independent authorization/raw consent, edit
invalidation, unavailable backends, unsupported filters, idle cancellation,
typed monotonic progress, stale owner delivery and preservation of current case
IDs/triage until explicit Apply. Both-mode header/footer and scroll geometry are
checked at 900×620; 1180×730 remains covered by existing workstation tests.

Survey checks include normalized transforms, sampling timestamp/unknown dBm,
reversible removal, bounded PNG/GIF preallocation (including oversized GIF
subframes), projected safe SVG, new-directory export and all three typed
extensions through cases. General engine suites cover multi-BSSID rejection,
canonical identity provenance, input limits, convex-hull/local-contributor masks
and unsupported merge contexts. Default and raw-identity exports both discard
arbitrary imported prose, floorplans/paths, local notes and packet contents.

Synthetic Tk runs showed a finite startup/native layout delay on this Windows
host, followed by regular scheduled callbacks. Timing is an environment
observation, not a cross-machine performance benchmark. Tk checks skip when a
display is unavailable; such skips do not establish native UI coverage. Heavy
maximum-grid preparation/export runs in the worker; cancellation remains
cooperative and may wait for the current bounded geometry operation. No physical
Wi-Fi capture, field heatmap validation, comprehensive vulnerability coverage,
RF planning accuracy, full DPI, user study, native Linux capture/collection, or
new browser visual verification is established by these tests. The earlier
browser restriction remains in force. Hosted CI and final cross-version/native
review require their own successful runs.

Independent native Windows review on 2026-10-29 exercised both modes and all
three tabs at 900×620: persistent entries, scrolling, visible Apply/replacement/
Cancel/export controls, unchecked independent raw-export choice, synthetic
multi-CVE audit, blocked capture start without enumerated selection, exact
capture defaults/separate raw consent, offline parsed-packet demo and synthetic
survey dots/interpolated cells/unknown mask/table. No live enumeration, sample,
probe or capture was clicked during this visual review. File dialogs, background
loading and zoom were not manually verified in that review. Native automation
occasionally timed out obtaining accessibility/frame state and recovered on a
fresh view; a persistent mainloop hang was not observed. These observations do
not establish general performance, field accuracy or novice usability.
