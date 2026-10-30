# WiFiScope

A local security evidence workstation using only the Python standard library. It combines Wi-Fi/local configuration, authorized TCP/TLS/HTTP checks, scanner reports, local CVE candidate audits, bounded live capture and sampled signal surveys. The Chinese Tk interface and CLI share typed evidence. Exports redact identities by default; case history stays local.

[中文](README.md) · [Comparison with established tools](docs/competitive-landscape.md) · [Validation](docs/validation.md) · [Methodology](docs/audit-methodology.md) · [Dependency audit](docs/dependencies.md)

## Run from source or ZIP

Use Python 3.12 or 3.13. Extract the source ZIP and open a terminal in the directory containing `wifiscope`. No pip, account, server, or dependency installation is required.

```console
python -m wifiscope
python -m wifiscope --help
python -m wifiscope demo --out demo-report
```

Windows: double-click `run-wifiscope.cmd`. Linux/macOS: `./run-wifiscope.sh`. The CLI works without a display or Tk. The Windows python.org installer normally provides Tk; Linux distributions may package it separately. WiFiScope never installs it automatically. Native macOS collection is unsupported; offline evidence and demo still work.

The demo contains invented synthetic evidence, never live measurements: WPA2/open networks, candidate assets, imported findings, a normally verified TLS 1.3 certificate with 14 days remaining, a separate certificate-verification error, and a hand-built HTTP capture processed by the real parser. Demo dates, addresses and findings are examples only.

## Three steps for beginners

1. The app opens in Chinese novice guidance (`新手引导`). Try the offline demo, inspect this computer's read-only configuration, or import an existing evidence file. Launching or changing modes starts no collection.
2. Read coverage, unknowns and run status before the three suggested next actions. For an explicit device, enter one hostname/IP and optionally a URL on that host. Preview the default ports 80/443, any URL endpoint, TLS/HEAD connection counts and rate-limit duration; then check authorization beside the start button. Cancel stays in the footer.
3. Export a default-redacted JSON/CSV/HTML bundle using the footer. Switch to `专业工作台` for all tables, custom scopes/ports, cases, triage and comparisons; the same report and case remain associated.

See [guidance, glossary and privacy choices](docs/usability.md). Main-window raw report export and raw case retention are separate professional opt-ins. Main novice export always redacts. The dedicated tools below have their own explicit export privacy choice in either mode.

## Four security tools

The persistent header opens **漏洞库与资产清单** (indexed catalog/inventory), **漏洞审计** (small-pack evidence audit), **实时抓包** (live capture), and **Wi-Fi 热力图** (survey) in both modes. Panels scroll; Apply, Cancel and Export remain in the footer. Opening, changing modes or clicking a survey position starts no collection. Each explicit offline demo runs real local engines on prominently labeled synthetic evidence.

- Indexed catalog: explicitly build a new SQLite file from 1..64 local NVD feeds or open an existing one, browse 20 rows per page, select a typed detail's literal CPE or CNA identity and enter your own asset label/version. No JSON/CPE authoring is required for the form. Alternatively import native schema1, CycloneDX JSON 1.6/1.7, SPDX JSON SPDX-2.3 with explicit CPE 2.3, or explicitly select `nmap` for local XML CPE assertions using the finite URI/formatted profile. Source documents are ≤16 MiB; inventories ≤1024 assets/8192 components. Inspect per-host addresses, service/OS hypotheses and source times; choose a component's analysis ordering deliberately (default `unknown`, never a discovered fact). Run an explicit preview, then Apply/export deliberately. Existing demos remain; the additional Nmap walkthrough is synthetic, with two invented hosts, a probed service and alternative OS hypotheses. See [formats, privacy, bounds and measured catalog capacity](docs/catalogs.md).

```console
python -m wifiscope catalog audit --db LOCAL.db --inventory scan.xml --inventory-format nmap --out NEW_NMAP_REPORT
```

This reads an existing local file and never runs Nmap. Default exports use shared HMAC pseudonyms; `--include-identifiers` is an explicit raw export choice. Historical indexing acceptance at source `d676fdd` / public `54112f97` stored 416321 records from 25 annual feeds; indexing is separate from inventory assessability. Source-error/missing-completion and work-limit reports remain partial, with unknown unexamined counts where appropriate. Installation, exploitability and complete annual inventory coverage are unproved.

- Audit existing evidence with the reviewed six-CVE subset or a selected local native/NVD2 catalog and optional SHA256. Results include catalog version/hash/review/source, candidate version ranges, confidence, existing configuration rules and unknown service counts. Check distribution backports and applicability; no match does not establish security.
- Enumerate and explicitly select one capture interface. Review the default 10 seconds/2,000 packets/8 MiB/96 bytes/non-promiscuous plan, then check adjacent authorization. Edits clear authorization. Larger snapshots or raw files need separate consent because prefixes/full packets may contain private application data. Raw paths must be new; ordinary reports contain metadata only. Windows requires installed Npcap and permissions; Linux requires installed libpcap or AF_PACKET permissions. Nothing is installed automatically.
- Select SSID/BSSID (prefer BSSID) and percent/measured dBm, create a project, click a blank or local PNG/GIF canvas, then explicitly sample once. The background is local only: ≤8 MiB, ≤8192 per axis, ≤32 million pixels. Resize/zoom/pan preserve normalized coordinates. Unknown stays unknown; IDW estimates require three non-collinear locations and three local contributors within the supported hull/radius. Open/save local projects, import CSV, undo point removal, and export a safe standalone SVG.

Tool results remain separate previews, preserving the current report, case IDs and triage. Save the case first if needed, check the adjacent replacement choice, then Apply. Incompatible contexts are never silently merged. Tool export is available in both modes, defaults to HMAC and has its own unchecked raw-identity option, independent of the main window and case retention. Neither identity opt-in exports backgrounds/paths, packet files/paths, payloads, local notes or arbitrary imported prose.

Synthetic surveys cannot be saved as native projects because that format omits the synthetic marker; use tool report export to preserve it. Ordinary projects still support exclusive save/open. Successful JSON/CSV/demo project replacement clears the previous project's undo history.

```console
python -m wifiscope vuln --input REPORT.json --out NEW_VULN_REPORT
python -m wifiscope vuln --input REPORT.json --catalog PACK.json --catalog-format native --catalog-sha256 EXPECTED_SHA256 --out NEW_CATALOG_REPORT
python -m wifiscope vuln --input REPORT.json --catalog NVD.json --catalog-format nvd2
python -m wifiscope capture --list-interfaces
python -m wifiscope capture --interface "EXACT_LISTED_INTERFACE" --duration 10 --max-packets 2000 --max-bytes 8388608 --snaplen 96 --authorized --out NEW_CAPTURE_REPORT
python -m wifiscope capture --interface "EXACT_LISTED_INTERFACE" --filter "tcp port 443" --authorized --out NEW_FILTERED_REPORT
python -m wifiscope capture --interface "EXACT_LISTED_INTERFACE" --snaplen 65535 --retain-packets --raw-out NEW_CAPTURE.pcap --authorized --out NEW_RAW_METADATA_REPORT
python -m wifiscope survey --input samples.csv --format csv --grid-size 40 --radius .35 --power 2 --out NEW_SURVEY_REPORT
python -m wifiscope survey --input project.json --format json --include-identifiers --out NEW_EXPLICIT_ID_REPORT
```

Replace the interface placeholder with an explicitly enumerated authorized interface. See [audit engine](docs/vulnerability-engine.md), [capture prerequisites/limits](docs/live-capture.md), and [survey formats](docs/wifi-survey.md). Import CSV uses `x,y,value,observed_at,ssid,bssid,metric`; blank values are unknown. Flattened report CSV is a different format.

## Workstation workflow

1. Switch to the professional workstation, then choose offline demo, local collection, or Open evidence (Ctrl+O). Explicitly select nmap, greenbone, pcap, pcapng, netsh, nmcli, or WiFiScope JSON. XML dialects are never silently guessed.
2. Import explicitly replaces the current snapshot by default. The merge-current option correlates raw evidence already in memory. Independently pseudonymized exports cannot be reliably merged. Original observation times and import times are distinct; missing times remain unknown.
3. Read run status, planned/actual connections, remaining endpoints and coverage gaps before interpreting finding counts. Search findings by title/rule, filter severity, and select a row for confidence, detection status, structured evidence, remediation and retest details.
4. Save snapshot writes a local SQLite case and reloads its actual persisted IDs before enabling triage. Case history is paginated in groups of 100. Its raw-identity retention checkbox affects subsequent case saves only.
5. Triage records open, investigating, accepted-risk or resolved plus a local note. Workflow `triage_status` never overwrites detection `status`. Notes are excluded from ordinary reports. Partial retests cannot automatically establish remediation.
6. Verify case optionally accepts a trusted SHA256 head saved independently. Verification runs in a worker and displays the receipt in the status bar. A recomputable local chain alone cannot detect an intact-prefix deletion or complete history replacement.
7. Compare uses persisted database snapshot IDs when a case is open; otherwise select two JSON files. Identity correlation requires both snapshots to retain original identifiers. Otherwise comparison is counts/times/coverage only with an actionable explanation. Missing assets are not-observed, never automatically removed or resolved.
8. Export (Ctrl+E) writes JSON, CSV and self-contained static HTML into a new directory. The raw-export checkbox is separate from raw case retention. Tables scroll and the window resizes.

Scope, ports and an explicit authorization checkbox sit beside Run/Quick Audit. The quick profile visibly lists `22,80,443,445,3389,5900,8080,8443`; edit it to narrow the plan. Scope is never inferred from local interfaces. Only check explicit targets you are authorized to investigate.

## CLI examples

Output directories must not already exist. Evidence/SBOM inputs have a 16 MiB bound; indexed feed builds have separate source/expanded limits documented in [catalogs](docs/catalogs.md). JSON stdout is also an export and uses the same default privacy projection.

```console
python -m wifiscope collect --out local-report
python -m wifiscope analyze --input wifi.txt --format netsh --out wifi-report
python -m wifiscope analyze --input wifi-linux.txt --format nmcli
python -m wifiscope import-scan --format nmap --input scan.xml --out scan-report
python -m wifiscope import-scan --format greenbone --input gmp.xml --out greenbone-report
python -m wifiscope packets --input capture.pcapng --out packet-report
python -m wifiscope probe --host 127.0.0.1 --port 8080 --attempts 1 --timeout 0.5 --authorized --out loopback-report
python -m wifiscope audit --scope 127.0.0.1 --port 8080 --deadline 300 --authorized --out audit-report
python -m wifiscope compare before.json after.json --out comparison-report
python -m wifiscope merge --input raw-local.json --input raw-scanner.json --out combined-report
```

`probe` accepts repeated `--host`, `--port`, and `--url` for authorized HTTP/HTTPS HEAD checks. Limits: 4 hosts, 8 ports, 5 TCP attempts per endpoint, 2 addresses per family, 128 total connection attempts, timeout 0.2–5 seconds. DNS is resolved once and addresses are pinned. TLS uses normal certificate verification. No downgrade, redirects, response bodies or cookie values are retained. Port 443 adds a TLS diagnostic; explicit URLs add HEAD connections. TCP connection timing/failure rate is neither throughput nor network packet-loss measurement.

`audit` accepts repeated explicit `--scope IP_OR_CIDR`, at most 64 unique IPs, and repeated optional `--port`. The default is the quick profile above. Batches contain at most 4 hosts, with one TCP attempt per endpoint, default timeout 0.5 seconds and default/maximum total deadline 300 seconds. Connections are limited to 4/second; a cancellation-aware boundary wait of at least 0.25 seconds separates batches that run. A full 64-host quick plan has 512 TCP plus up to 64 TLS connections, an approximate rate-based planning estimate of 144 seconds at 4/second (the first connection can start immediately, so actual duration may be shorter or longer). The deadline does not guarantee completion. Planning is printed to stderr before work. Ctrl+C/cancellation and deadline retain observations, run status and unattempted scope; local collection is not repeated per batch. A DNS error is attempted-but-unresolved, never successful evaluation.

Exit codes: 0 command completed (including refused connections or observed risks); 1 partial/deadline audit or failed case integrity; 2 argument/input/permission/output error; 130 cancellation. Finding count alone does not make a command fail.

## Cases and persisted IDs

```console
python -m wifiscope case add --db investigation.db --input demo-report/report.json
python -m wifiscope case list --db investigation.db --limit 100 --offset 0
python -m wifiscope case show --db investigation.db --snapshot 1 --include-identifiers
python -m wifiscope case triage --db investigation.db --snapshot 1 --finding PERSISTED_FINDING_ID --status investigating --note "Local review"
python -m wifiscope case show --db investigation.db --snapshot 1
python -m wifiscope case verify --db investigation.db
python -m wifiscope case verify --db investigation.db --expected-head TRUSTED_SHA256_HEAD
python -m wifiscope case compare --db investigation.db 1 2 --out case-comparison
```

Replace `PERSISTED_FINDING_ID` with an `investigation.findings[].id` from the preceding explicit `case show --include-identifiers`. That flag exposes the exact stored ID; with default case retention it is still a pseudonym. Ordinary show re-pseudonymizes IDs, so those new export IDs cannot triage stored findings. PowerShell can select the persisted ID directly:

```powershell
$caseView = python -m wifiscope case show --db investigation.db --snapshot 1 --include-identifiers | ConvertFrom-Json
$caseFinding = $caseView.investigation.findings[0].id
python -m wifiscope case triage --db investigation.db --snapshot 1 --finding $caseFinding --status investigating
```

Identity comparison requires opting into identifiers at initial export and again when adding that raw report to a case. These are separate decisions. Already redacted input cannot recover original identities: re-exporting or saving it with the flag still reports `identifiers_included=false`, comparisons remain counts-only, and merge refuses it. Case load/show/export preserves its existing assets, findings and coverage instead of rebuilding IP correlations from pseudonyms.

## Capabilities and limits

- Windows read-only adapters use netsh Wi-Fi and PowerShell interfaces/default routes/firewall. OS permission/location privacy restrictions become gaps; the tool never elevates itself. Enable the relevant OS location/wireless permissions and retry, or import netsh output offline.
- Linux adapters use cached nmcli Wi-Fi and `ip -j` addresses/IPv4+IPv6 default routes; DNS configuration and firewall are currently unavailable. Linux adapters are fixture-tested until native evidence exists; offline Linux CI alone does not validate live collection. Missing commands/timeouts become gaps.
- Nmap XML and Greenbone GMP XML are imported scanner evidence; WiFiScope does not launch scanners. Service versions, CVEs and scores remain imported-unverified. There is no comprehensive built-in CVE database, exploitation or credential audit.
- PCAP/PCAPNG provides bounded offline metadata analysis; live capture has a separate explicit interface/limits/authorization flow. Common Ethernet/VLAN/IP/ARP, TCP/UDP, HTTP request hints, DNS query/NXDOMAIN and ARP hints are supported. Reports do not retain payloads, URIs, DNS names or credentials. No full DPI/reassembly, IDS or complete Wireshark decoder is provided. ARP conflicts may reflect HA, proxy ARP or address reuse.
- Wi-Fi signal is an observation; channel distribution is not measured interference. No deauthentication, key retrieval or cracking. Proxy presence is context only.
- Default exports use a fresh HMAC context per export and allowlisted typed measurements; HTML is escaped, CSV formula prefixes are neutralized, and HTML has no external resources. Pseudonymization minimizes data but cannot guarantee anonymity: timing, topology and services can still identify environments. Original input files are not erased.
- Local SQLite snapshots are immutable and events append-only through this API. The unsigned hash chain is recomputable by someone who can rewrite the database; Windows ACL guarantees are absent. Protect cases/raw reports and keep trusted receipts independently.
- Cancellation is cooperative. Network waits poll it; local OS commands, offline parsing and atomic case writes may finish their current bounded operation first. Status distinguishes running, cancelled, partial, deadline and complete. Cancellation does not undo completed writes.

A clean report does not establish security. Use independently verified retests of equivalent authorized scope, configuration review and specialist tools. [Security reporting](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)
