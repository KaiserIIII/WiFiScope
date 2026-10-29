# Network audit scope and tool comparison

Official product/documentation review: 2026-10-29. These are complementary tools; this document does not claim that WiFiScope replaces their mature engines or is the most comprehensive product on the market.

| Reference | Established strength | Design implication for WiFiScope |
| --- | --- | --- |
| [Nmap XML output](https://nmap.org/book/output-formats-xml-output.html) | Host/service discovery; XML distinguishes port-table guesses from probed service identification and carries confidence | Import assets with their source and confidence; an open port is an exposure observation, not a confirmed vulnerability |
| [Wireshark introduction](https://www.wireshark.org/docs/wsug_html_chunked/ChapterIntroduction.html) | Native capture, filtering, detailed packet dissectors and analysis | Provide bounded metadata capture while keeping Wireshark as the deep protocol workbench |
| [Greenbone reporting and detection quality](https://docs.greenbone.net/GSM-Manual/gos-24.10/en/reports.html) | Report history, vulnerability management, CVSS and Quality of Detection | Import scanner claims with their original score/QoD and separate assertions from measured evidence |
| [NetSpot Inspector](https://www.netspotapp.com/features.html) | Wi-Fi AP properties, signal/channel observations, site surveys and heatmaps | Make Wi-Fi posture understandable alongside network assets; channel counts must not be presented as RF interference or a measured heatmap |
| [Fing capabilities](https://www.fing.com/faq/) | Device discovery, monitoring, security checks and troubleshooting | Provide assets, changes and next steps together while exposing gaps in device identification |
| [PingPlotter measurements](https://www.pingplotter.com/manual/displayoptions/) | Time-series latency, packet-loss and jitter presentation | Keep timing metrics explicit: TCP connection failures are not ICMP packet loss; connection-time variation is not application throughput |

## Product focus

WiFiScope is designed as a local network security investigation workspace: gather observations, link each risk to evidence, record confidence and missing checks, prioritize remediation, compare later observations, and share a privacy-preserving report. This is a product focus, not a verified claim that no other tool offers these capabilities.

Built-in collectors and bounded probes provide a dependency-free starting point. Existing scan and packet-capture files extend the investigation without redistributing or automatically installing other vendors' tools. No CVE claim is generated from a port number or an unverified version string. A scan with no findings still carries the checks and evidence gaps needed to judge its coverage.

Implementation status and exact supported formats are maintained in the main README and validation document. Unsupported capabilities are documented explicitly; a roadmap item is not a shipped feature.

## Shipped capability matrix

| Area | Shipped built-in measurement / presentation | Imported evidence | Unsupported |
| --- | --- | --- | --- |
| Beginner guidance | Chinese task entry, controlled explanations, coverage first, three next steps, default minimized export | Explicit format and replace/merge choice; scanner claims remain unverified | Automated diagnosis or assurance that a network is safe; proven novice usability study |
| Local Wi-Fi / host | Read-only Windows/Linux configuration; Windows firewall observations; adapter/permission gaps | netsh / nmcli Wi-Fi text; WiFiScope JSON | Native macOS collection; Linux native evidence on this host; RF interference measurement |
| Explicit connectivity | Authorized bounded DNS/TCP/TLS/HEAD, normal certificate verification, cooperative cancel; novice default ports 80/443 | Typed scan endpoints with source/time kept distinct from measurement | Inferred subnet scanning, throughput testing, ICMP packet-loss measurement, automatic target expansion |
| Vulnerability audit / external scanners | Built-in six-CVE reviewed subset, explicit aliases/ranges, config rules, catalog provenance and unknowns; CLI and both-mode desktop panel | Bounded native/NVD2 catalog; Nmap/Greenbone evidence, CVSS/QoD where supplied | Complete CVE coverage, authenticated checks, exploit verification; unknown suffixes/prerequisites remain gaps |
| Packets | Built-in read-only live metadata capture and both-mode panel; explicit interface/limits/authorization, cancellation and progress; Windows installed Npcap/permissions or Linux installed libpcap/AF_PACKET privileges required | Supported pcap / pcapng link types within parser limits | Full DPI, payload/TCP reassembly, complete Wireshark dissectors; native Linux capture evidence on this Windows host |
| Wi-Fi survey | Built-in normalized samples, actual local collector action, masked IDW and standalone safe SVG; both-mode canvas/optional bounded local PNG/GIF; collector availability required for live sampling | Validated local JSON projects/CSV; measured and imported labels separate | RF planning, wall/propagation modeling, interference/throughput inference, field-validated accuracy |
| Cases / retests | Local SQLite snapshots, separate triage, integrity receipt, count or retained-identity comparison | WiFiScope snapshots, explicit source merge | Automatic proof of remediation or reliable cross-export pseudonym identity |

Surpassing existing tools is an ambition, not an established product fact. No benchmark here establishes universal superiority, complete coverage, or the easiest experience.

[Nmap NSE](https://nmap.org/book/nse.html) supports discovery, service/version and
vulnerability scripting; this project does not reproduce that script ecosystem.
[NetSpot](https://www.netspotapp.com/features.html) includes AP inspection,
multiple heatmap types and floor/planning workflows; WiFiScope's IDW interpolator
is a limited signal visualization, not RF planning or interference measurement.
The product emphasis is inspectable evidence provenance, controlled unknowns,
novice/professional access and privacy-preserving cases. No quantitative result
establishes superiority over these products, and no novice user study is claimed.
