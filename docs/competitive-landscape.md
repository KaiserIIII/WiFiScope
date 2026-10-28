# Network audit scope and tool comparison

Official product/documentation review: 2026-10-28. These are complementary tools; this document does not claim that WiFiScope replaces their mature engines or is the most comprehensive product on the market.

| Reference | Established strength | Design implication for WiFiScope |
| --- | --- | --- |
| [Nmap XML output](https://nmap.org/book/output-formats-xml-output.html) | Host/service discovery; XML distinguishes port-table guesses from probed service identification and carries confidence | Import assets with their source and confidence; an open port is an exposure observation, not a confirmed vulnerability |
| [Wireshark expert information](https://www.wireshark.org/docs/wsug_html/) | Packet dissection, conversations, protocol statistics and context-dependent expert observations | Offer bounded offline packet metadata analysis and keep packet interpretation limitations visible; retain the original tool as the deep protocol workbench |
| [Greenbone reporting and detection quality](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html) | Vulnerability management, CVSS and Quality of Detection | Import scanner claims with their original score/QoD and clearly separate imported assertions from directly measured evidence |
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
| Local Wi-Fi / host | Read-only Windows/Linux configuration and firewall observations | netsh / nmcli Wi-Fi text; WiFiScope JSON | Native macOS collection; RF heatmaps, site surveys or interference measurement |
| Explicit connectivity | Authorized bounded DNS/TCP/TLS/HEAD, normal certificate verification, cooperative cancel; novice default ports 80/443 | Typed scan endpoints with source/time kept distinct from measurement | Inferred subnet scanning, throughput testing, ICMP packet-loss measurement, automatic target expansion |
| External scanners | Conservative exposure rules and independent-verification guidance | Supported Nmap XML and Greenbone XML profiles, CVSS/QoD where supplied | Built-in CVE engine, exploit verification, complete CVE coverage |
| Packets | Bounded offline metadata and conservative observations | Supported pcap / pcapng link types within parser limits | Live capture, full DPI, payload/TCP reassembly, complete Wireshark dissectors |
| Cases / retests | Local SQLite snapshots, separate triage, integrity receipt, count or retained-identity comparison | WiFiScope snapshots, explicit source merge | Automatic proof of remediation or reliable cross-export pseudonym identity |

Surpassing existing tools is an ambition, not an established product fact. No benchmark here establishes universal superiority, complete coverage, or the easiest experience.
