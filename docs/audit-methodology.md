# Evidence-led network security investigation

WiFiScope keeps the observed fact, interpretation and next action separate. A useful security report explains how its conclusion could be checked again.

| Layer | Example | Required context |
| --- | --- | --- |
| Observation | A TCP connection to an address and port succeeded | Target, family, port, method, time and scope |
| Interpretation | The endpoint may expose a remote administration service | Identification confidence, source and alternative explanations |
| Finding | Exposure should be reviewed against the intended access policy | Severity, confidence, status, evidence, recommendation and retest |
| Follow-up | Restrict access, then repeat the same scoped measurement | Comparable scope, completed checks and remaining gaps |

## Reading findings

Severity describes potential consequence. Confidence describes how strongly the available evidence supports the interpretation. These are separate fields. A high-impact imported scanner result can still be unverified by this application. A reliably observed open port does not establish vulnerable software, missing authentication or exploitability.

Findings retain their source. Scan import time is separate from the original measurement time, which can be unknown. Correlation by IP address, family, port and protocol is useful for investigation but does not establish permanent physical device identity. DHCP changes, NAT, proxies, virtual IPs and load balancing can change what an address represents.

## Coverage and retesting

A report with no findings does not establish a secure network. Read its planned, attempted, evaluated and unattempted scope, source age, partial-run status and evidence gaps first. Missing IPv6 answers do not prove IPv6 policy enforcement. A connection timeout does not establish filtering. An HTTP redirect does not establish a captive portal.

Compare like scope with like scope. An incomplete retest cannot automatically prove that an old exposure disappeared or was remediated. A different scan profile may simply omit the original check. Keep the original finding available until its specific condition has been checked again.

Wi-Fi observations also need context. Several BSSIDs under one SSID are normal in many managed networks. Different advertised security under the same name deserves verification; it does not prove an evil twin. Weak signal is a measurement observation rather than proof of interference or poor throughput. ARP binding changes can involve legitimate failover or proxy behavior.

## Sharing evidence

Ordinary exports minimize data and pseudonymize supported identity fields. The same bundle preserves joins between its tables; separate default exports use independent contexts. They therefore cannot support reliable identity-level change detection. Measurements, timing and configuration can still reveal context, so pseudonymization does not guarantee anonymity.

Case retention and report sharing are separate choices. Keeping identifiers in a local case enables more useful correlation; it does not grant permission to disclose them in a later export. Local investigation notes stay local.

Case event hashes can reveal changes relative to an intact history or a trusted external head receipt. A locally recomputable hash chain is not a digital signature and cannot independently prove authorship or prevent wholesale replacement. Preserve a trusted receipt when independent integrity checking is needed.

## Measurement boundaries

Built-in connection timing measures TCP connection establishment. Its failure percentage and successive timing variation are not ICMP packet loss, application throughput or proof of an ISP fault. Selected HTTP checks are conservative configuration observations rather than a browser-equivalent policy analysis. Offline packet metadata is not a substitute for full protocol dissection, traffic decryption or exploit validation.

The exact implemented checks, supported input formats and validation limits are listed in the README and validation document. The [tool comparison](competitive-landscape.md) explains how external scanners and packet tools fit this workflow.
