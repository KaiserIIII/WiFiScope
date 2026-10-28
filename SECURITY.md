# Security reporting

Do not post real network reports, captures, credentials, private addresses, case databases or local notes in public issues. Use a minimal synthetic reproduction or loopback fixture. Include the affected version/commit, command, expected behavior, observed behavior, OS/Python version and a small bounded sample with invented identifiers.

For a suspected vulnerability, use the repository's private vulnerability reporting option if enabled. If unavailable, open a public issue containing only a request for a private reporting channel; do not include exploit details or sensitive evidence until a private channel is agreed. No response-time or supported-release guarantee is made for this early project.

The tool provides observations, not a security certification. Only explicitly authorized scope may be actively checked. No unknown networks are scanned automatically. Parser bounds, identity projection, CSV/HTML safety, cancellation, case integrity and source/scope/time provenance are security-sensitive code paths.

Case history uses a local unsigned SHA256 chain. It is not tamper-proof: an attacker with database write access can recompute it. Retain a trusted external head receipt to detect intact-prefix deletion or whole-history replacement. Protect databases with OS access controls and backups; Windows ACLs are not guaranteed by the tool. Redaction reduces data but does not guarantee anonymity.
