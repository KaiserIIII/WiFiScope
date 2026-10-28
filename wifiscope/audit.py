"""Conservative posture observations, never an assurance of security."""
import re

from .wifi import _security_value


def assess(report: dict) -> list[dict]:
    findings = []

    def add(code, severity, title, evidence, recommendation):
        findings.append(dict(code=code, severity=severity, title=title,
                             evidence=evidence, recommendation=recommendation))

    wifi = report.get('wifi') or []
    groups = {}
    if not wifi:
        add('wifi-unavailable', 'info', 'Wi-Fi evidence unavailable', {},
            'Collect Wi-Fi observations before assessing wireless posture.')
    for row in wifi:
        evidence = {key: row.get(key) for key in ('ssid', 'bssid', 'authentication', 'encryption', 'signal_percent')}
        auth = _security_value(row.get('authentication'), 'authentication')
        cipher = _security_value(row.get('encryption'), 'encryption')
        evidence.update(authentication=auth, encryption=cipher)
        if str(auth).casefold() in ('open', '开放式', '开放'):
            add('open-wifi', 'warning', 'Open Wi-Fi observed', evidence,
                'Verify the intended network and use authenticated encryption where available.')
        if re.search(r'\b(?:WEP|TKIP)\b', str(cipher), re.I) or re.search(r'\bWEP\b', str(auth), re.I):
            add('weak-encryption', 'warning', 'Legacy Wi-Fi encryption observed', evidence,
                'Replace WEP or TKIP with supported modern authenticated encryption.')
        if not auth or not cipher:
            add('security-unavailable', 'info', 'Wi-Fi security evidence unavailable', evidence,
                'Obtain authentication and cipher evidence before assessing this access point.')
        signal = row.get('signal_percent')
        if isinstance(signal, (int, float)) and not isinstance(signal, bool) and 0 <= signal < 30:
            add('weak-signal', 'info', 'Low signal observed', evidence,
                'Repeat observations near the access point; signal alone does not establish connection quality.')
        ssid = row.get('ssid')
        if ssid and (auth or cipher):
            groups.setdefault(ssid, []).append(evidence)
    for ssid, rows in groups.items():
        # Missing measurements are unknown; compare only observed values.
        differs = any(len({str(row[field]).casefold() for row in rows if row.get(field)}) > 1
                      for field in ('authentication', 'encryption'))
        if differs:
            add('mixed-security', 'warning', 'Different security under one SSID',
                {'ssid': ssid, 'observations': [{key: r.get(key) for key in ('bssid', 'authentication', 'encryption')} for r in rows]},
                'Verify these access points with the network administrator; same-name variation alone does not establish an attack.')
    firewall = report.get('firewall') or []
    if not firewall or any(type(row.get('enabled')) is not bool for row in firewall):
        add('firewall-unavailable', 'info', 'Firewall evidence unavailable', {},
            'Check firewall status using platform administration tools.')
    for row in firewall:
        if row.get('enabled') is False:
            add('firewall-disabled', 'warning', 'Firewall profile disabled',
                {'profile': row.get('name'), 'enabled': False},
                'Verify the intended host firewall policy before changing settings.')
    return findings
