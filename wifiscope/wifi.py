"""Pure parsers for netsh and nmcli observations; no command execution."""
import locale
import re


_SECURITY_LABELS = {
    'authentication': ('Open', 'WEP', 'OWE', 'SAE', '802.1X', 'WPA', 'WPA-Personal',
        'WPA-Enterprise', 'WPA2', 'WPA2-Personal', 'WPA2-Enterprise', 'WPA3',
        'WPA3-Personal', 'WPA3-Enterprise', 'WPA1 WPA2', 'WPA2 WPA3', 'WPA2-PSK',
        'WPA3-SAE', 'WPA3-Enterprise 192 bits', 'WPA-个人', 'WPA-企业', 'WPA2-个人',
        'WPA2-企业', 'WPA3-个人', 'WPA3-企业'),
    'encryption': ('None', 'WEP', 'TKIP', 'CCMP', 'GCMP', 'AES', 'CCMP-256',
        'GCMP-256', 'TKIP+CCMP', 'TKIP CCMP'),
}


def _security_value(value, field):
    """Share recognized security evidence across parsing, audit and export.

    Unknown, unsupported and unfamiliar labels are missing evidence rather than
    an affirmative security measurement. No arbitrary OS prose is retained.
    """
    if not isinstance(value, str):
        return None
    value = {'开放式': 'Open', '开放': 'Open', '无': 'None'}.get(value.strip(), value.strip())
    return next((label for label in _SECURITY_LABELS[field] if label.casefold() == value.casefold()), None)


def decode_console(raw: bytes) -> str:
    """Decode UTF-8 first, then common Chinese console output, then locale."""
    if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
        return raw.decode('utf-16', errors='replace')
    for encoding in dict.fromkeys(('utf-8-sig', 'gb18030', locale.getpreferredencoding(False))):
        try:
            return raw.decode(encoding)
        except (UnicodeError, LookupError):
            pass
    return raw.decode('utf-8', errors='replace')


def _measurement(value, maximum):
    if len(value) > 3 or not re.fullmatch(r'[0-9]+', value):
        return None
    number = int(value)
    return number if 0 <= number <= maximum else None


def _record(ssid, bssid, authentication=None, encryption=None):
    return dict(ssid=ssid, bssid=bssid.lower(), authentication=authentication,
                encryption=encryption, signal_percent=None, channel=None, radio_type=None)


def _mac(value):
    return re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value) is not None


def parse_netsh(text: str) -> list[dict]:
    rows = []
    ssid, authentication, encryption, current = None, None, None, None
    labels = {'authentication': 'authentication', '身份验证': 'authentication',
              '验证': 'authentication', 'encryption': 'encryption', '加密': 'encryption',
              'signal': 'signal_percent', '信号': 'signal_percent',
              'channel': 'channel', '频道': 'channel', '信道': 'channel',
              'radio type': 'radio_type', '无线电类型': 'radio_type'}
    for line in text.splitlines():
        match = re.match(r'^\s*(SSID|BSSID)\s+\d+\s*[:：] ?(.*)$', line, re.I)
        if match:
            if match[1].upper() == 'SSID':
                # netsh adds one ASCII formatting space after the separator.
                # Additional whitespace belongs to the SSID and is significant.
                ssid, authentication, encryption, current = match[2], None, None, None
            else:
                value = match[2].strip()
                current = None
                if ssid is not None and _mac(value):
                    current = _record(ssid, value, authentication, encryption)
                    rows.append(current)
            continue
        parts = re.split(r'\s*[:：]\s*', line.strip(), maxsplit=1)
        if len(parts) != 2:
            continue
        field = labels.get(parts[0].lower())
        value = parts[1].strip()
        if field in ('authentication', 'encryption'):
            value = _security_value(value, field)
            if field == 'authentication':
                authentication = value
            else:
                encryption = value
            if current is not None:
                current[field] = value
        elif current is not None and field:
            if field == 'signal_percent':
                current[field] = _measurement(value.removesuffix('%'), 100)
            elif field == 'channel':
                current[field] = _measurement(value, 233)
                if current[field] == 0:
                    current[field] = None
            else:
                current[field] = value or None
    return rows


def _split_terse(line):
    fields, chars, escaped = [], [], False
    for char in line:
        if escaped:
            chars.append(char)
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == ':':
            fields.append(''.join(chars))
            chars = []
        else:
            chars.append(char)
    if escaped:
        return []
    return fields + [''.join(chars)]


def parse_nmcli(text: str) -> list[dict]:
    """Parse -t --escape yes -f SSID,BSSID,SECURITY,SIGNAL,CHAN output."""
    rows = []
    for line in text.splitlines():
        fields = _split_terse(line)
        if len(fields) != 5 or not _mac(fields[1]):
            continue
        ssid, bssid, security, signal, channel = fields
        row = _record(ssid, bssid, _security_value('Open' if security == '--' else security, 'authentication'))
        row['signal_percent'] = _measurement(signal, 100)
        row['channel'] = _measurement(channel, 233)
        if row['channel'] == 0:
            row['channel'] = None
        rows.append(row)
    return rows
