"""Projection and exclusive JSON export for standalone field evidence."""
import copy
import json
import os
import secrets
import tempfile
from pathlib import Path

from .export_schema import _project_identity

_LINK_FIELDS = (
    'interface', 'ssid', 'bssid', 'authentication', 'cipher', 'channel',
    'signal_percent', 'signal_dbm', 'addresses', 'gateways', 'dns', 'routes',
    'dhcp_enabled', 'lease_seconds', 'lease_remaining_seconds', 'listeners',
    'firewall', 'proxy_configured', 'gaps', 'observed_at',
)
_IDENTITY_KEYS = frozenset((
    'interface', 'ssid', 'bssid', 'target', 'address', 'addresses', 'gateways',
    'gateway', 'dns', 'source', 'portal_targets', 'peer_targets',
))


def project_field(report, include_identifiers=False):
    result = copy.deepcopy(report)
    if 'link' in result:
        result['link'] = {k: result['link'][k] for k in _LINK_FIELDS if k in result['link']}
    result['identifiers_included'] = include_identifiers is True
    if include_identifiers is True:
        return result
    key = secrets.token_bytes(32)

    def redact(value):
        if isinstance(value, dict):
            return {k: (identity(v) if k in _IDENTITY_KEYS and isinstance(v, (str, list))
                        else redact(v)) for k, v in value.items()}
        if isinstance(value, list):
            return [redact(v) for v in value]
        return value

    def identity(value):
        if isinstance(value, list):
            return [identity(item) for item in value]
        return _project_identity(value, False, key)

    return redact(result)


def check_new_path(path):
    target = Path(path).absolute()
    if target.exists() or target.is_symlink():
        raise FileExistsError('Use a new field report file.')
    if not target.parent.is_dir():
        raise ValueError('The parent directory of the field report must already exist.')
    return target


def save_field(report, path, include_identifiers=False):
    target = check_new_path(path)
    content = json.dumps(project_field(report, include_identifiers), ensure_ascii=False,
                         indent=2, allow_nan=False) + '\n'
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=target.parent,
                                     prefix='.wifiscope-field-', delete=False) as stream:
        staged = Path(stream.name)
        try:
            stream.write(content)
            stream.close()
            os.link(staged, target)
        finally:
            staged.unlink(missing_ok=True)
    return str(target)
