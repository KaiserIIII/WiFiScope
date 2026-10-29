"""Strict bounded local inventory contract; no identity inference or IO collection."""
import copy
from datetime import datetime
import ipaddress
import json
import math
import re
import unicodedata

from .cpe_names import parse_cpe

MAX_BYTES = 16 * 1024 * 1024
SCHEMES = ('numeric', 'semver2', 'openssh-portable', 'unknown')
SOURCES = ('local', 'nmap', 'sbom', 'native', 'synthetic', 'unknown')
IDENTIFICATIONS = ('probed', 'declared', 'imported', 'unknown')
CONTEXT_COUNTERS = ('input_entries', 'input_cpe_identifiers', 'retained_components',
                    'unmapped_entries', 'unsupported_identifiers', 'duplicate_identifiers')
IMPORT_GAPS = frozenset(('sbom-import-unverified', 'unsupported-cpe', 'unmapped-identifier',
    'duplicate-identifier', 'runtime-state-unverified', 'input-partial', 'source-time-unknown'))


def bad_inventory():
    raise ValueError('Invalid typed inventory; use bounded inventory schema_version=1.')


def bounded_json(value, *, max_depth=32, max_nodes=250000, allow_numbers=False):
    """Bound the exact default-separator, ensure_ascii=False JSON byte size.

    Count escape expansion and UTF-8 before serializing/copying the object. Only
    constant-size scalar representations and the bounded traversal stack exist;
    no expanded JSON string/bytes is constructed by this validation pass.
    """
    pending = [(value, 0)]
    nodes, size = 0, 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > max_nodes or depth > max_depth or size > MAX_BYTES:
            bad_inventory()
        if isinstance(item, str):
            if len(item) + 2 > MAX_BYTES - size:
                bad_inventory()
            size += 2  # quoted string, including dictionary keys
            for char in item:
                escaped = json.encoder.ESCAPE_DCT.get(char)
                if escaped is not None:
                    size += len(escaped)
                else:
                    code = ord(char)
                    if 0xD800 <= code <= 0xDFFF:
                        # Preserve the normal UTF-8 failure, not an unrelated
                        # controlled size failure or a lossy replacement.
                        char.encode('utf8')
                    size += 1 if code < 0x80 else 2 if code < 0x800 else 3 if code < 0x10000 else 4
                if size > MAX_BYTES:
                    bad_inventory()
        elif isinstance(item, dict):
            if len(item) * 2 + nodes + len(pending) > max_nodes:
                bad_inventory()
            if any(not isinstance(k, str) for k in item):
                bad_inventory()
            size += 2 + 2 * len(item) + 2 * max(0, len(item) - 1)  # {}, ': ', ', '
            if size > MAX_BYTES:
                bad_inventory()
            pending.extend((v, depth + 1) for pair in item.items() for v in pair)
        elif isinstance(item, list):
            if len(item) + nodes + len(pending) > max_nodes:
                bad_inventory()
            size += 2 + 2 * max(0, len(item) - 1)  # [], ', '
            if size > MAX_BYTES:
                bad_inventory()
            pending.extend((v, depth + 1) for v in item)
        elif type(item) is float and allow_numbers and math.isfinite(item):
            size += len(repr(item))
        elif type(item) is int and item.bit_length() > 64:
            bad_inventory()
        elif item is not None and type(item) not in (int, bool):
            bad_inventory()
        else:
            size += 4 if item is None or item is True else 5 if item is False else len(str(item))
        if size > MAX_BYTES:
            bad_inventory()


def text(value, limit=256):
    if (not isinstance(value, str) or not 1 <= len(value) <= limit
            or any(unicodedata.category(c) == 'Cc' for c in value)):
        bad_inventory()
    return value


def timestamp(value):
    if value is not None:
        text(value, 64)
        try:
            datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            bad_inventory()


def digest(value, *, projected=False):
    if value is not None and (not isinstance(value, str) or not (
            re.fullmatch('[0-9a-f]{64}', value) or projected and re.fullmatch('id-[0-9a-f]{24}', value))):
        bad_inventory()


def validate_import_context(value, count, *, projected=False):
    if (not isinstance(value, dict) or set(value) != set(CONTEXT_COUNTERS) | {
            'format', 'source_sha256', 'document_observed_at', 'partial', 'gaps'}):
        bad_inventory()
    if value['format'] not in ('native', 'cyclonedx', 'spdx', 'nmap') or type(value['partial']) is not bool:
        bad_inventory()
    for key in CONTEXT_COUNTERS:
        if type(value[key]) is not int or not 0 <= value[key] <= 250000:
            bad_inventory()
    if value['retained_components'] != count:
        bad_inventory()
    digest(value['source_sha256'], projected=projected)
    timestamp(value['document_observed_at'])
    gaps = value['gaps']
    if (not isinstance(gaps, list) or any(not isinstance(g, str) or g not in IMPORT_GAPS for g in gaps)
            or len(gaps) != len(set(gaps))):
        bad_inventory()


def validate_inventory(value):
    bounded_json(value)
    if (not isinstance(value, dict) or set(value) - {'schema_version', 'assets', 'import_context'}
            or type(value.get('schema_version')) is not int or value['schema_version'] != 1):
        bad_inventory()
    assets = value.get('assets')
    if not isinstance(assets, list) or not 1 <= len(assets) <= 1024:
        bad_inventory()
    asset_ids, component_ids, count = set(), set(), 0
    result = {'schema_version': 1, 'assets': []}
    provenance = {'source', 'identification', 'observed_at', 'source_sha256', 'version_scheme'}
    for asset in assets:
        if not isinstance(asset, dict) or set(asset) - {'id', 'components', 'complete_parts', 'address'}:
            bad_inventory()
        identifier = text(asset.get('id'))
        if identifier in asset_ids:
            bad_inventory()
        asset_ids.add(identifier)
        parts = asset.get('complete_parts', [])
        if (not isinstance(parts, list) or any(not isinstance(p, str) or p not in ('a', 'o', 'h') for p in parts)
                or len(parts) != len(set(parts))):
            bad_inventory()
        address = asset.get('address')
        if address is not None:
            try:
                if not isinstance(address, str) or '%' in address:
                    bad_inventory()
                address = str(ipaddress.ip_address(address))
            except ValueError:
                bad_inventory()
        rows = asset.get('components')
        if not isinstance(rows, list) or not rows:
            bad_inventory()
        normalized = dict(id=identifier, complete_parts=list(parts), components=[])
        if 'address' in asset:
            normalized['address'] = address
        for row in rows:
            count += 1
            if count > 8192 or not isinstance(row, dict):
                bad_inventory()
            key = text(row.get('id'))
            if key in component_ids:
                bad_inventory()
            component_ids.add(key)
            if 'cpe' in row:
                if set(row) - ({'id', 'cpe'} | provenance):
                    bad_inventory()
                name = parse_cpe(row['cpe'])
                if name.field('part').kind != 'literal':
                    bad_inventory()
                component = dict(id=key, cpe=row['cpe'])
            else:
                if (set(row) - ({'id', 'vendor', 'product', 'version'} | provenance)
                        or 'version' not in row):
                    bad_inventory()
                version = row['version']
                if version is not None:
                    text(version, 1024)
                component = dict(id=key, vendor=text(row.get('vendor')), product=text(row.get('product')), version=version)
            component.update(source=row.get('source', 'unknown'), identification=row.get('identification', 'unknown'),
                             observed_at=row.get('observed_at'), source_sha256=row.get('source_sha256'),
                             version_scheme=row.get('version_scheme', 'unknown'))
            if (component['source'] not in SOURCES or component['identification'] not in IDENTIFICATIONS
                    or component['version_scheme'] not in SCHEMES):
                bad_inventory()
            timestamp(component['observed_at'])
            digest(component['source_sha256'])
            normalized['components'].append(component)
        result['assets'].append(normalized)
    if 'import_context' in value:
        validate_import_context(value['import_context'], count)
        result['import_context'] = copy.deepcopy(value['import_context'])
    return result


def load_inventory(path):
    from .catalog_store import _safe_path
    from .catalog_stream import _JSONStream, CatalogError
    # Reuse the already-reviewed local path and streaming lexical JSON boundary;
    # depth/nodes are checked before json.loads allocates the decoded object.
    local = _safe_path(path)
    size = 0
    def on_bytes(raw):
        nonlocal size
        size += len(raw)
        if size > MAX_BYTES:
            bad_inventory()
    try:
        with open(local, 'rb') as stream:
            reader = _JSONStream(stream, on_bytes)
            value = reader.value(max_depth=32, max_nodes=250000)
            reader.space()
            if reader.peek():
                bad_inventory()
        return validate_inventory(value)
    except (RecursionError, UnicodeError, CatalogError):
        bad_inventory()
