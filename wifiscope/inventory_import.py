"""Bounded local SBOM identity extraction, never installation discovery.

This is not full SBOM schema validation. No remote references are resolved.
Retention overflow refuses the complete import; identities are never truncated.
"""
import hashlib

from .catalog_store import _safe_path
from .catalog_stream import _JSONStream, CatalogError
from .cpe_names import parse_cpe
from .inventory import MAX_BYTES, timestamp, validate_inventory, _cancel


def _document(path, cancel):
    local, digest, size = _safe_path(path), hashlib.sha256(), 0
    def consumed(raw):
        nonlocal size
        _cancel(cancel)
        size += len(raw)
        if size > MAX_BYTES:
            raise ValueError('Inventory source exceeds 16 MiB.')
        digest.update(raw)
    try:
        with open(local, 'rb') as stream:
            reader = _JSONStream(stream, consumed)
            value = reader.value(max_depth=32, max_nodes=250000)
            reader.space()
            if reader.peek():
                raise ValueError('Invalid inventory JSON.')
        return value, digest.hexdigest()
    except (UnicodeError, RecursionError, CatalogError):
        raise ValueError('Invalid bounded inventory JSON.') from None


def _list(value):
    if not isinstance(value, list):
        raise ValueError('Invalid SBOM entry list.')
    return value


def _entries(document, format):
    if format == 'cyclonedx':
        if document.get('bomFormat') != 'CycloneDX' or document.get('specVersion') not in ('1.6', '1.7'):
            raise ValueError('Use explicit CycloneDX JSON 1.6 or 1.7.')
        metadata = document.get('metadata', {})
        if not isinstance(metadata, dict):
            raise ValueError('Invalid SBOM metadata.')
        source_time = metadata.get('timestamp')
        roots = list(_list(document.get('components', [])))
        if 'component' in metadata:
            roots.append(metadata['component'])
        def entries():
            pending = list(reversed(roots))
            while pending:
                row = pending.pop()
                if not isinstance(row, dict):
                    raise ValueError('Invalid SBOM component.')
                pending.extend(reversed(_list(row.get('components', []))))
                identifiers = [row['cpe']] if 'cpe' in row else []
                # Count explicit unsupported identifiers, without retaining PURLs.
                other = [('purl', row['purl'])] if 'purl' in row else []
                yield identifiers, other
    else:
        if document.get('spdxVersion') != 'SPDX-2.3':
            raise ValueError('Use explicit SPDX JSON SPDX-2.3.')
        metadata = document.get('creationInfo', {})
        if not isinstance(metadata, dict):
            raise ValueError('Invalid SBOM metadata.')
        source_time = metadata.get('created')
        packages = _list(document.get('packages', []))
        def entries():
            for row in packages:
                if not isinstance(row, dict):
                    raise ValueError('Invalid SPDX package.')
                identifiers, other = [], []
                for ref in _list(row.get('externalRefs', [])):
                    if not isinstance(ref, dict):
                        raise ValueError('Invalid SPDX external reference.')
                    if ref.get('referenceCategory') == 'SECURITY' and ref.get('referenceType') == 'cpe23Type':
                        identifiers.append(ref.get('referenceLocator'))
                    else:
                        other.append((ref.get('referenceType'), ref.get('referenceLocator')))
                yield identifiers, other
    timestamp(source_time)
    return entries(), source_time


def import_inventory(path, *, format, cancel=None):
    """Return independent schema1 from explicit native/SBOM JSON or Nmap XML.

    One SBOM becomes one logical asset. IDs hash exact source bytes, traversal
    ordinal and decoded equivalent CPE tokens. Repetition within an entry is
    deduplicated case-insensitively; separate entries remain separate components.
    """
    if format == 'nmap':
        from .nmap_inventory import import_nmap_inventory
        return import_nmap_inventory(path, cancel=cancel)
    if format not in ('native', 'cyclonedx', 'spdx'):
        raise ValueError('Select native, cyclonedx, spdx or nmap explicitly.')
    _cancel(cancel)
    document, digest = _document(path, cancel)
    if format == 'native':
        result = validate_inventory(document)
        for asset in result['assets']:
            for component in asset['components']:
                _cancel(cancel)
        return result
    if not isinstance(document, dict):
        raise ValueError('Invalid SBOM document.')
    entries, source_time = _entries(document, format)
    context = dict(format=format, source_sha256=digest, document_observed_at=source_time,
        input_entries=0, input_cpe_identifiers=0, retained_components=0, unmapped_entries=0,
        unsupported_identifiers=0, duplicate_identifiers=0, partial=False, gaps=[])
    components = []
    for ordinal, (identifiers, other) in enumerate(entries):
        _cancel(cancel)
        context['input_entries'] += 1
        context['input_cpe_identifiers'] += len(identifiers)
        context['unsupported_identifiers'] += len(other)
        seen, kept = set(), 0
        for kind, value in other:
            if isinstance(kind, str) and isinstance(value, str):
                key = ('unsupported', kind, value)
                if key in seen:
                    context['duplicate_identifiers'] += 1
                seen.add(key)
        for identifier in identifiers:
            _cancel(cancel)
            try:
                name = parse_cpe(identifier)
                if (any(name.field(k).kind != 'literal' for k in ('part', 'vendor', 'product', 'version'))
                        or any(a.kind in ('pattern', 'unsupported') for a in name.attributes)
                        or any(len(name.field(k).text) > 256 for k in ('vendor', 'product'))):
                    raise ValueError
            except ValueError:
                context['unsupported_identifiers'] += 1
                if isinstance(identifier, str):
                    key = ('unsupported-cpe', identifier.casefold())
                    if key in seen:
                        context['duplicate_identifiers'] += 1
                    seen.add(key)
                continue
            key = tuple((a.kind, a.text) for a in name.attributes)
            if key in seen:
                context['duplicate_identifiers'] += 1
                continue
            seen.add(key)
            if len(components) >= 8192:
                raise ValueError('Inventory retention limit exceeded; import refused without truncation.')
            component_id = hashlib.sha256(repr((digest, ordinal, key)).encode('utf-8')).hexdigest()
            components.append(dict(id='sbom-component-'+component_id, cpe=identifier, source='sbom',
                identification='imported', observed_at=source_time, source_sha256=digest))
            kept += 1
        if not kept:
            context['unmapped_entries'] += 1
    if not components:
        raise ValueError('No usable explicit CPE 2.3 identity; select native inventory or provide explicit literal CPEs. PURLs/names are not inferred.')
    context['retained_components'] = len(components)
    gaps = ['sbom-import-unverified', 'runtime-state-unverified']
    for counter, gap in [('unsupported_identifiers', 'unsupported-cpe'), ('unmapped_entries', 'unmapped-identifier'),
                         ('duplicate_identifiers', 'duplicate-identifier')]:
        if context[counter]:
            gaps.append(gap)
    if source_time is None:
        gaps.append('source-time-unknown')
    context['gaps'] = gaps
    return validate_inventory(dict(schema_version=1, assets=[dict(id='sbom-document-'+digest,
        complete_parts=[], components=components)], import_context=context))
