"""Bounded local NVD 2.0 streaming. No network operations."""
import codecs
import datetime
import gzip
import hashlib
import io
import json
import math
import re

CHUNK = 65536
MAX_SOURCE_BYTES = 256 * 1024**2
MAX_EXPANDED_BYTES = 2 * 1024**3
MAX_VALUE_BYTES = 16 * 1024**2
MAX_DEPTH = 32
MAX_NODES = 250000


class CatalogError(ValueError):
    """A controlled input, integrity, resource or catalog error."""


class CatalogCancelled(CatalogError):
    """The caller cancelled a build."""


def check_cancel(cancel):
    if cancel is not None and (cancel() if callable(cancel) else cancel.is_set()):
        raise CatalogCancelled('Catalog operation cancelled.')


def hash_pin(value):
    if value is not None and (not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', value)):
        raise CatalogError('Expected SHA256 must contain 64 hexadecimal characters.')
    return value.lower() if value is not None else None


def valid_timestamp(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        return False
    try:
        datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
        return True
    except ValueError:
        return False


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CatalogError('Duplicate JSON key.')
        result[key] = value
    return result


def _integer(value):
    if len(value.lstrip('-')) > 18:
        raise CatalogError('JSON integer exceeds supported range.')
    return int(value)


def _float(value):
    if len(value) > 64:
        raise CatalogError('JSON number exceeds supported range.')
    exponent = value.lower().partition('e')[2]
    if exponent and (len(exponent.lstrip('+-')) > 3 or abs(int(exponent)) > 100):
        raise CatalogError('JSON exponent exceeds supported range.')
    number = float(value)
    if not math.isfinite(number) or (number and abs(number) > 1e100):
        raise CatalogError('JSON number exceeds supported range.')
    return number


def _constant(value):
    raise CatalogError('Nonfinite JSON number.')


def decode_json(value):
    """Decode one already byte/depth/node-bounded value with strict scalars."""
    try:
        return json.loads(value, object_pairs_hook=_pairs, parse_int=_integer,
                          parse_float=_float, parse_constant=_constant)
    except (ValueError, RecursionError) as exc:
        raise CatalogError('Invalid or over-budget JSON value.') from exc


class _Source:
    def __init__(self, file, cancel):
        self.file, self.cancel = file, cancel
        self.size = 0
        self.digest = hashlib.sha256()

    def read(self, size):
        check_cancel(self.cancel)
        parts = []
        remaining = min(size, 65536)
        while remaining:
            check_cancel(self.cancel)
            part = self.file.read(min(remaining, CHUNK))
            if not part:
                break
            parts.append(part)
            remaining -= len(part)
        data = b''.join(parts)
        self.size += len(data)
        if self.size > MAX_SOURCE_BYTES:
            raise CatalogError('Source byte budget exceeded.')
        self.digest.update(data)
        return data

    def seek(self, *args):
        return self.file.seek(*args)

    def tell(self):
        return self.file.tell()


class _JSONStream:
    def __init__(self, file, on_bytes):
        self.file, self.on_bytes = file, on_bytes
        self.decoder = codecs.getincrementaldecoder('utf-8-sig')('strict')
        self.buffer, self.pos, self.eof = '', 0, False

    def peek(self):
        while self.pos == len(self.buffer) and not self.eof:
            raw = self.file.read(CHUNK)
            self.on_bytes(raw)
            self.eof = not raw
            self.buffer = self.decoder.decode(raw, final=self.eof)
            self.pos = 0
        return self.buffer[self.pos:self.pos + 1]

    def take(self):
        char = self.peek()
        self.pos += bool(char)
        return char

    def space(self):
        while self.peek() and self.peek() in ' \t\r\n':
            self.take()

    def expect(self, char):
        self.space()
        if self.take() != char:
            raise CatalogError('Invalid NVD JSON structure.')

    def value(self, *, max_depth=None, max_nodes=None):
        depth_limit = MAX_DEPTH if max_depth is None else max_depth
        node_limit = MAX_NODES if max_nodes is None else max_nodes
        self.space()
        first = self.peek()
        if not first:
            raise CatalogError('Missing JSON value.')
        stack, quoted, escaped, started, nodes = [], False, False, False, 0
        text = io.StringIO()
        size = 0
        scalar = first not in '{["'
        while True:
            char = self.peek()
            if not char or (scalar and char in ',]} \t\r\n'):
                break
            self.take()
            size += len(char.encode('utf8'))
            if size > MAX_VALUE_BYTES:
                raise CatalogError('Encoded JSON value budget exceeded.')
            text.write(char)
            if quoted:
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == '"':
                    quoted = False
                    if not stack:
                        break
                continue
            if char == '"':
                quoted = True
                nodes += 1
                started = False
            elif char in '{[':
                stack.append(char)
                nodes += 1
                started = False
                if len(stack) > depth_limit:
                    raise CatalogError('JSON depth budget exceeded.')
            elif char in '}]':
                if not stack or stack.pop() != ('{' if char == '}' else '['):
                    raise CatalogError('Invalid JSON nesting.')
                started = False
                if not stack:
                    break
            elif char in ',: \t\r\n':
                started = False
            elif not started:
                nodes += 1
                started = True
            if nodes > node_limit:
                raise CatalogError('JSON node budget exceeded.')
        if stack or quoted:
            raise CatalogError('Truncated JSON value.')
        return decode_json(text.getvalue())


class FeedStream:
    """Single-use iterable of NVD wrapper objects; metadata final after exhaustion."""
    def __init__(self, path, *, expected_sha256=None, cancel=None, on_bytes=None):
        self.path, self.pin, self.cancel = path, hash_pin(expected_sha256), cancel
        self.on_bytes = on_bytes
        self.metadata = {}
        self.used = False

    def __iter__(self):
        if self.used:
            raise CatalogError('Feed stream already consumed.')
        self.used = True
        try:
            with open(self.path, 'rb') as file:
                magic = file.read(2)
                file.seek(0)
                source = _Source(file, self.cancel)
                expanded = 0
                digest = hashlib.sha256()

                def received(raw):
                    nonlocal expanded
                    check_cancel(self.cancel)
                    expanded += len(raw)
                    if expanded > MAX_EXPANDED_BYTES:
                        raise CatalogError('Expanded byte budget exceeded.')
                    digest.update(raw)
                    if self.on_bytes:
                        self.on_bytes(len(raw))

                with (gzip.GzipFile(fileobj=source, mode='rb') if magic == b'\x1f\x8b' else _Plain(source)) as stream:
                    reader = _JSONStream(stream, received)
                    reader.expect('{')
                    envelope, seen, count = {}, set(), 0
                    reader.space()
                    if reader.peek() == '}':
                        raise CatalogError('Missing NVD envelope.')
                    while True:
                        key = reader.value()
                        if not isinstance(key, str) or len(key) > 256 or key in seen:
                            raise CatalogError('Invalid or duplicate envelope key.')
                        seen.add(key)
                        if len(seen) > 256:
                            raise CatalogError('Envelope field budget exceeded.')
                        reader.expect(':')
                        if key == 'vulnerabilities':
                            reader.expect('[')
                            reader.space()
                            if reader.peek() != ']':
                                while True:
                                    record = reader.value()
                                    if not isinstance(record, dict) or set(record) != {'cve'} or not isinstance(record['cve'], dict):
                                        raise CatalogError('Invalid NVD vulnerability wrapper.')
                                    count += 1
                                    check_cancel(self.cancel)
                                    yield record
                                    reader.space()
                                    if reader.peek() == ']':
                                        break
                                    reader.expect(',')
                            reader.expect(']')
                        else:
                            value = reader.value()
                            if key in ('format', 'version', 'timestamp', 'totalResults', 'startIndex', 'resultsPerPage'):
                                envelope[key] = value
                        reader.space()
                        if reader.peek() == '}':
                            break
                        reader.expect(',')
                    reader.expect('}')
                    reader.space()
                    if reader.peek():
                        raise CatalogError('Trailing JSON data.')
                if envelope.get('format') != 'NVD_CVE' or envelope.get('version') != '2.0' or 'vulnerabilities' not in seen:
                    raise CatalogError('Unsupported NVD envelope.')
                for field in ('totalResults', 'startIndex', 'resultsPerPage'):
                    if field in envelope and (type(envelope[field]) is not int or not 0 <= envelope[field] <= 10**12):
                        raise CatalogError('Invalid NVD page count.')
                total, start, page = (envelope.get(k) for k in ('totalResults', 'startIndex', 'resultsPerPage'))
                if ((total is not None and (start or 0) + count > total)
                        or (page is not None and count > page)):
                    raise CatalogError('Contradictory NVD page counts.')
                timestamp = envelope.get('timestamp')
                if timestamp is not None and not valid_timestamp(timestamp):
                    raise CatalogError('Invalid feed timestamp.')
                if self.pin and digest.hexdigest() != self.pin:
                    raise CatalogError('Expanded SHA256 mismatch.')
                self.metadata = {'source_sha256': source.digest.hexdigest(), 'expanded_sha256': digest.hexdigest(),
                                     'source_bytes': source.size, 'expanded_bytes': expanded, 'records': count,
                                     'total_results': total, 'start_index': start, 'results_per_page': page,
                                     'timestamp': timestamp, 'partial': total is None or (start or 0) != 0 or count != total,
                                     'pin_verified': self.pin is not None}
        except CatalogError:
            raise
        except (OSError, EOFError, UnicodeError, ValueError, OverflowError) as exc:
            raise CatalogError('Cannot read valid bounded local NVD data.') from exc


class _Plain:
    def __init__(self, source):
        self.source = source

    def read(self, size):
        return self.source.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False
