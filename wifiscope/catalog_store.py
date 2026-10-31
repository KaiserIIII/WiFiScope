"""Immutable SQLite catalog generations and bounded readonly queries."""
import hashlib
import io
import json
import os
import re
import sqlite3
import tempfile
import time
from contextlib import suppress
from functools import wraps
from heapq import heappush, heapreplace
from pathlib import Path

from .catalog_records import (
    GAPS,
    STATUSES,
    canonical,
    cve_id,
    modified_time,
    normalize,
    text,
)
from .catalog_stream import (
    MAX_VALUE_BYTES,
    CatalogCancelled,
    CatalogError,
    FeedStream,
    _JSONStream,
    check_cancel,
    hash_pin,
)

MAX_INPUTS = 64
MAX_RECORDS = 1000000
MAX_DB_BYTES = 8 * 1024**3
MAX_RELEVANT_BYTES = 16 * 1024**2
MAX_IDENTITY_ROWS = 200000
QUERY_STEPS = 20000000
# Private full-generation scan: linear allowance for the bounded staged DB,
# plus an elapsed deadline. Ordinary readonly queries retain QUERY_STEPS.
_BUILD_INTEGRITY_STEPS_PER_BYTE = 64
_BUILD_INTEGRITY_SECONDS = 600
APPLICATION_ID = 0x57534332
SCHEMA_VERSION = 1
SCHEMA = (
    "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID",
    "CREATE TABLE feeds (feed_index INTEGER PRIMARY KEY, body TEXT NOT NULL)",
    "CREATE TABLE records (cve TEXT PRIMARY KEY, status TEXT NOT NULL, published TEXT, modified TEXT, body TEXT NOT NULL) WITHOUT ROWID",
    "CREATE TABLE identities (kind TEXT NOT NULL, part TEXT NOT NULL, vendor TEXT NOT NULL, product TEXT NOT NULL, cve TEXT NOT NULL, PRIMARY KEY (kind, part, vendor, product, cve)) WITHOUT ROWID",
    "CREATE TABLE memberships (cve TEXT NOT NULL, feed_index INTEGER NOT NULL, PRIMARY KEY (cve, feed_index)) WITHOUT ROWID",
    "CREATE INDEX identities_names ON identities (vendor, product, cve)",
    "CREATE INDEX identities_cve ON identities (cve)",
    "CREATE INDEX memberships_feed ON memberships (feed_index, cve)",
)
EXPECTED_SCHEMA = {sql.split()[2]: ('index' if sql.startswith('CREATE INDEX') else 'table', sql) for sql in SCHEMA}


def _bounded_int(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise CatalogError('Invalid catalog query bound.')
    return value


def _local_name(path):
    """Reject network syntax before ANY filesystem metadata lookup."""
    try:
        name = os.fspath(path)
        if (not isinstance(name, str) or not name or '\x00' in name
                or name.startswith(('\\\\', '//'))
                or (re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', name) and not re.match(r'^[a-zA-Z]:', name))):
            raise CatalogError('Only explicit local filesystem paths are supported.')
        result = Path(os.path.abspath(name))
        if str(result).startswith(('\\\\', '//')):
            raise CatalogError('Only explicit local filesystem paths are supported.')
        if os.name == 'nt':
            import ctypes
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(str(result.anchor))
            if drive_type == 4:  # DRIVE_REMOTE: includes mapped SMB drives.
                raise CatalogError('Network-share catalog paths are not supported.')
        return result
    except (OSError, TypeError, ValueError) as exc:
        if isinstance(exc, CatalogError):
            raise
        raise CatalogError('Invalid local catalog path.') from exc


def _safe_path(path, *, destination=False):
    try:
        result = _local_name(path)
        for ancestor in (result, *result.parents):
            if ancestor.is_symlink() or getattr(ancestor, 'is_junction', lambda: False)():
                raise CatalogError('Catalog path must not traverse links.')
        if destination:
            if os.path.lexists(result) or not result.parent.is_dir():
                raise CatalogError('Catalog output must be a new file in an existing directory.')
        elif not result.is_file():
            raise CatalogError('Catalog input must be a local regular file.')
        return result
    except (OSError, TypeError, ValueError) as exc:
        if isinstance(exc, CatalogError):
            raise
        raise CatalogError('Invalid local catalog path.') from exc


def _file_hash(path, *, cancel=None):
    digest = hashlib.sha256()
    def checkpoint():
        try:
            check_cancel(cancel)
        except CatalogCancelled:
            raise
        except Exception:
            raise CatalogError('Catalog cancellation callback failed.') from None
    checkpoint()
    with open(path, 'rb') as file:
        while chunk := file.read(65536):
            digest.update(chunk)
            checkpoint()
    checkpoint()
    return digest.hexdigest()


def _json_body(value):
    if not isinstance(value, str) or len(value) > MAX_VALUE_BYTES:
        raise CatalogError('Invalid catalog row size.')
    raw = value.encode('utf8')
    if len(raw) > MAX_VALUE_BYTES:
        raise CatalogError('Invalid catalog row size.')
    reader = _JSONStream(io.BytesIO(raw), lambda _: None)
    result = reader.value(max_depth=40, max_nodes=4000000)
    reader.space()
    if reader.peek():
        raise CatalogError('Invalid catalog JSON row.')
    return result


def _validate_record(row):
    fields = {'cve', 'status', 'published', 'modified', 'cvss', 'configurations', 'affected', 'gaps', 'applicability'}
    if not isinstance(row, dict) or set(row) != fields:
        raise CatalogError('Invalid catalog record schema.')
    cve_id(row['cve'])
    if not isinstance(row['status'], str) or row['status'] not in STATUSES | {'Unknown'}:
        raise CatalogError('Invalid catalog status.')
    for field in ('published', 'modified'):
        if row[field] is not None and modified_time(row[field]) is None:
            raise CatalogError('Invalid catalog timestamp.')
    if (not isinstance(row['gaps'], list) or any(not isinstance(g, str) or g not in GAPS for g in row['gaps'])
            or row['gaps'] != sorted(set(row['gaps']))):
        raise CatalogError('Invalid catalog gaps.')
    if (not isinstance(row['applicability'], dict) or set(row['applicability']) != {'configurations', 'affected'}
            or any(v not in ('present', 'missing', 'unsupported') for v in row['applicability'].values())):
        raise CatalogError('Invalid catalog applicability metadata.')
    if not isinstance(row['cvss'], list):
        raise CatalogError('Invalid catalog CVSS.')
    for metric in row['cvss']:
        if (not isinstance(metric, dict) or set(metric) != {'score', 'version', 'source'}
                or type(metric['score']) not in (int, float) or not 0 <= metric['score'] <= 10
                or metric['version'] not in ('2.0', '3.0', '3.1', '4.0') or not text(metric['source'])):
            raise CatalogError('Invalid catalog CVSS.')
    # Re-normalize the supported typed structures and require their exact shape.
    def original_node(node):
        if (not isinstance(node, dict) or set(node) != {'operator', 'negate', 'nodes', 'cpeMatch', 'unsupported'}
                or type(node['unsupported']) is not bool or node['operator'] not in ('OR', 'AND')
                or type(node['negate']) is not bool or not isinstance(node['nodes'], list)
                or not isinstance(node['cpeMatch'], list)):
            raise CatalogError('Invalid catalog configuration.')
        matches = []
        for match in node['cpeMatch']:
            if not isinstance(match, dict) or type(match.get('unsupported')) is not bool:
                raise CatalogError('Invalid catalog CPE match.')
            allowed = {'criteria', 'vulnerable', 'matchCriteriaId', 'versionStartIncluding', 'versionStartExcluding',
                       'versionEndIncluding', 'versionEndExcluding', 'unsupported'}
            if set(match) - allowed:
                raise CatalogError('Invalid catalog CPE fields.')
            for key, value in match.items():
                valid = type(value) is bool if key in ('unsupported', 'vulnerable') else text(value, 2048 if key == 'criteria' else 1024)
                if not valid:
                    raise CatalogError('Invalid catalog CPE field type.')
            if not match['unsupported'] and not {'criteria', 'vulnerable'} <= set(match):
                raise CatalogError('Missing catalog CPE fields.')
            matches.append({k: v for k, v in match.items() if k != 'unsupported'})
        return {"operator": node['operator'], "negate": node['negate'],
                    "nodes": [original_node(n) for n in node['nodes']], "cpeMatch": matches}
    if not isinstance(row['configurations'], list) or not isinstance(row['affected'], list):
        raise CatalogError('Invalid applicability structures.')
    configs = [original_node(n) for n in row['configurations']]
    affected = []
    for source in row['affected']:
        if (not isinstance(source, dict) or set(source) != {'source', 'affectedData'}
                or (source['source'] is not None and not text(source['source'])) or not isinstance(source['affectedData'], list)):
            raise CatalogError('Invalid catalog affected source.')
        entry = {'source': source['source'], 'affectedData': []}
        for item in source['affectedData']:
            if (not isinstance(item, dict) or set(item) != {'vendor', 'product', 'defaultStatus', 'versions', 'context', 'cpes', 'unsupported'}
                    or type(item['unsupported']) is not bool or not isinstance(item['context'], dict)
                    or set(item['context']) - {'platforms', 'modules', 'programFiles', 'programRoutines', 'routines', 'collectionURL', 'packageURL', 'packageName', 'repo'}
                    or not isinstance(item['versions'], list) or not isinstance(item['cpes'], list)
                    or any(not text(cpe, 2048) for cpe in item['cpes'])):
                raise CatalogError('Invalid catalog affected row.')
            for field in ('vendor', 'product'):
                if item[field] is not None and not text(item[field]):
                    raise CatalogError('Invalid catalog affected identity.')
            if item['defaultStatus'] not in (None, 'affected', 'unaffected', 'unknown'):
                raise CatalogError('Invalid catalog affected default.')
            original = {k: item[k] for k in ('vendor', 'product', 'cpes') if item[k] is not None}
            original.update(item['context'])
            if item['defaultStatus'] is not None:
                original['defaultStatus'] = item['defaultStatus']
            original['versions'] = []
            for version in item['versions']:
                if (not isinstance(version, dict) or type(version.get('unsupported')) is not bool
                        or not isinstance(version.get('changes'), list)
                        or set(version) - {'version', 'lessThan', 'lessThanOrEqual', 'versionType', 'status', 'changes', 'unsupported'}):
                    raise CatalogError('Invalid catalog CNA version.')
                for field, value in version.items():
                    if field not in ('unsupported', 'changes') and (not text(value, 1024) or (field == 'status' and value not in ('affected', 'unaffected', 'unknown'))):
                        raise CatalogError('Invalid catalog CNA version field.')
                if not version['unsupported'] and not {'version', 'status'} <= set(version):
                    raise CatalogError('Missing catalog CNA version fields.')
                for change in version['changes']:
                    if (not isinstance(change, dict) or set(change) != {'at', 'status'} or not text(change['at'], 1024)
                            or change['status'] not in ('affected', 'unaffected', 'unknown')):
                        raise CatalogError('Invalid catalog CNA change.')
                original['versions'].append({k: v for k, v in version.items() if k != 'unsupported'})
            entry['affectedData'].append(original)
        affected.append(entry)
    # This enforces leaf/affected-row budgets on untrusted database bodies too.
    normalize({"id": row['cve'], "vulnStatus": row['status'], "configurations": configs, "affected": affected})
    return row


class _Progress:
    def __init__(self, callback, cancel):
        self.callback, self.cancel = callback, cancel
        self.start = time.monotonic()
        self.last = None
        self.records = self.expanded = self.feed = 0

    def emit(self, status='running'):
        check_cancel(self.cancel)
        now = time.monotonic()
        if self.callback and (status != 'running' or self.last is None or now - self.last >= .2):
            event = {"status": status, "records": self.records, "expanded_bytes": self.expanded,
                         "feed_index": self.feed, "elapsed_ms": max(0, int((now - self.start) * 1000))}
            try:
                self.callback(event)
            except Exception as exc:
                raise CatalogError('Catalog progress callback failed.') from exc
            self.last = now

    def received(self, count):
        self.expanded += count
        self.emit()


def build_catalog(inputs, destination, *, expected_sha256=None, cancel=None, progress=None):
    """Build from 1..64 explicit local paths, publish a NEW file atomically."""
    if not isinstance(inputs, (list, tuple)) or not 1 <= len(inputs) <= MAX_INPUTS:
        raise CatalogError('Supply 1..64 explicit input files.')
    if expected_sha256 is not None and (not isinstance(expected_sha256, (list, tuple)) or len(expected_sha256) != len(inputs)):
        raise CatalogError('Supply one expanded SHA256 per input or no pins.')
    pins = [hash_pin(pin) for pin in expected_sha256] if expected_sha256 is not None else [None] * len(inputs)
    if expected_sha256 is not None and any(pin is None for pin in pins):
        raise CatalogError('Supply one expanded SHA256 per input or no pins.')
    for name in (*inputs, destination):
        _local_name(name)
    target = _safe_path(destination, destination=True)
    paths = [_safe_path(path) for path in inputs]
    tracker = _Progress(progress, cancel)
    staging, connection = None, None
    try:
        tracker.emit()
        descriptor, staging = tempfile.mkstemp(prefix='.wifiscope-catalog-', suffix='.db', dir=target.parent)
        os.close(descriptor)
        connection = sqlite3.connect(staging)
        connection.execute('PRAGMA journal_mode=DELETE')
        connection.execute('PRAGMA synchronous=FULL')
        connection.execute('PRAGMA temp_store=FILE')
        connection.execute('PRAGMA cache_size=-8192')
        connection.execute(f'PRAGMA max_page_count={MAX_DB_BYTES // 4096}')
        connection.execute(f'PRAGMA application_id={APPLICATION_ID}')
        connection.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
        connection.set_progress_handler(lambda: int(_cancelled(cancel)), 1000)
        for sql in SCHEMA:
            connection.execute(sql)
        feed_info = []
        for number, (path, pin) in enumerate(zip(paths, pins)):
            tracker.feed = number
            stream = FeedStream(path, expected_sha256=pin, cancel=cancel, on_bytes=tracker.received)
            for wrapper in stream:
                tracker.records += 1
                if tracker.records > MAX_RECORDS:
                    raise CatalogError('Input record budget exceeded.')
                record, keys = normalize(wrapper['cve'])
                body = canonical(record)
                if len(body.encode('utf8')) > MAX_VALUE_BYTES:
                    raise CatalogError('Normalized record byte budget exceeded.')
                identifier = record['cve']
                prior = connection.execute('SELECT modified, body FROM records WHERE cve=?', (identifier,)).fetchone()
                replace = prior is None
                if prior and prior[1] != body:
                    old_time, new_time = modified_time(prior[0]), modified_time(record['modified'])
                    if old_time is None or new_time is None or old_time[0] != new_time[0] or old_time[1] == new_time[1]:
                        raise CatalogError('Conflicting duplicate CVE timestamps or data.')
                    replace = new_time[1] > old_time[1]
                if replace:
                    connection.execute('INSERT OR REPLACE INTO records VALUES (?,?,?,?,?)',
                                       (identifier, record['status'], record['published'], record['modified'], body))
                    connection.execute('DELETE FROM identities WHERE cve=?', (identifier,))
                    connection.executemany('INSERT INTO identities VALUES (?,?,?,?,?)', [(*key, identifier) for key in keys])
                connection.execute('INSERT OR IGNORE INTO memberships VALUES (?,?)', (identifier, number))
                tracker.emit()
            feed_info.append(dict(feed_index=number, **stream.metadata))
            connection.execute('INSERT INTO feeds VALUES (?,?)', (number, canonical(feed_info[-1])))
        counts = {"records": 0, "input_records": tracker.records, "duplicate_records": 0,
                      "rejected_records": 0, "without_applicability": 0, "unsupported_records": 0}
        catalog_hash = hashlib.sha256()
        catalog_hash.update(canonical(feed_info).encode('utf8'))
        for status, body in connection.execute('SELECT status, body FROM records ORDER BY cve'):
            check_cancel(cancel)
            record = json.loads(body)  # Trusted normalized rows written by this build.
            counts['records'] += 1
            counts['rejected_records'] += status == 'Rejected'
            counts['without_applicability'] += all(v == 'missing' for v in record['applicability'].values())
            counts['unsupported_records'] += bool(record['gaps'])
            catalog_hash.update(body.encode('utf8'))
        counts['duplicate_records'] = counts['input_records'] - counts['records']
        info = dict(schema_version=SCHEMA_VERSION, catalog_id=catalog_hash.hexdigest(), **counts, feeds=feed_info)
        connection.execute('INSERT INTO metadata VALUES (?,?)', ('info', canonical(info)))
        connection.commit()
        connection.close()
        connection = None
        database_bytes = os.path.getsize(staging)
        if database_bytes > MAX_DB_BYTES:
            raise CatalogError('Catalog database byte budget exceeded.')
        check_cancel(cancel)
        with CatalogIndex(staging) as verified:
            if verified.info() != info:
                raise CatalogError('Catalog generation verification failed.')
            _verify_generation_integrity(verified, database_bytes, cancel)
        # Reserve the final progress event before publication: callback errors abort.
        tracker.emit('complete')
        _safe_path(target, destination=True)
        os.link(staging, target)  # Atomic and exclusive, including concurrent publishers.
        return info
    except CatalogCancelled:
        if tracker.callback:
            # A notification failure must not replace the original cancellation.
            with suppress(Exception):
                tracker.callback({"status": 'cancelled', "records": tracker.records, "expanded_bytes": tracker.expanded,
                                      "feed_index": tracker.feed, "elapsed_ms": max(0, int((time.monotonic() - tracker.start) * 1000))})
        raise
    except CatalogError:
        raise
    except (OSError, sqlite3.Error, UnicodeError, OverflowError) as exc:
        if _cancelled(cancel):
            raise CatalogCancelled('Catalog operation cancelled.') from exc
        raise CatalogError('Catalog build failed; no complete generation published.') from exc
    finally:
        if connection:
            connection.close()
        if staging:
            for suffix in ('', '-journal', '-wal', '-shm'):
                try:
                    os.unlink(staging + suffix)
                except FileNotFoundError:
                    pass


def _cancelled(cancel):
    return cancel is not None and (cancel() if callable(cancel) else cancel.is_set())


def _verify_generation_integrity(index, database_bytes, cancel):
    """Scan only the builder's closed, size/schema-verified private generation."""
    remaining = database_bytes * _BUILD_INTEGRITY_STEPS_PER_BYTE
    deadline = time.monotonic() + _BUILD_INTEGRITY_SECONDS
    cancelled = False

    def step():
        nonlocal remaining, cancelled
        cancelled = _cancelled(cancel)
        remaining -= 1000
        return cancelled or remaining < 0 or time.monotonic() >= deadline

    check_cancel(cancel)
    connection = index._connection
    connection.set_progress_handler(step, 1000)
    try:
        if connection.execute('PRAGMA quick_check').fetchone() != ('ok',):
            raise CatalogError('Catalog generation integrity failed.')
        check_cancel(cancel)
        if time.monotonic() >= deadline:
            raise CatalogError('Catalog generation integrity exceeded work budget.')
    except sqlite3.Error as exc:
        if cancelled or _cancelled(cancel):
            raise CatalogCancelled('Catalog operation cancelled.') from exc
        raise CatalogError('Catalog generation integrity failed or exceeded work budget.') from exc
    finally:
        connection.set_progress_handler(index._step, 1000)


def _controlled(method):
    @wraps(method)
    def guarded(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except CatalogError:
            raise
        except (sqlite3.Error, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, MemoryError) as exc:
            raise CatalogError('Invalid catalog data or query work budget exceeded.') from exc
    return guarded


class _LargestCVE:
    """Reverse lexical heap order so the largest retained CVE is at the root."""
    __slots__ = ('identifier',)

    def __init__(self, identifier):
        self.identifier = identifier

    def __lt__(self, other):
        return other.identifier < self.identifier


class CatalogIndex:
    """Untrusted SQLite opened readonly; all public queries validate typed results."""
    def __init__(self, path, *, expected_sha256=None, cancel=None):
        self._connection = None
        pin = hash_pin(expected_sha256)
        path = _safe_path(path)
        try:
            if path.stat().st_size > MAX_DB_BYTES:
                raise CatalogError('Catalog database byte budget exceeded.')
            if pin and _file_hash(path, cancel=cancel) != pin:
                raise CatalogError('Catalog SHA256 mismatch.')
            self._connection = sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True)
            connection = self._connection
            connection.enable_load_extension(False)
            connection.execute('PRAGMA query_only=ON')
            connection.execute('PRAGMA trusted_schema=OFF')
            connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_VALUE_BYTES + 4096)
            connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 16384)
            connection.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 64)
            connection.setlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH, 64)
            connection.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
            connection.setlimit(sqlite3.SQLITE_LIMIT_VDBE_OP, 10000)
            connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 16)
            self._budget = QUERY_STEPS
            connection.set_progress_handler(self._step, 1000)
            if (connection.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID
                    or connection.execute('PRAGMA user_version').fetchone()[0] != SCHEMA_VERSION):
                raise CatalogError('Unsupported catalog identity or schema version.')
            schema = connection.execute("SELECT type,name,sql FROM sqlite_schema ORDER BY name LIMIT 9").fetchall()
            if {name: (kind, sql) for kind, name, sql in schema} != EXPECTED_SCHEMA or len(schema) != len(EXPECTED_SCHEMA):
                raise CatalogError('Unsupported or executable catalog schema.')
            connection.set_authorizer(self._authorize)
            self._info = self.info()
        except (sqlite3.Error, OSError, UnicodeError, ValueError, TypeError, MemoryError) as exc:
            self.close()
            if isinstance(exc, CatalogError):
                raise
            raise CatalogError('Cannot open a supported readonly catalog.') from exc

    def _step(self):
        self._budget -= 1000
        return self._budget < 0

    @staticmethod
    def _authorize(action, arg1, arg2, database, source):
        if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ):
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_FUNCTION and arg2 in ('length', 'count'):
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_PRAGMA and arg1 == 'quick_check' and arg2 is None:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    def _query(self, sql, values=()):
        try:
            return self._connection.execute(sql, values)
        except (sqlite3.Error, ValueError, TypeError, MemoryError) as exc:
            raise CatalogError('Catalog query failed or exceeded work budget.') from exc

    def _reset(self):
        if self._connection is None:
            raise CatalogError('Catalog is closed.')
        self._budget = QUERY_STEPS

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    @_controlled
    def info(self):
        self._reset()
        value = self._query("SELECT value FROM metadata WHERE key='info'").fetchone()
        if value is None:
            raise CatalogError('Missing catalog metadata.')
        info = _json_body(value[0])
        count_fields = {'records', 'input_records', 'duplicate_records', 'rejected_records', 'without_applicability', 'unsupported_records'}
        if (not isinstance(info, dict) or set(info) != count_fields | {'schema_version', 'catalog_id', 'feeds'}
                or info['schema_version'] != SCHEMA_VERSION or type(info['schema_version']) is not int
                or any(type(info[k]) is not int or not 0 <= info[k] <= MAX_RECORDS for k in count_fields)
                or not isinstance(info['catalog_id'], str) or hash_pin(info['catalog_id']) != info['catalog_id'] or not isinstance(info['feeds'], list)
                or not 1 <= len(info['feeds']) <= MAX_INPUTS
                or info['input_records'] != info['records'] + info['duplicate_records']
                or any(info[k] > info['records'] for k in ('rejected_records', 'without_applicability', 'unsupported_records'))):
            raise CatalogError('Invalid catalog metadata.')
        feed_keys = {'feed_index', 'source_sha256', 'expanded_sha256', 'source_bytes', 'expanded_bytes', 'records',
                     'total_results', 'start_index', 'results_per_page', 'timestamp', 'partial', 'pin_verified'}
        for number, feed in enumerate(info['feeds']):
            if not isinstance(feed, dict) or set(feed) != feed_keys:
                raise CatalogError('Invalid feed metadata schema.')
            for key in ('feed_index', 'source_bytes', 'expanded_bytes', 'records'):
                if type(feed[key]) is not int or not 0 <= feed[key] <= 2 * 1024**3:
                    raise CatalogError('Invalid feed numeric metadata.')
            for key in ('total_results', 'start_index', 'results_per_page'):
                if feed[key] is not None and (type(feed[key]) is not int or not 0 <= feed[key] <= 10**12):
                    raise CatalogError('Invalid feed page metadata.')
            if (feed['feed_index'] != number or type(feed['partial']) is not bool or type(feed['pin_verified']) is not bool
                    or (feed['timestamp'] is not None and modified_time(feed['timestamp']) is None)):
                raise CatalogError('Invalid feed metadata types.')
            for key in ('source_sha256', 'expanded_sha256'):
                if hash_pin(feed[key]) != feed[key] or feed[key] is None:
                    raise CatalogError('Invalid source digest.')
            stored = self._query('SELECT body FROM feeds WHERE feed_index=?', (number,)).fetchone()
            if stored is None or _json_body(stored[0]) != feed:
                raise CatalogError('Inconsistent source metadata.')
        if sum(feed['records'] for feed in info['feeds']) != info['input_records']:
            raise CatalogError('Inconsistent feed record counts.')
        if self._query('SELECT count(*) FROM records').fetchone()[0] != info['records']:
            raise CatalogError('Inconsistent catalog record count.')
        return info

    def _summary(self, row):
        cve, status, published, modified = row
        cve_id(cve)
        if not isinstance(status, str) or status not in STATUSES | {'Unknown'} or any(v is not None and modified_time(v) is None for v in (published, modified)):
            raise CatalogError('Invalid catalog summary row.')
        return {"cve": cve, "status": status, "published": published, "modified": modified,
                    "reference": 'https://nvd.nist.gov/vuln/detail/' + cve}

    @_controlled
    def search(self, *, cve=None, vendor=None, product=None, limit=20, offset=0):
        self._reset()
        _bounded_int(limit, 1, 100)
        _bounded_int(offset, 0, 1000000)
        if cve is not None:
            cve_id(cve)
            if vendor is not None or product is not None:
                raise CatalogError('Search by CVE or vendor and product.')
            sql = 'SELECT cve,status,published,modified FROM records WHERE cve=? ORDER BY cve LIMIT ? OFFSET ?'
            values = (cve, limit, offset)
        elif vendor is not None or product is not None:
            if not text(vendor) or not text(product):
                raise CatalogError('Search requires literal vendor and product of 1..256 characters.')
            sql = ('SELECT r.cve,r.status,r.published,r.modified FROM records r WHERE r.cve IN '
                   '(SELECT cve FROM identities WHERE vendor=? AND product=?) ORDER BY r.cve LIMIT ? OFFSET ?')
            values = (vendor.casefold(), product.casefold(), limit, offset)
        else:
            sql, values = 'SELECT cve,status,published,modified FROM records ORDER BY cve LIMIT ? OFFSET ?', (limit, offset)
        try:
            return [self._summary(row) for row in self._query(sql, values)]
        except sqlite3.Error as exc:
            raise CatalogError('Catalog search exceeded work budget.') from exc

    def _get(self, identifier):
        result = self._query('SELECT cve,status,published,modified,body FROM records WHERE cve=?', (identifier,)).fetchone()
        if result is None:
            return None
        summary = self._summary(result[:4])
        record = _validate_record(_json_body(result[4]))
        if any(record[k] != summary[k] for k in ('cve', 'status', 'published', 'modified')):
            raise CatalogError('Inconsistent catalog record columns.')
        members = [r[0] for r in self._query('SELECT feed_index FROM memberships WHERE cve=? ORDER BY feed_index LIMIT 65', (identifier,))]
        if not members or len(members) > MAX_INPUTS or any(type(n) is not int or not 0 <= n < MAX_INPUTS for n in members):
            raise CatalogError('Invalid catalog feed membership.')
        digests = []
        for number in members:
            feed = self._query('SELECT body FROM feeds WHERE feed_index=?', (number,)).fetchone()
            if feed is None:
                raise CatalogError('Missing catalog source.')
            digest = _json_body(feed[0]).get('expanded_sha256')
            if digest is None or hash_pin(digest) != digest:
                raise CatalogError('Invalid catalog source digest.')
            digests.append(digest)
        return dict(record, catalog_id=self._info['catalog_id'], reference=summary['reference'], feed_membership=members, source_sha256=sorted(set(digests)))

    @_controlled
    def get(self, cve):
        self._reset()
        cve_id(cve)
        try:
            return self._get(cve)
        except (sqlite3.Error, UnicodeError, TypeError, AttributeError, RecursionError) as exc:
            raise CatalogError('Invalid or over-budget catalog record.') from exc

    @_controlled
    def relevant(self, identities, *, limit=50000, after=None):
        """Return a byte-bounded page; explicit truncation/work flags forbid clearance.

        Identity: {kind:'cpe',part:'a'|'o'|'h',vendor,product} or
        {kind:'cna',vendor,product}. Exact literals only; 1..8192 identities.
        ``after`` is the previous next_after CVE. Work-limited pages have no safe
        continuation; callers must narrow identities and report unexamined work.
        """
        self._reset()
        _bounded_int(limit, 1, 50000)
        if not isinstance(identities, (list, tuple)) or not 1 <= len(identities) <= 8192:
            raise CatalogError('Supply 1..8192 explicit catalog identities.')
        if after is not None:
            cve_id(after)
        queries = set()
        for identity in identities:
            if not isinstance(identity, dict) or identity.get('kind') not in ('cpe', 'cna'):
                raise CatalogError('Invalid catalog identity.')
            kind = identity['kind']
            if set(identity) != ({'kind', 'part', 'vendor', 'product'} if kind == 'cpe' else {'kind', 'vendor', 'product'}):
                raise CatalogError('Invalid catalog identity fields.')
            if not text(identity['vendor']) or not text(identity['product']):
                raise CatalogError('Invalid literal catalog identity.')
            part = identity.get('part', '')
            if kind == 'cpe' and part not in ('a', 'o', 'h'):
                raise CatalogError('Invalid catalog CPE part.')
            queries.add((kind, part, identity['vendor'].casefold(), identity['product'].casefold()))
            if part:
                queries.add(('broad', part, '', ''))
        queries.add(('broad', '*', '', ''))
        ids, largest, examined, done, work_limited = set(), [], 0, 0, False
        for key in sorted(queries):
            done += 1
            cursor = self._query('SELECT i.cve FROM identities i JOIN records r ON r.cve=i.cve '
                                 'WHERE i.kind=? AND i.part=? AND i.vendor=? AND i.product=? '
                                 "AND i.cve>? AND r.status!='Rejected' ORDER BY i.cve LIMIT ?",
                                 (*key, after or '', limit + 1))
            try:
                for (identifier,) in cursor:
                    cve_id(identifier)
                    # Retain the smallest limit+1 in O(log limit) update work;
                    # duplicates and values beyond the retained maximum are O(1).
                    if identifier not in ids:
                        if len(ids) < limit + 1:
                            ids.add(identifier)
                            heappush(largest, _LargestCVE(identifier))
                        elif identifier < largest[0].identifier:
                            removed = heapreplace(largest, _LargestCVE(identifier))
                            ids.remove(removed.identifier)
                            ids.add(identifier)
                    examined += 1
                    if examined >= MAX_IDENTITY_ROWS:
                        work_limited = True
                        break
            except sqlite3.Error as exc:
                raise CatalogError('Relevant query exceeded work budget.') from exc
            if work_limited:
                break
        records, size = [], 2
        ordered = sorted(ids)
        for identifier in ordered[:limit]:
            record = self._get(identifier)
            encoded_size = len(canonical(record).encode('utf8'))
            if size + encoded_size + bool(records) > MAX_RELEVANT_BYTES:
                if not records:
                    raise CatalogError('One record exceeds the relevant-page byte budget.')
                break
            records.append(record)
            size += encoded_size + (len(records) > 1)
        truncated = work_limited or len(ordered) > len(records)
        return {"records": records, "truncated": truncated, "next_after": records[-1]['cve'] if truncated and records and not work_limited else None,
                    "examined": examined, "identity_queries": done, "identity_queries_total": len(queries), "work_limited": work_limited}
