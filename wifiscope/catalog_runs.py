"""Explicit local SQLite audit runs: one atomic, source-bound chunk per advance."""
import copy
from datetime import datetime, timezone
from functools import wraps
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3

from .catalog_chunks import _audit_chunk
from .catalog_records import canonical
from .catalog_store import CatalogIndex, _safe_path, MAX_DB_BYTES as MAX_CATALOG_BYTES
from .catalog_stream import CatalogCancelled, hash_pin
from .catalog_run_schema import (COUNTS, TOTALS, bad, counts, decode, digest, render_page,
    source_gaps, validate_checkpoint, validate_frozen)
from .inventory import bounded_json, validate_inventory
from .case_validation import validate_report

MAX_PAGES = 4096
MAX_PAIRS = 10000000
MAX_PAYLOAD_BYTES = 512 * 1024**2
MAX_DB_BYTES = 1024**3
QUERY_STEPS = 500000000
APPLICATION_ID = 0x57535231
SCHEMA = (
    'CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID',
    'CREATE TABLE pages (number INTEGER PRIMARY KEY, body TEXT NOT NULL)',
    'CREATE TABLE pairs (asset_ordinal INTEGER NOT NULL, cve TEXT NOT NULL, applicability TEXT NOT NULL, page_number INTEGER NOT NULL, PRIMARY KEY (asset_ordinal, cve)) WITHOUT ROWID',
    'CREATE TABLE seen_cves (cve TEXT PRIMARY KEY) WITHOUT ROWID',
    'CREATE INDEX pairs_page ON pairs (page_number, asset_ordinal, cve)',
    'CREATE INDEX pairs_cve ON pairs (cve)',
)
EXPECTED_SCHEMA = {sql.split()[2]: ('index' if sql.startswith('CREATE INDEX') else 'table', sql) for sql in SCHEMA}


def _controlled(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError,
                OSError, sqlite3.Error, MemoryError):
            raise ValueError('Cannot read or update this local catalog audit run.') from None
    return wrapped


def _cancelled(cancel):
    try:
        return cancel is not None and bool(cancel() if callable(cancel) else cancel.is_set())
    except Exception:
        raise ValueError('Catalog run cancellation callback failed.') from None


def _hash_file(path, cancel=None, *, finish=False):
    path = _safe_path(path)
    if path.stat().st_size > MAX_CATALOG_BYTES:
        bad()
    digest = hashlib.sha256()
    cancelled = False
    with path.open('rb') as stream:
        size = 0
        while True:
            cancelled = _cancelled(cancel) or cancelled
            if cancelled and not finish:
                return None, True
            block = stream.read(65536)
            if not block:
                break
            size += len(block)
            if size > MAX_CATALOG_BYTES:
                bad()
            digest.update(block)
    return digest.hexdigest(), cancelled


def _path(path, *, create=False):
    path = _safe_path(path, destination=create)
    for suffix in ('-journal', '-wal', '-shm'):
        companion = Path(str(path) + suffix)
        if os.path.lexists(companion):
            if create:
                bad()
            _safe_path(companion)
            if companion.stat().st_size > MAX_DB_BYTES:
                bad()
            # Only rollback journals belong to this DELETE-mode format.
            if suffix != '-journal':
                bad()
        else:
            _safe_path(companion, destination=True)
    if not create and path.stat().st_size > MAX_DB_BYTES:
        bad()
    return path


class _Store:
    """Connection owner; schema verified before existing-file write statements."""
    def __init__(self, path, *, new=False):
        self.connection = None
        self.writable = False
        self.budget = QUERY_STEPS
        try:
            self.connection = sqlite3.connect(path.as_uri() + '?mode=rw', uri=True,
                isolation_level=None, timeout=.25)
            db = self.connection
            db.enable_load_extension(False)
            db.execute('PRAGMA trusted_schema=OFF')
            for category, value in (
                (sqlite3.SQLITE_LIMIT_LENGTH, 16 * 1024**2 + 4096),
                (sqlite3.SQLITE_LIMIT_SQL_LENGTH, 16384), (sqlite3.SQLITE_LIMIT_COLUMN, 64),
                (sqlite3.SQLITE_LIMIT_EXPR_DEPTH, 64), (sqlite3.SQLITE_LIMIT_ATTACHED, 0),
                (sqlite3.SQLITE_LIMIT_VDBE_OP, 10000), (sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 16),
                (sqlite3.SQLITE_LIMIT_COMPOUND_SELECT, 8), (sqlite3.SQLITE_LIMIT_TRIGGER_DEPTH, 0)):
                db.setlimit(category, value)
            db.set_progress_handler(self._step, 1000)
            if new:
                db.execute('PRAGMA page_size=4096')
                db.execute(f'PRAGMA application_id={APPLICATION_ID}')
                db.execute('PRAGMA user_version=1')
                for statement in SCHEMA:
                    db.execute(statement)
            self._schema()
            db.set_authorizer(self._authorize)
        except BaseException:
            self.close()
            raise

    def _step(self):
        self.budget -= 1000
        return self.budget < 0

    def _schema(self):
        db = self.connection
        if (db.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID
                or db.execute('PRAGMA user_version').fetchone()[0] != 1
                or db.execute('PRAGMA page_size').fetchone()[0] != 4096
                or db.execute('PRAGMA auto_vacuum').fetchone()[0] != 0
                or db.execute('PRAGMA encoding').fetchone()[0] != 'UTF-8'
                or db.execute('PRAGMA journal_mode').fetchone()[0] != 'delete'):
            bad()
        schema = db.execute('SELECT type,name,sql FROM sqlite_schema ORDER BY name LIMIT 7').fetchall()
        if len(schema) != len(EXPECTED_SCHEMA) or {name: (kind, sql) for kind, name, sql in schema} != EXPECTED_SCHEMA:
            bad()

    def _authorize(self, action, first, second, database, source):
        if source is not None or database not in (None, 'main'):
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_SELECT:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ and first in {'metadata', 'pages', 'pairs', 'seen_cves', 'sqlite_master'}:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_PRAGMA and second is None and first in {
                'application_id', 'user_version', 'page_size', 'auto_vacuum', 'encoding', 'journal_mode'}:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_FUNCTION and second in {'count'}:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_TRANSACTION and first in {'BEGIN', 'COMMIT', 'ROLLBACK'}:
            return sqlite3.SQLITE_OK
        if self.writable:
            if action == sqlite3.SQLITE_INSERT and first in {'metadata', 'pages', 'pairs', 'seen_cves'}:
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_UPDATE and first == 'metadata' and second == 'value':
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_PRAGMA and (
                    (first == 'journal_mode' and second == 'DELETE')
                    or (first == 'synchronous' and second == 'FULL')
                    or (first == 'max_page_count' and second == str(MAX_DB_BYTES // 4096))):
                return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    def enable_writes(self):
        self.writable = True
        self.connection.execute('PRAGMA journal_mode=DELETE')
        self.connection.execute('PRAGMA synchronous=FULL')
        self.connection.execute(f'PRAGMA max_page_count={MAX_DB_BYTES // 4096}')

    def rollback(self):
        if self.connection is not None and self.connection.in_transaction:
            try:
                self.connection.execute('ROLLBACK')
            except sqlite3.Error:
                pass  # close also discards a transaction; preserve the primary failure.

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None


def _page_data(db, frozen, number):
    row = db.execute('SELECT body FROM pages WHERE number=?', (number,)).fetchone()
    if row is None:
        bad()
    payload = decode(row[0])
    if (not isinstance(payload.get('results'), list) or len(payload['results']) > frozen['page_size']
            or sum(len(canonical(r).encode('utf8')) for r in payload['results']) > 2 * 1024**2):
        bad()
    pairs = db.execute('SELECT asset_ordinal,cve,applicability FROM pairs WHERE page_number=? ORDER BY asset_ordinal,cve LIMIT 50001', (number,)).fetchall()
    if not pairs or len(pairs) > 50000:
        bad()
    counts(payload['summary'])
    from .catalog_audit_schema import CVE
    from .catalog_chunks import _cursor
    _cursor(payload['cursor'], len(frozen['inventory']['assets']))
    expected = dict.fromkeys(('evaluated_pairs', 'true_pairs', 'unknown_pairs', 'not_matched_pairs', 'retained_results'), 0)
    result_pairs = []
    for ordinal, cve, outcome in pairs:
        if (type(ordinal) is not int or not 0 <= ordinal < len(frozen['inventory']['assets'])
                or not isinstance(cve, str) or not CVE.fullmatch(cve) or outcome not in ('true', 'false', 'unknown')):
            bad()
        expected['evaluated_pairs'] += 1
        expected[{'true': 'true_pairs', 'false': 'not_matched_pairs', 'unknown': 'unknown_pairs'}[outcome]] += 1
        if outcome != 'false':
            result_pairs.append((frozen['inventory']['assets'][ordinal]['id'], cve, outcome))
            expected['retained_results'] += 1
    if any(payload['summary'][k] != v for k, v in expected.items()):
        bad()
    if [(r['asset_id'], r['cve'], r['applicability']) for r in payload['results']] != result_pairs:
        bad()
    if (_position(payload['cursor']) < pairs[-1][:2]
            or payload['cursor']['after'] is not None and _position(payload['cursor']) != pairs[-1][:2]):
        bad()
    return payload, pairs, len(row[0].encode('utf8'))


def _position(cursor):
    return cursor['asset_ordinal'], cursor['after'] or ''


def _load(db):
    rows = db.execute('SELECT key,value FROM metadata ORDER BY key LIMIT 3').fetchall()
    if len(rows) != 2 or [r[0] for r in rows] != ['checkpoint', 'frozen']:
        bad()
    checkpoint, frozen = (decode(r[1]) for r in rows)
    validate_frozen(frozen)
    validate_checkpoint(checkpoint, frozen)
    status = checkpoint['status']
    if db.execute('SELECT count(*) FROM pages').fetchone()[0] != status['page_count']:
        bad()
    totals = dict.fromkeys(COUNTS, 0)
    totals.update(checkpoint['unpaged_work'])
    payload_bytes = 0
    previous = (0, '')
    for number in range(1, status['page_count'] + 1):
        payload, pairs, size = _page_data(db, frozen, number)
        if pairs[0][:2] <= previous:
            bad()
        previous = _position(payload['cursor'])
        payload_bytes += size
        for key in COUNTS:
            totals[key] += payload['summary'][key]
        render_page(frozen, payload, status, number, len({p[1] for p in pairs}))
    if ((checkpoint['unpaged_cursor'] is None or checkpoint['cursor']['after'] is not None)
            and previous != _position(checkpoint['cursor'])
            or any(totals[k] != status['cumulative'][k] for k in COUNTS)
            or payload_bytes != checkpoint['payload_bytes'] or previous > _position(checkpoint['cursor'])
            or db.execute('SELECT count(*) FROM pairs').fetchone()[0] != totals['evaluated_pairs']
            or db.execute('SELECT count(*) FROM seen_cves').fetchone()[0] != status['cumulative']['relevant_records']
            or db.execute('SELECT cve FROM pairs EXCEPT SELECT cve FROM seen_cves LIMIT 1').fetchone()
            or db.execute('SELECT cve FROM seen_cves EXCEPT SELECT cve FROM pairs LIMIT 1').fetchone()):
        bad()
    return frozen, checkpoint


class _RunReader:
    """Task 3 interface: owned values from one validated, consistent transaction."""
    def __init__(self, run_path):
        self.path = run_path
        self.store = None

    @_controlled
    def __enter__(self):
        try:
            self.store = _Store(_path(self.path))
            self.store.connection.execute('BEGIN')
            self.store._schema()
            self.frozen, self.checkpoint = _load(self.store.connection)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        if self.store is not None:
            self.store.rollback()
            self.store.close()
            self.store = None

    @_controlled
    def status(self):
        if self.store is None:
            bad()
        return copy.deepcopy(self.checkpoint['status'])

    @_controlled
    def read_page(self, number):
        if (self.store is None or type(number) is not int
                or not 1 <= number <= self.checkpoint['status']['page_count']):
            bad()
        payload, pairs, _ = _page_data(self.store.connection, self.frozen, number)
        return render_page(self.frozen, payload, self.checkpoint['status'], number, len({p[1] for p in pairs}))


@_controlled
def run_status(run_path):
    with _RunReader(run_path) as reader:
        return reader.status()


@_controlled
def read_run_page(run_path, page_number):
    with _RunReader(run_path) as reader:
        return reader.read_page(page_number)


@_controlled
def create_run(destination, report, inventory, catalog_path, *, expected_sha256=None,
               store_raw_identifiers=False, page_size=256, cancel=None):
    if store_raw_identifiers is not True:
        raise ValueError('Explicit local raw-identifier storage consent is required.')
    bounded_json(report, max_depth=64, max_nodes=200000, allow_numbers=True)
    validate_report(report)
    destination = _path(destination, create=True)
    pin = hash_pin(expected_sha256)
    fingerprint, cancelled = _hash_file(catalog_path, cancel)
    if cancelled or pin is not None and fingerprint != pin:
        bad()
    with CatalogIndex(catalog_path, expected_sha256=fingerprint, cancel=lambda: _cancelled(cancel)) as index:
        frozen = dict(report=copy.deepcopy(report), inventory=validate_inventory(inventory),
            report_sha256=digest(report), inventory_sha256='', synthetic=False,
            run_engine_version='1', matching_engine_version='1', page_size=page_size,
            catalog_sha256=fingerprint, catalog=index.info())
        frozen['inventory_sha256'] = digest(frozen['inventory'])
        frozen['synthetic'] = report.get('synthetic', False) or any(
            c['source'] == 'synthetic' for a in frozen['inventory']['assets'] for c in a['components'])
        validate_frozen(frozen)
        gaps = source_gaps(frozen)
        status = dict(run_id=secrets.token_hex(16), state='ready', stop_reason='ready', page_count=0,
            computation_complete=False, source_partial=bool(gaps & {'catalog-input-partial', 'inventory-input-partial'}),
            cumulative=dict.fromkeys(TOTALS, 0), unexamined_pairs=None, gaps=sorted(gaps))
        checkpoint = dict(status=status, cursor=dict(asset_ordinal=0, after=None), payload_bytes=0, unpaged_cursor=None,
                          unpaged_work=dict.fromkeys(('predicates', 'identity_queries', 'index_hits'), 0))
        validate_checkpoint(checkpoint, frozen)
        frozen_body, checkpoint_body = canonical(frozen), canonical(checkpoint)
        # Creation must satisfy the same finite JSON admission as reopening.
        decode(frozen_body)
        decode(checkpoint_body)
        last_hash, cancelled = _hash_file(catalog_path, cancel)
        if cancelled or last_hash != fingerprint or index.info() != frozen['catalog']:
            bad()
    # Exclusive ownership precedes SQLite initialization; never touch a preexisting file.
    with destination.open('xb'):
        pass
    store = None
    try:
        store = _Store(destination, new=True)
        store.enable_writes()
        store.connection.execute('BEGIN IMMEDIATE')
        store.connection.executemany('INSERT INTO metadata (key,value) VALUES (?,?)',
            [('frozen', frozen_body), ('checkpoint', checkpoint_body)])
        store.connection.execute('COMMIT')
    except BaseException:
        if store is not None:
            store.rollback()
            store.close()
        # Only the new main file is owned here; SQLite owns its journal recovery.
        destination.unlink(missing_ok=True)
        raise
    finally:
        if store is not None:
            store.close()
    return copy.deepcopy(status)


@_controlled
def advance_run(run_path, catalog_path, *, cancel=None, progress=None):
    store = _Store(_path(run_path))
    try:
        store.enable_writes()
        db = store.connection
        db.execute('BEGIN IMMEDIATE')
        store._schema()
        frozen, checkpoint = _load(db)
        status = checkpoint['status']
        if status['state'] in ('complete', 'blocked', 'limited') or _cancelled(cancel):
            store.rollback()
            return copy.deepcopy(status)
        fingerprint, cancelled = _hash_file(catalog_path, cancel)
        if cancelled:
            store.rollback()
            return copy.deepcopy(status)
        if fingerprint != frozen['catalog_sha256']:
            bad()
        try:
            index = CatalogIndex(catalog_path, expected_sha256=fingerprint, cancel=lambda: _cancelled(cancel))
        except CatalogCancelled:
            store.rollback()
            return copy.deepcopy(status)
        with index:
            if index.info() != frozen['catalog']:
                bad()
            chunk = _audit_chunk(frozen['report'], frozen['inventory'], index,
                cursor=checkpoint['cursor'], page_size=frozen['page_size'], cancel=cancel, progress=progress)
            last_hash, cancelled = _hash_file(catalog_path, cancel, finish=True)
            if last_hash != fingerprint or index.info() != frozen['catalog']:
                bad()
        if cancelled and not chunk['computation_complete']:
            chunk['stop_reason'] = 'cancelled'
            chunk['gaps'] = sorted(set(chunk['gaps']) | {'audit-cancelled'})
        if not chunk['pairs'] and chunk['stop_reason'] == 'cancelled':
            store.rollback()
            return copy.deepcopy(status)
        payload = dict(summary=chunk['summary'], results=chunk['results'], gaps=chunk['gaps'],
                       cursor=chunk['cursor'], evaluated_at=datetime.now(timezone.utc).isoformat())
        body = canonical(payload)
        size = len(body.encode('utf8')) if chunk['pairs'] else 0
        limit = None
        if chunk['pairs']:
            if status['page_count'] >= MAX_PAGES:
                limit = 'run-page-limit'
            elif status['cumulative']['evaluated_pairs'] + len(chunk['pairs']) > MAX_PAIRS:
                limit = 'run-pair-limit'
            elif checkpoint['payload_bytes'] + size > MAX_PAYLOAD_BYTES:
                limit = 'run-byte-limit'
        if limit:
            status.update(state='limited', stop_reason=limit)
            status['gaps'] = sorted(set(status['gaps']) | {'audit-work-limit'})
        else:
            if chunk['pairs']:
                number = status['page_count'] + 1
                db.execute('INSERT INTO pages (number,body) VALUES (?,?)', (number, body))
                db.executemany('INSERT INTO pairs (asset_ordinal,cve,applicability,page_number) VALUES (?,?,?,?)',
                    [(p['asset_ordinal'], p['cve'], p['applicability'], number) for p in chunk['pairs']])
                db.executemany('INSERT OR IGNORE INTO seen_cves (cve) VALUES (?)', [(p['cve'],) for p in chunk['pairs']])
                for key in COUNTS:
                    status['cumulative'][key] += chunk['summary'][key]
                status['cumulative']['relevant_records'] = db.execute('SELECT count(*) FROM seen_cves').fetchone()[0]
                status['page_count'] = number
                checkpoint['payload_bytes'] += size
                checkpoint['unpaged_cursor'] = None
            else:
                checkpoint['unpaged_cursor'] = chunk['cursor']
                for key in checkpoint['unpaged_work']:
                    checkpoint['unpaged_work'][key] += chunk['summary'][key]
                    status['cumulative'][key] += chunk['summary'][key]
            checkpoint['cursor'] = chunk['cursor']
            reason = chunk['stop_reason']
            status.update(state='complete' if chunk['computation_complete'] else 'blocked' if reason.startswith('blocked-') else 'paused',
                          stop_reason=reason, computation_complete=chunk['computation_complete'], gaps=chunk['gaps'])
            status['unexamined_pairs'] = 0 if status['computation_complete'] and not status['source_partial'] else None
        validate_checkpoint(checkpoint, frozen)
        if chunk['pairs'] and not limit:
            render_page(frozen, payload, status, status['page_count'], len({p['cve'] for p in chunk['pairs']}))
        db.execute("UPDATE metadata SET value=? WHERE key='checkpoint'", (canonical(checkpoint),))
        db.execute('COMMIT')
        return copy.deepcopy(status)
    except BaseException:
        store.rollback()
        raise
    finally:
        store.close()


def export_run(run_path, destination, *, include_identifiers=False, cancel=None):
    """Export a consistent whole-run bundle without loading it at startup."""
    from .catalog_run_export import export_run as write_bundle
    return write_bundle(run_path, destination, include_identifiers=include_identifiers, cancel=cancel)
