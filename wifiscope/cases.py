"""Immutable local SQLite snapshots and a recomputable SHA256 event chain.

The chain is not a signature. Keep a trusted external head receipt if suffix
truncation or whole-history replacement must be detected. No database on import.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from .case_validation import canonical, validate_report, MAX_BYTES
from .reports import prepare_export

STATUSES = frozenset(('open', 'investigating', 'accepted-risk', 'resolved'))
LIMITATIONS = ('This local recomputable hash chain is not a signature. A trusted external head is required '
               'to detect suffix truncation or whole-history replacement. Default snapshots use independent '
               'pseudonyms and cannot reliably correlate identities across snapshots. Windows ACLs are not guaranteed.')


def _hash(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _page(limit, offset):
    if type(limit) is not int or not 1 <= limit <= 1000 or type(offset) is not int or offset < 0:
        raise ValueError('History requires limit 1..1000 and offset >=0.')


def _finding_ids(report):
    rows = list(report.get('findings', []))
    investigation = report.get('investigation')
    if isinstance(investigation, dict):
        rows.extend(investigation.get('findings', []))
    return {row['id'] for row in rows if isinstance(row, dict) and isinstance(row.get('id'), str)}


class CaseStore:
    def __init__(self, path):
        self.path = Path(path)
        self._db = None
        try:
            # Reserve with private POSIX mode before SQLite opens the new file.
            try:
                descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
            self._db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            self._db.row_factory = sqlite3.Row
            self._db.execute('PRAGMA foreign_keys=ON')
            with self._transaction():
                version = self._db.execute('PRAGMA user_version').fetchone()[0]
                tables = {r[0] for r in self._db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
                if version == 0 and not tables:
                    self._db.execute('CREATE TABLE snapshots (id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, identifiers_included INTEGER NOT NULL, report TEXT NOT NULL, report_hash TEXT NOT NULL)')
                    self._db.execute('CREATE TABLE events (seq INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, action TEXT NOT NULL, payload TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL)')
                    self._db.execute('PRAGMA user_version=1')
                elif version != 1 or tables != {'snapshots', 'events'}:
                    raise ValueError('Unsupported case database schema; preserve the file and choose a compatible database.')
                self._db.execute('SELECT id, timestamp, identifiers_included, report, report_hash FROM snapshots LIMIT 0')
                self._db.execute('SELECT seq, timestamp, action, payload, prev_hash, hash FROM events LIMIT 0')
                if self._db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                    raise ValueError('Corrupt case database; preserve it and restore a trusted backup.')
        except (sqlite3.Error, OSError, ValueError) as exc:
            self.close()
            raise ValueError('Cannot open case database; check the path, permissions, schema and backup. Preserve the original file.') from exc

    @contextmanager
    def _transaction(self, write=True):
        if self._db is None:
            raise ValueError('Case database is closed.')
        own = not self._db.in_transaction
        if own:
            self._db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        try:
            yield
            if own:
                self._db.commit()
        except BaseException:
            if own:
                self._db.rollback()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def add_snapshot(self, report, *, include_identifiers=False):
        if type(include_identifiers) is not bool:
            raise ValueError('include_identifiers must be a boolean retention choice.')
        validate_report(report)
        projected = prepare_export(report, include_identifiers)
        retained = projected['identifiers_included']
        serialized = validate_report(projected)
        stamp = _now()
        with self._transaction():
            self._require_valid()
            cursor = self._db.execute('INSERT INTO snapshots(timestamp,identifiers_included,report,report_hash) VALUES(?,?,?,?)',
                (stamp, int(retained), serialized, _hash(serialized)))
            snapshot_id = cursor.lastrowid
            self._append('snapshot', dict(snapshot_id=snapshot_id, report_hash=_hash(serialized),
                identifiers_included=retained, timestamp=stamp))
        return snapshot_id

    def _append(self, action, payload):
        row = self._db.execute('SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1').fetchone()
        seq, previous = (row['seq'] + 1, row['hash']) if row else (1, '')
        event = dict(seq=seq, timestamp=_now(), action=action, payload=payload, prev_hash=previous)
        self._db.execute('INSERT INTO events VALUES(?,?,?,?,?,?)',
            (seq, event['timestamp'], action, canonical(payload), previous, _hash(canonical(event))))
        return seq

    def _require_valid(self):
        if not self.verify()['ok']:
            raise ValueError('Case database verification failed; preserve history and inspect verify() before appending.')

    def snapshots(self, limit=100, offset=0):
        _page(limit, offset)
        with self._transaction(False):
            rows = self._db.execute('SELECT id,timestamp,identifiers_included,report FROM snapshots ORDER BY id LIMIT ? OFFSET ?', (limit, offset))
            result = []
            for row in rows:
                report = self._decode(row['report'])
                investigation = report.get('investigation', {}) if isinstance(report, dict) else None
                summary = investigation.get('summary', {}) if isinstance(investigation, dict) else None
                if not isinstance(summary, dict):
                    raise ValueError('Invalid snapshot shape in case database; preserve history and inspect the database.')
                result.append(dict(id=row['id'], timestamp=row['timestamp'], identifiers_included=bool(row['identifiers_included']), summary=summary))
            return result

    @staticmethod
    def _decode(serialized):
        if not isinstance(serialized, str) or len(serialized.encode('utf-8')) > MAX_BYTES:
            raise ValueError('Invalid or oversized case database record; preserve and inspect the database.')
        try:
            return json.loads(serialized)
        except (ValueError, RecursionError) as exc:
            raise ValueError('Invalid JSON in case database; preserve and inspect the database.') from exc

    def load_snapshot(self, snapshot_id):
        if type(snapshot_id) is not int or snapshot_id < 1:
            raise ValueError('A persisted positive snapshot ID is required.')
        with self._transaction(False):
            self._require_valid()
            row = self._db.execute('SELECT report FROM snapshots WHERE id=?', (snapshot_id,)).fetchone()
            if row is None:
                raise ValueError('Unknown case snapshot ID.')
            return self._decode(row['report'])

    def triage(self, finding_id, status, note='', *, snapshot_id=None):
        if not isinstance(finding_id, str) or not finding_id or len(finding_id) > 4096:
            raise ValueError('A known stored finding ID is required.')
        if not isinstance(status, str) or status not in STATUSES:
            raise ValueError('Triage status must be open, investigating, accepted-risk or resolved.')
        if not isinstance(note, str) or len(note) > 2000:
            raise ValueError('Local triage notes must be at most 2000 characters.')
        with self._transaction():
            self._require_valid()
            if snapshot_id is None:
                matches = []
                for row in self._db.execute('SELECT id,report FROM snapshots ORDER BY id'):
                    if finding_id in _finding_ids(self._decode(row['report'])):
                        matches.append(row['id'])
                        if len(matches) > 1:
                            break
                if len(matches) != 1:
                    raise ValueError('Supply an explicit snapshot_id with this stored finding ID.')
                snapshot_id = matches[0]
            stored = self.load_snapshot(snapshot_id)
            if finding_id not in _finding_ids(stored):
                raise ValueError('Finding ID does not exist inside the selected stored snapshot.')
            return self._append('triage', dict(snapshot_id=snapshot_id, finding_id=finding_id, status=status, note=note))

    def events(self, limit=100, offset=0):
        _page(limit, offset)
        with self._transaction(False):
            return [dict(dict(row), payload=self._decode(row['payload'])) for row in
                self._db.execute('SELECT * FROM events ORDER BY seq LIMIT ? OFFSET ?', (limit, offset))]

    def triage_state(self, *, snapshot_id=None, limit=100, offset=0):
        _page(limit, offset)
        with self._transaction(False):
            self._require_valid()
            if snapshot_id is None:
                row = self._db.execute('SELECT id FROM snapshots ORDER BY id DESC LIMIT 1').fetchone()
                if row is None:
                    return {}
                snapshot_id = row['id']
            self.load_snapshot(snapshot_id)
            # Latest state per finding, ordered by its most recent event. Stream
            # past the offset; never build an unbounded dictionary of note text.
            state, seen = {}, set()
            for row in self._db.execute("SELECT payload FROM events WHERE action='triage' ORDER BY seq DESC"):
                payload = self._decode(row['payload'])
                identifier = payload['finding_id']
                if payload['snapshot_id'] != snapshot_id or identifier in seen:
                    continue
                seen.add(identifier)
                if len(seen) <= offset:
                    continue
                state[identifier] = dict(status=payload['status'], note=payload['note'], snapshot_id=snapshot_id)
                if len(state) == limit:
                    break
            return state

    def verify(self, expected_head=None):
        if expected_head is not None and (not isinstance(expected_head, str) or len(expected_head) not in (0, 64)):
            raise ValueError('Expected head must be a SHA256 receipt or empty genesis head.')
        checked, head = 0, ''
        problem = None
        try:
            with self._transaction(False):
                if self._db.execute('PRAGMA user_version').fetchone()[0] != 1:
                    raise ValueError('Invalid case schema version.')
                snapshot_count = 0
                for row in self._db.execute('SELECT seq,timestamp,action,payload,prev_hash,hash FROM events ORDER BY seq'):
                    if row['seq'] != checked + 1:
                        problem = 'sequence-mismatch'
                        break
                    payload = self._decode(row['payload'])
                    event = dict(seq=row['seq'], timestamp=row['timestamp'], action=row['action'], payload=payload, prev_hash=row['prev_hash'])
                    if row['prev_hash'] != head or _hash(canonical(event)) != row['hash']:
                        problem = 'event-hash-mismatch'
                        break
                    if not isinstance(payload, dict):
                        problem = 'invalid-record'
                        break
                    if row['action'] == 'snapshot':
                        stored = self._db.execute('SELECT * FROM snapshots WHERE id=?', (payload.get('snapshot_id'),)).fetchone()
                        if (payload.get('snapshot_id') != snapshot_count + 1 or stored is None or not isinstance(stored['report'], str) or len(stored['report'].encode('utf-8')) > MAX_BYTES
                            or _hash(stored['report']) != stored['report_hash'] or stored['report_hash'] != payload.get('report_hash')
                            or stored['timestamp'] != payload.get('timestamp') or stored['identifiers_included'] not in (0, 1)
                            or type(payload.get('identifiers_included')) is not bool
                            or bool(stored['identifiers_included']) != payload.get('identifiers_included')):
                            problem = 'snapshot-mismatch'
                            break
                        if validate_report(self._decode(stored['report'])) != stored['report']:
                            problem = 'snapshot-mismatch'
                            break
                        if self._decode(stored['report']).get('identifiers_included') is not bool(stored['identifiers_included']):
                            problem = 'snapshot-mismatch'
                            break
                        snapshot_count += 1
                    elif row['action'] == 'triage':
                        stored = self._db.execute('SELECT report FROM snapshots WHERE id=?', (payload.get('snapshot_id'),)).fetchone()
                        if (stored is None or payload.get('finding_id') not in _finding_ids(self._decode(stored['report']))
                            or payload.get('status') not in STATUSES or not isinstance(payload.get('note'), str) or len(payload['note']) > 2000):
                            problem = 'triage-mismatch'
                            break
                    else:
                        problem = 'unknown-action'
                        break
                    checked += 1
                    head = row['hash']
                if problem is None and snapshot_count != self._db.execute('SELECT COUNT(*) FROM snapshots').fetchone()[0]:
                    problem = 'snapshot-mismatch'
                if problem is None and expected_head is not None and expected_head != head:
                    problem = 'head-mismatch'
        except (sqlite3.Error, ValueError, TypeError, KeyError, RecursionError):
            problem = 'invalid-record'
        return dict(ok=problem is None, checked_events=checked, head=head, problem=problem, limitations=LIMITATIONS)

    def close(self):
        if self._db is not None:
            self._db.close()
            self._db = None
