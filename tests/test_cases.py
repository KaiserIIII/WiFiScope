import concurrent.futures
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from wifiscope.cases import CaseStore
from wifiscope.reports import prepare_export
from wifiscope.demo import demo_report


def report():
    return {'schema_version': 1, 'wifi': [{'ssid': 'PRIVATE', 'bssid': 'aa:bb:cc:dd:ee:ff'}],
            'investigation': {'findings': [{'id': 'finding-private', 'code': 'packet-http', 'status': 'observed',
                'evidence': {'address': '192.0.2.1'}, 'note': 'DO NOT EXPORT'}]}, 'note': 'DO NOT EXPORT'}


class CaseTests(unittest.TestCase):
    def test_complete_shared_demo_report_saves_and_isolated_snapshots_do_not_correlate(self):
        with CaseStore(self.path) as store:
            left = store.add_snapshot(demo_report())
            right = store.add_snapshot(demo_report())
            left_report = store.load_snapshot(left)
            right_report = store.load_snapshot(right)
            self.assertNotEqual(left_report['investigation']['findings'][0]['id'], right_report['investigation']['findings'][0]['id'])
            self.assertIn('packet_analysis', left_report)
            self.assertTrue(store.verify()['ok'])

    def test_typed_packet_and_nested_structure_validation(self):
        invalid = [{'packet_analysis': {'packets': 'one'}}, {'packet_analysis': {'endpoints': 'wrong'}},
                   {'packet_analysis': {'conversations': [{'src_port': 65536}]}},
                   {'packet_analysis': {'protocol_counts': {'tcp': 'one'}}},
                   {'investigation': {'findings': 'wrong'}}, {'gaps': 'wrong'},
                   {'packet_analysis': {'packets': -1}}, {'run': {'planned_hosts': True}}]
        with CaseStore(self.path) as store:
            for extra in invalid:
                with self.subTest(extra=extra), self.assertRaises(ValueError):
                    store.add_snapshot(dict(schema_version=1, **extra))
            self.assertEqual(store.snapshots(), [])

    def test_external_connection_schema_change_is_detected_on_verify(self):
        with CaseStore(self.path) as store:
            store.add_snapshot(report())
            with closing(sqlite3.connect(self.path)) as connection, connection:
                connection.execute('PRAGMA user_version=2')
            self.assertFalse(store.verify()['ok'])

    def test_snapshot_listing_rejects_corrupt_json_shapes_and_preserves_history(self):
        shapes = [[], None, 'PRIVATE-CORRUPT-REPORT', {'investigation': None}, {'investigation': []},
                  {'investigation': {'summary': None}}, {'investigation': {'summary': []}},
                  {'investigation': {'summary': 'PRIVATE-CORRUPT-SUMMARY'}}, {'investigation': {'summary': 3}}]
        for index, shape in enumerate(shapes):
            with self.subTest(shape=shape):
                path = Path(self.directory.name) / f'shape-{index}.db'
                with CaseStore(path) as store:
                    store.add_snapshot(report())
                    sid = store.add_snapshot(report())
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute('UPDATE snapshots SET report=? WHERE id=?', (json.dumps(shape), sid))
                    snapshots_before = connection.execute('SELECT * FROM snapshots ORDER BY id').fetchall()
                    events_before = connection.execute('SELECT * FROM events ORDER BY seq').fetchall()
                with CaseStore(path) as store:
                    self.assertEqual(store.snapshots(limit=1)[0]['id'], 1)
                    with self.assertRaisesRegex(ValueError, 'case database.*[Pp]reserve') as caught:
                        store.snapshots(limit=1, offset=1)
                    self.assertLessEqual(len(str(caught.exception)), 160)
                    self.assertNotIn('PRIVATE-CORRUPT', str(caught.exception))
                    self.assertEqual(store.verify()['problem'], 'snapshot-mismatch')
                with closing(sqlite3.connect(path)) as connection:
                    self.assertEqual(connection.execute('SELECT * FROM snapshots ORDER BY id').fetchall(), snapshots_before)
                    self.assertEqual(connection.execute('SELECT * FROM events ORDER BY seq').fetchall(), events_before)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'case.db'

    def test_immutable_private_snapshot_triage_reopen_and_receipt(self):
        original = report()
        with CaseStore(self.path) as store:
            sid = store.add_snapshot(original)
            stored = store.load_snapshot(sid)
            fid = stored['investigation']['findings'][0]['id']
            self.assertNotEqual(fid, 'finding-private')
            self.assertNotIn('PRIVATE', json.dumps(stored))
            self.assertNotIn('DO NOT EXPORT', json.dumps(stored))
            store.triage(fid, 'investigating', 'LOCAL SECRET', snapshot_id=sid)
            self.assertEqual(store.load_snapshot(sid), stored)
            self.assertEqual(store.triage_state(snapshot_id=sid)[fid]['note'], 'LOCAL SECRET')
            self.assertNotIn('LOCAL SECRET', json.dumps(prepare_export(dict(stored, case=store.events()), True)))
            receipt = store.verify()['head']
            self.assertTrue(store.verify(receipt)['ok'])
            self.assertIn('not a signature', store.verify()['limitations'])
        with CaseStore(self.path) as store:
            self.assertEqual(store.verify(receipt)['head'], receipt)
            self.assertEqual(store.triage_state()[fid]['status'], 'investigating')
            raw_sid = store.add_snapshot(original, include_identifiers=True)
            self.assertEqual(store.load_snapshot(raw_sid)['wifi'][0]['ssid'], 'PRIVATE')
            self.assertEqual(store.triage_state(), {})
        self.assertIn('note', original)

    def test_triage_requires_known_snapshot_and_status_and_bounded_note(self):
        with CaseStore(self.path) as store:
            sid = store.add_snapshot(report(), include_identifiers=True)
            for status in ('unknown', '', 'observed'):
                with self.assertRaises(ValueError):
                    store.triage('finding-private', status, snapshot_id=sid)
            for kwargs in ({'finding_id': 'unknown', 'status': 'open', 'snapshot_id': sid},
                           {'finding_id': 'finding-private', 'status': 'open', 'snapshot_id': 999},
                           {'finding_id': 'finding-private', 'status': 'open', 'note': 'x' * 2001, 'snapshot_id': sid}):
                with self.assertRaises(ValueError):
                    store.triage(**kwargs)
            for status in ('open', 'investigating', 'accepted-risk', 'resolved'):
                store.triage('finding-private', status, snapshot_id=sid)
            store.add_snapshot(report(), include_identifiers=True)
            with self.assertRaises(ValueError):
                store.triage('finding-private', 'open')
            self.assertEqual(store.triage_state(snapshot_id=sid)['finding-private']['status'], 'resolved')

    def test_paged_history_and_triage_state(self):
        with CaseStore(self.path) as store:
            for n in range(4):
                sid = store.add_snapshot(report(), include_identifiers=True)
                store.triage('finding-private', 'open', str(n), snapshot_id=sid)
            self.assertEqual([s['id'] for s in store.snapshots(limit=2, offset=1)], [2, 3])
            self.assertEqual([e['seq'] for e in store.events(limit=2, offset=2)], [3, 4])
            self.assertEqual(store.triage_state(snapshot_id=1, limit=1, offset=1), {})
            for method in (store.events, store.snapshots, store.triage_state):
                for kwargs in ({'limit': 0}, {'limit': 1001}, {'offset': -1}, {'limit': True}):
                    with self.assertRaises(ValueError):
                        method(**kwargs)
            self.assertEqual(store.verify()['checked_events'], 8)

    def test_triage_paging_pages_latest_states_without_empty_untriaged_slots(self):
        data = dict(schema_version=1, investigation=dict(findings=[dict(id=name, code='packet-http') for name in ('a', 'z')]))
        with CaseStore(self.path) as store:
            sid = store.add_snapshot(data, include_identifiers=True)
            store.triage('z', 'open', snapshot_id=sid)
            self.assertEqual(list(store.triage_state(snapshot_id=sid, limit=1)), ['z'])
            store.triage('a', 'open', snapshot_id=sid)
            store.triage('z', 'resolved', snapshot_id=sid)
            self.assertEqual(store.triage_state(snapshot_id=sid, limit=1)['z']['status'], 'resolved')
            self.assertEqual(list(store.triage_state(snapshot_id=sid, limit=1, offset=1)), ['a'])

    def test_reordered_events_and_snapshot_association_are_detected(self):
        with CaseStore(self.path) as store:
            sid = store.add_snapshot(report(), include_identifiers=True)
            store.triage('finding-private', 'open', snapshot_id=sid)
            with closing(sqlite3.connect(self.path)) as connection, connection:
                connection.execute('UPDATE events SET seq=99 WHERE seq=1')
                connection.execute('UPDATE events SET seq=1 WHERE seq=2')
                connection.execute('UPDATE events SET seq=2 WHERE seq=99')
            self.assertEqual(store.verify()['problem'], 'event-hash-mismatch')
        second = Path(self.directory.name) / 'association.db'
        with CaseStore(second) as store:
            store.add_snapshot(report())
            with closing(sqlite3.connect(second)) as connection, connection:
                connection.execute("UPDATE snapshots SET report_hash=?", ('0' * 64,))
            self.assertEqual(store.verify()['problem'], 'snapshot-mismatch')

    def test_verify_rejects_invalid_retention_flag_and_malformed_chained_payload(self):
        with CaseStore(self.path) as store:
            store.add_snapshot(report(), include_identifiers=True)
            with closing(sqlite3.connect(self.path)) as connection, connection:
                connection.execute('UPDATE snapshots SET identifiers_included=2')
            self.assertFalse(store.verify()['ok'])
        other = Path(self.directory.name) / 'malformed.db'
        with CaseStore(other) as store:
            store.add_snapshot(report())
            event = store.events()[0]
            event.pop('hash')
            event['payload'] = []
            encoded = json.dumps(event, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
            with closing(sqlite3.connect(other)) as connection, connection:
                connection.execute('UPDATE events SET payload=?,hash=?', ('[]', hashlib.sha256(encoded.encode()).hexdigest()))
            self.assertFalse(store.verify()['ok'])

    def test_changed_snapshot_event_middle_and_suffix_deletion(self):
        for change, code in (("UPDATE snapshots SET report='{}' WHERE id=1", 'snapshot-mismatch'),
                             ("UPDATE events SET payload='{}' WHERE seq=2", 'event-hash-mismatch'),
                             ('DELETE FROM events WHERE seq=2', 'sequence-mismatch'),
                             ('DELETE FROM events WHERE seq=3', 'head-mismatch')):
            path = Path(self.directory.name) / (code + '.db')
            with CaseStore(path) as store:
                sid = store.add_snapshot(report(), include_identifiers=True)
                store.triage('finding-private', 'open', snapshot_id=sid)
                store.triage('finding-private', 'resolved', snapshot_id=sid)
                head = store.verify()['head']
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute(change)
                self.assertEqual(store.verify(expected_head=head)['problem'], code)
                self.assertFalse(store.verify(expected_head=head)['ok'])
                if code != 'head-mismatch':
                    with self.assertRaisesRegex(ValueError, 'verification failed'):
                        store.triage_state(snapshot_id=sid)
                    with self.assertRaisesRegex(ValueError, 'verification failed'):
                        store.triage('finding-private', 'open', snapshot_id=sid)

    def test_snapshot_type_size_depth_guards_leave_no_failed_records(self):
        deep = {}
        cursor = deep
        for _ in range(65):
            cursor['nested'] = {}
            cursor = cursor['nested']
        invalid = [{}, {'schema_version': 2}, {'schema_version': 1, 'wifi': 'wrong'},
                   {'schema_version': 1, 'run': {'planned_hosts': float('nan')}},
                   {'schema_version': 1, 'wifi': [{'channel': 'wrong'}]},
                   {'schema_version': 1, 'unknown': 'x' * (16 * 1024 * 1024)}, dict(deep, schema_version=1)]
        with CaseStore(self.path) as store:
            for item in invalid:
                with self.subTest(item=list(item)), self.assertRaises(ValueError):
                    store.add_snapshot(item)
            self.assertEqual(store.events(), [])

    def test_concurrent_writers_and_bad_database_error(self):
        with CaseStore(self.path):
            pass
        def write(_):
            with CaseStore(self.path) as store:
                return store.add_snapshot(report())
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            ids = list(pool.map(write, range(12)))
        self.assertEqual(len(set(ids)), 12)
        with CaseStore(self.path) as store:
            self.assertTrue(store.verify()['ok'])
            self.assertEqual(store.verify()['checked_events'], 12)
        bad = Path(self.directory.name) / 'bad.db'
        bad.write_bytes(b'not a database')
        with self.assertRaisesRegex(ValueError, 'case database'):
            CaseStore(bad)
        with self.assertRaisesRegex(ValueError, 'case database'):
            CaseStore(Path(self.directory.name) / 'missing-parent' / 'case.db')
