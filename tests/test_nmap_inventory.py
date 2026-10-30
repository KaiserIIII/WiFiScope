"""Invented offline scanner assertions; never real device or installed proof."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from xml.etree.ElementTree import Element

from wifiscope.applicability import evaluate_cve, MatchBudget, WorkLimit
from wifiscope.inventory import validate_inventory
from wifiscope.inventory_import import import_inventory
from tests.test_applicability import cpe, leaf, node, record


def service(identity='cpe:/a:acme:app:1.2', *, method='probed', extra='', port='80',
            state='open', protocol='tcp', conf='9'):
    return (f'<ports><port protocol="{protocol}" portid="{port}"><state state="{state}"/>'
            f'<service method="{method}" conf="{conf}" product="PRIVATE_PROSE" version="99">'
            f'<cpe>{identity}</cpe>{extra}</service></port></ports>')


def document(body=None, *, host_attrs='starttime="1700000001" endtime="1700000002"',
             addresses='<address addr="192.0.2.10" addrtype="ipv4"/>'
                       '<address addr="2001:db8::10" addrtype="ipv6"/>',
             status='up', finish='<runstats><finished exit="success"/></runstats>', start='1700000000'):
    if body is None:
        body = service() + ('<os><osmatch accuracy="99"><osclass accuracy="98">'
            '<cpe>cpe:/o:linux:kernel:6</cpe></osclass><osclass accuracy="97">'
            '<cpe>cpe:/o:microsoft:windows:11</cpe></osclass></osmatch></os>')
    return (f'<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun start="{start}" args="PRIVATE_COMMAND">'
            f'<host {host_attrs}><status state="{status}"/>{addresses}{body}'
            '<hostnames><hostname name="PRIVATE_DNS"/></hostnames>'
            '<hostscript><script output="PRIVATE_SCRIPT"><cpe>cpe:/a:evil:script:1</cpe></script></hostscript>'
            f'</host>{finish}</nmaprun>').encode()


class CountedPort(Element):
    """Count actual direct-child visits, including Element.find's sibling work."""
    def __init__(self, port):
        super().__init__(port.tag, port.attrib)
        self.extend(port)
        self.visits = 0

    def __iter__(self):
        for index in range(len(self)):
            self.visits += 1
            yield self[index]

    def find(self, path, namespaces=None):
        if path == 'state' and namespaces is None:
            return next((child for child in self if child.tag == 'state'), None)
        return super().find(path, namespaces)


class NmapInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'PRIVATE_PATH.xml'

    def load(self, raw=None, **kwargs):
        raw = document() if raw is None else raw
        self.path.write_bytes(raw)
        try:
            result = import_inventory(self.path, format='nmap', **kwargs)
        except ValueError as exc:
            self.fail(f'Nmap identity import refused valid local fixture: {exc}')
        self.assertEqual(self.path.read_bytes(), raw)
        return result

    def refused(self, raw, **kwargs):
        self.path.write_bytes(raw)
        with self.assertRaises(ValueError) as caught:
            import_inventory(self.path, format='nmap', **kwargs)
        self.assertEqual(self.path.read_bytes(), raw)
        self.assertNotIn('PRIVATE', str(caught.exception))

    def test_direct_evidence_grouping_hash_time_determinism_and_no_io(self):
        raw = document()
        with patch('socket.socket', side_effect=AssertionError('network forbidden')), \
                patch('subprocess.Popen', side_effect=AssertionError('scanner forbidden')), \
                patch('urllib.request.urlopen', side_effect=AssertionError('fetch forbidden')):
            inv = self.load(raw)
        again = import_inventory(self.path, format='nmap')
        self.assertEqual(inv, again)
        self.assertEqual(len(inv['assets']), 1)
        asset = inv['assets'][0]
        self.assertEqual(asset['addresses'], ['192.0.2.10', '2001:db8::10'])
        self.assertEqual(asset['address'], '192.0.2.10')
        self.assertEqual(asset['complete_parts'], [])
        self.assertEqual(len(asset['components']), 3)
        self.assertEqual([r['scanner']['presence'] for r in asset['components']], ['asserted', 'possible', 'possible'])
        row = asset['components'][0]
        self.assertEqual((row['source'], row['identification']), ('nmap', 'probed'))
        self.assertEqual(row['scanner']['confidence'], 9)
        self.assertEqual(row['scanner'], dict(origin='service', method='probed', confidence=9,
            accuracy=None, protocol='tcp', port=80, state='open', host_status='up', host_ordinal=0,
            entry_ordinal=0, cpe_ordinal=0, binding='uri', timestamp_origin='host-end',
            metadata_valid=True, presence='asserted'))
        self.assertEqual([r['scanner']['accuracy'] for r in asset['components'][1:]], [98, 97])
        self.assertEqual(row['observed_at'], '2023-11-14T22:13:22+00:00')
        self.assertEqual(row['scanner']['timestamp_origin'], 'host-end')
        self.assertEqual(inv['import_context']['document_observed_at'], '2023-11-14T22:13:20+00:00')
        self.assertEqual(row['source_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(inv['import_context']['source_sha256'], row['source_sha256'])
        self.assertEqual(inv['import_context']['scanner_summary'], dict(input_hosts=1, retained_hosts=1,
            unmapped_hosts=0, service_entries=1, osclass_entries=2, scan_status='success'))
        self.assertFalse(inv['import_context']['partial'])
        self.assertNotIn('PRIVATE', json.dumps(inv))
        again['assets'][0]['addresses'].append('192.0.2.11')
        again['assets'][0]['components'][0]['scanner']['confidence'] = 0
        self.assertEqual(asset['addresses'], ['192.0.2.10', '2001:db8::10'])
        self.assertEqual(row['scanner']['confidence'], 9)

    def test_hypotheses_do_not_satisfy_cross_os_and(self):
        asset = self.load()['assets'][0]
        app = leaf()
        linux = leaf(cpe(part='o', vendor='linux', product='kernel', version='6'), False)
        windows = leaf(cpe(part='o', vendor='microsoft', product='windows', version='11'), False)
        before = copy.deepcopy(asset)
        self.assertEqual(evaluate_cve(record(node(app, linux, windows, operator='AND')), asset)['applicability'], 'unknown')
        self.assertEqual(evaluate_cve(record(node(app)), asset)['applicability'], 'true')
        self.assertEqual(asset, before)

    def test_possible_versions_environment_negation_cna_and_asserted_controls(self):
        inv = self.load(document(service(method='table')))
        asset = inv['assets'][0]
        asset['complete_parts'] = ['a']
        for criteria in (cpe(version='1.2'), cpe(version='99'), cpe(version='*', target_sw='linux')):
            for negate in (False, True):
                self.assertEqual(evaluate_cve(record(node(leaf(criteria), negate=negate)), asset)['applicability'], 'unknown')
        self.assertEqual(evaluate_cve(record(node(leaf(cpe(vendor='other')))), asset)['applicability'], 'false')
        for status in ('affected', 'unaffected'):
            row = dict(cpes=[cpe(version='99')], context={}, unsupported=False,
                       defaultStatus=status, versions=[])
            self.assertEqual(evaluate_cve(record(affected=[dict(affectedData=[row])]), asset)['applicability'], 'unknown')
        native = copy.deepcopy(asset)
        del native['components'][0]['scanner']
        self.assertEqual(evaluate_cve(record(node(leaf())), native)['applicability'], 'true')
        asserted = self.load(document(service()))['assets'][0]
        self.assertEqual(evaluate_cve(record(node(leaf(cpe(version='99')))), asserted)['applicability'], 'false')
        with self.assertRaises(WorkLimit):
            evaluate_cve(record(node(leaf())), asset, budget=MatchBudget(2))
        with self.assertRaises(InterruptedError):
            evaluate_cve(record(node(leaf())), asset, budget=MatchBudget(cancel=lambda: True))

    def test_possible_cna_affected_unaffected_wrong_version_and_callback_bounds(self):
        asset = self.load(document(service(method='table')))['assets'][0]
        before = copy.deepcopy(asset)
        for status in ('affected', 'unaffected'):
            row = dict(cpes=[cpe(version='99')], context={}, unsupported=False,
                       defaultStatus=status, versions=[])
            rec = record(affected=[dict(affectedData=[row])])
            self.assertEqual(evaluate_cve(rec, asset)['applicability'], 'unknown')
            calls = 0
            def broken():
                nonlocal calls
                calls += 1
                if calls == 7:
                    raise RuntimeError('PRIVATE')
                return False
            with self.assertRaisesRegex(ValueError, 'callback') as caught:
                evaluate_cve(rec, asset, budget=MatchBudget(cancel=broken))
            self.assertNotIn('PRIVATE', str(caught.exception))
        self.assertEqual(asset, before)

    def test_counters_include_no_identity_bad_duplicates_and_distinct_version_case(self):
        extra = ('<cpe>cpe:2.3:a:ACME:app:1.2:*:*:*:*:*:*:*</cpe>'
                 '<cpe>cpe:/a:acme:app:1.0.0-RC</cpe><cpe>cpe:/a:acme:app:1.0.0-rc</cpe>'
                 '<cpe>cpe:/a:*:app:1</cpe><cpe>PRIVATE_BAD</cpe>')
        raw = document(service(extra=extra) + service() +
            '<ports><port><service/></port></ports><os><osclass/></os>')
        context = self.load(raw)['import_context']
        self.assertEqual([context[k] for k in ('input_entries', 'input_cpe_identifiers', 'retained_components',
            'unmapped_entries', 'unsupported_identifiers', 'duplicate_identifiers')], [4, 7, 4, 2, 2, 1])
        self.assertEqual(context['scanner_summary']['service_entries'], 3)

    def test_missing_any_na_patterns_and_no_version_substitution(self):
        for identity, want, presence in [('cpe:/a:acme:app', '*', 'asserted'),
                ('cpe:/a:acme:app:-', '-', 'asserted'), ('cpe:/a:acme:app:1.%02', '1.*', 'possible')]:
            with self.subTest(identity=identity):
                inv = self.load(document(service(identity)))
                row = inv['assets'][0]['components'][0]
                self.assertEqual(row['cpe'].split(':')[5], want)
                self.assertEqual(row['scanner']['presence'], presence)
                self.assertIn('nmap-version-unknown', inv['import_context']['gaps'])
        self.refused(document(service('cpe:/a:acme:app:a%02b')))

    def test_addressless_and_unmapped_hosts_no_auto_merge(self):
        inv = self.load(document(service(), addresses=''))
        self.assertNotIn('address', inv['assets'][0])
        self.assertNotIn('addresses', inv['assets'][0])
        self.assertEqual(inv['assets'][0]['components'][0]['scanner']['presence'], 'possible')
        self.assertIn('nmap-address-unknown', inv['import_context']['gaps'])
        raw = document().replace(b'</host>', b'</host><host><ports><port><service/></port></ports></host>', 1)
        inv = self.load(raw)
        self.assertEqual(inv['import_context']['scanner_summary']['unmapped_hosts'], 1)
        raw = document().replace(b'</host>', b'</host><host><address addr="192.0.2.10" addrtype="ipv4"/>' + service().encode() + b'</host>', 1)
        inv = self.load(raw)
        self.assertEqual(len(inv['assets']), 2)
        self.assertNotEqual(inv['assets'][0]['id'], inv['assets'][1]['id'])

    def test_metadata_missing_invalid_and_presence_admission(self):
        for changes in [dict(method='table'), dict(method='PRIVATE'), dict(protocol='PRIVATE'),
                        dict(port='bad'), dict(conf='11'), dict(conf='9.0'), dict(state='closed')]:
            inv = self.load(document(service(**changes)))
            self.assertEqual(inv['assets'][0]['components'][0]['scanner']['presence'], 'possible')
        inv = self.load(document(service().replace(' conf="9"', '')))
        self.assertIsNone(inv['assets'][0]['components'][0]['scanner']['confidence'])
        self.assertTrue(inv['assets'][0]['components'][0]['scanner']['metadata_valid'])
        for status in ('down', 'unknown', 'PRIVATE'):
            inv = self.load(document(service(), status=status))
            self.assertEqual(inv['assets'][0]['components'][0]['scanner']['presence'], 'possible')

    def test_many_services_have_linear_port_work_and_distinct_source_entries(self):
        import wifiscope.nmap_inventory as adapter
        xml = adapter._xml
        for count in (64, 256):
            for states, state, valid, presence in (
                    ('<state state="open"/><state state="closed"/>', 'open', True, 'asserted'),
                    ('', 'unknown', True, 'possible'),
                    ('<state state="PRIVATE"/><state state="open"/>', 'unknown', False, 'possible'),
                    ('<state/><state state="open"/>', 'unknown', True, 'possible'),
                    ('<script><state state="closed"/></script><state state="open"/>', 'open', True, 'asserted')):
                with self.subTest(count=count, states=states):
                    ports = []
                    def preflight(data, cancel=None):
                        root = xml(data, cancel=cancel)
                        container = root.find('./host/ports')
                        port = CountedPort(container[0])
                        container[0] = port
                        ports.append(port)
                        return root
                    entries = ('<service method="probed" conf="9"><cpe>cpe:/a:acme:app:1.2</cpe></service>'
                               * (count-1) + '<service/>')
                    raw = document('<ports><port protocol="tcp" portid="80">'+entries+states+'</port></ports>')
                    with patch.object(adapter, '_xml', side_effect=preflight):
                        inv = self.load(raw)
                    rows = inv['assets'][0]['components']
                    self.assertEqual(len(rows), count-1)
                    self.assertEqual(len({row['id'] for row in rows}), count-1)
                    self.assertEqual([row['scanner']['entry_ordinal'] for row in rows], list(range(count-1)))
                    for row in rows:
                        self.assertEqual((row['scanner']['state'], row['scanner']['metadata_valid'],
                                          row['scanner']['presence']), (state, valid, presence))
                        self.assertEqual((row['scanner']['host_ordinal'], row['scanner']['cpe_ordinal']), (0, 0))
                        self.assertEqual(row['source_sha256'], hashlib.sha256(raw).hexdigest())
                        self.assertEqual(row['observed_at'], '2023-11-14T22:13:22+00:00')
                    context = inv['import_context']
                    self.assertEqual([context[key] for key in ('input_entries', 'input_cpe_identifiers',
                        'retained_components', 'unmapped_entries', 'duplicate_identifiers')],
                        [count, count-1, count-1, 1, 0])
                    self.assertEqual(context['scanner_summary']['service_entries'], count)
                    self.assertLessEqual(ports[0].visits, 3*len(ports[0]))

    def test_many_service_port_scan_checks_cancellation_and_callback_failure(self):
        import wifiscope.nmap_inventory as adapter
        previous = self.load()
        before = copy.deepcopy(previous)
        xml = adapter._xml
        entries = '<service method="probed"><cpe>cpe:/a:acme:app:1.2</cpe></service>'*256
        raw = document('<ports><port protocol="tcp" portid="80">'+entries+'<state state="open"/></port></ports>')
        for broken in (False, True):
            with self.subTest(callback_failure=broken):
                ports = []
                def preflight(data, cancel=None):
                    root = xml(data, cancel=cancel)
                    container = root.find('./host/ports')
                    port = CountedPort(container[0])
                    container[0] = port
                    ports.append(port)
                    return root
                def cancel():
                    if ports and ports[0].visits >= 32:
                        if broken:
                            raise RuntimeError('PRIVATE')
                        return True
                    return False
                self.path.write_bytes(raw)
                message = 'callback failed' if broken else 'import cancelled'
                with patch.object(adapter, '_xml', side_effect=preflight), self.assertRaisesRegex(ValueError, message) as caught:
                    import_inventory(self.path, format='nmap', cancel=cancel)
                self.assertNotIn('PRIVATE', str(caught.exception))
                self.assertEqual(self.path.read_bytes(), raw)
                self.assertEqual(previous, before)
                self.assertGreaterEqual(ports[0].visits, 32)
                self.assertLessEqual(ports[0].visits, 33)

    def test_source_time_precedence_and_invalid_supplied_intervals(self):
        for attrs, origin, time in [('', 'document-start', '2023-11-14T22:13:20+00:00'),
                ('starttime="1700000001"', 'host-start', '2023-11-14T22:13:21+00:00'),
                ('endtime="PRIVATE"', 'unknown', None),
                ('starttime="1700000002" endtime="1700000001"', 'unknown', None),
                ('starttime="bad" endtime="1700000002"', 'unknown', None)]:
            with self.subTest(attrs=attrs):
                inv = self.load(document(service(), host_attrs=attrs))
                row = inv['assets'][0]['components'][0]
                self.assertEqual((row['observed_at'], row['scanner']['timestamp_origin']), (time, origin))
                if time is None:
                    self.assertFalse(row['scanner']['metadata_valid'])
                    self.assertIn('nmap-evidence-unknown', inv['import_context']['gaps'])

    def test_completion_partial_and_no_identity_refusal(self):
        for finish, status in [('', 'unknown'), ('<runstats><finished exit="error"/></runstats>', 'error'),
                               ('<runstats><finished exit="PRIVATE"/></runstats>', 'unknown')]:
            inv = self.load(document(service(), finish=finish))
            self.assertTrue(inv['import_context']['partial'])
            self.assertEqual(inv['import_context']['scanner_summary']['scan_status'], status)
            self.assertIn('input-partial', inv['import_context']['gaps'])
        self.refused(document('<ports><port><service/></port></ports>'))
        self.refused(document('<os><script><osclass><cpe>cpe:/a:acme:app:1</cpe></osclass></script></os>'))

    def test_typed_raw_schema_refuses_unknown_keys_types_and_forged_presence(self):
        inv = self.load()
        scanner = inv['assets'][0]['components'][0]['scanner']
        for key in scanner:
            for bad in ({'PRIVATE': []}, [], True if type(scanner[key]) is int else 123):
                value = copy.deepcopy(inv)
                value['assets'][0]['components'][0]['scanner'][key] = bad
                with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                    validate_inventory(value)
        for mutation in ('extra', 'missing', 'source', 'noncpe', 'presence', 'addresses', 'summary'):
            value = copy.deepcopy(inv)
            asset = value['assets'][0]
            row = asset['components'][0]
            if mutation == 'extra':
                row['scanner']['prose'] = 'PRIVATE'
            elif mutation == 'missing':
                del row['scanner']['port']
            elif mutation == 'source':
                row['source'] = 'sbom'
            elif mutation == 'noncpe':
                del row['cpe']
                row.update(vendor='a', product='b', version='1')
            elif mutation == 'presence':
                row['scanner']['method'] = 'table'
            elif mutation == 'addresses':
                asset['addresses'] = ['192.0.2.11']
            else:
                value['import_context']['scanner_summary']['retained_hosts'] = 0
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_inventory(value)
        for addresses in ([], ['192.0.2.10'] * 2, ['fe80::1%scope'], ['PRIVATE_DNS'],
                          ['2001:0db8::10'], ['192.0.2.'+str(i) for i in range(17)]):
            value = copy.deepcopy(inv)
            value['assets'][0].pop('address')
            value['assets'][0]['addresses'] = addresses
            with self.subTest(addresses=addresses), self.assertRaises(ValueError):
                validate_inventory(value)

    def test_xml_source_limits_control_entities_depth_and_local_paths(self):
        for raw in [document().replace(b'<!DOCTYPE nmaprun>', b'<!DOCTYPE nmaprun SYSTEM "https://invalid/PRIVATE">'),
                    document().replace(b'<!DOCTYPE nmaprun>', b'<!DOCTYPE nmaprun [<!ENTITY x "x">]>'),
                    document(service()).replace(b'1.2</cpe>', b'1.2&#x85;</cpe>'),
                    b'<nmaprun>'+b'<x>'*65+b'</x>'*65+b'</nmaprun>',
                    b'<nmaprun>'+b'<x/>'*200001+b'</nmaprun>',
                    b'x'*(16*1024*1024+1)]:
            self.refused(raw)
        for path in ('https://invalid/PRIVATE', '//server/share/PRIVATE', r'\\server\share\PRIVATE'):
            with patch('builtins.open', side_effect=AssertionError('must refuse before IO')), self.assertRaises(ValueError):
                import_inventory(path, format='nmap')

    def test_cancellation_during_preflight_retention_and_callback_failure(self):
        raw = document(service(extra='<cpe>cpe:/a:acme:app:2</cpe>'))
        self.load(raw)
        for at in (1, 3, 12, 30):
            calls = 0
            def stop():
                nonlocal calls
                calls += 1
                return calls >= at
            self.refused(raw, cancel=stop)
        def broken():
            raise RuntimeError('PRIVATE')
        self.refused(raw, cancel=broken)

    def test_normalized_retention_and_expansion_are_all_or_nothing(self):
        extra = ''.join('<cpe>cpe:/a:acme:app:'+str(i)+'</cpe>' for i in range(8193))
        self.refused(document(service(extra=extra)))
        hosts = '<host>'+service()+'</host>'
        self.refused(('<nmaprun>'+hosts*1025+'</nmaprun>').encode())
        addresses = ''.join(f'<address addr="192.0.2.{i}" addrtype="ipv4"/>' for i in range(17))
        self.refused(document(service(), addresses=addresses))
        from wifiscope import inventory
        raw = document()
        with patch.object(inventory, 'MAX_BYTES', 1000):
            self.refused(raw)

    def test_exact_budget_accounting_accepts_boundary_without_envelope_overcharge(self):
        from wifiscope import inventory
        inv = self.load()
        exact_size = len(json.dumps(inv, ensure_ascii=False).encode('utf8'))
        with patch.object(inventory, 'MAX_BYTES', exact_size):
            self.assertEqual(self.load(), inv)
        with patch.object(inventory, 'MAX_BYTES', exact_size-1):
            self.refused(document())
        self.assertEqual(inventory._measure_json({'x': [None, 7]}), (5, 16))
        self.assertIsNone(inventory.bounded_json({'x': [None, 7]}))

    def test_context_and_scanner_malicious_types_are_controlled(self):
        inv = self.load()
        for section in ('scanner_summary', None):
            target = inv['import_context'] if section is None else inv['import_context'][section]
            for key in target:
                for bad in ({'PRIVATE': []}, [], True):
                    value = copy.deepcopy(inv)
                    changed = value['import_context'] if section is None else value['import_context'][section]
                    changed[key] = bad
                    if section is None and (key == 'partial' and bad is True or key == 'gaps' and bad == []):
                        continue
                    with self.subTest(section=section, key=key, bad=bad), self.assertRaises(ValueError):
                        validate_inventory(value)

    def test_invalid_document_metadata_prevents_asserted_admission(self):
        inv = self.load(document(service(), start='PRIVATE'))
        row = inv['assets'][0]['components'][0]
        self.assertEqual(row['observed_at'], '2023-11-14T22:13:22+00:00')
        self.assertIsNone(inv['import_context']['document_observed_at'])
        self.assertFalse(row['scanner']['metadata_valid'])
        self.assertEqual(row['scanner']['presence'], 'possible')

    def test_literal_quoting_deduplicates_but_version_case_does_not(self):
        inv = self.load(document(service(extra='<cpe>cpe:2.3:a:ACME:\\app:1.2:*:*:*:*:*:*:*</cpe>')))
        self.assertEqual(inv['import_context']['duplicate_identifiers'], 1)
        self.assertEqual(inv['import_context']['retained_components'], 1)

    def test_pattern_equivalence_ignores_ordinary_quoting_but_keeps_literal_wildcard(self):
        extra = (r'<cpe>cpe:2.3:a:acme:app:\1.*:*:*:*:*:*:*:*</cpe>'
                 r'<cpe>cpe:2.3:a:acme:app:1.\*:*:*:*:*:*:*:*</cpe>')
        inv = self.load(document(service('cpe:/a:acme:app:1.%02', extra=extra)))
        self.assertEqual(inv['import_context']['input_cpe_identifiers'], 3)
        self.assertEqual(inv['import_context']['retained_components'], 2)
        self.assertEqual(inv['import_context']['duplicate_identifiers'], 1)

    def test_rejected_repeated_text_has_no_typed_duplicate_identity(self):
        inv = self.load(document(service(extra='<cpe>PRIVATE_BAD</cpe><cpe>PRIVATE_BAD</cpe>')))
        context = inv['import_context']
        self.assertEqual(context['input_cpe_identifiers'], 3)
        self.assertEqual(context['unsupported_identifiers'], 2)
        self.assertEqual(context['duplicate_identifiers'], 0)
        self.assertNotIn('PRIVATE', json.dumps(inv))

    def test_hypotheses_do_not_borrow_asserted_neighbor_or_user_order(self):
        inv = self.load(document(service()+service('cpe:/a:acme:other:99', method='table')))
        asset = inv['assets'][0]
        asset['components'][1]['version_scheme'] = 'numeric'
        self.assertEqual(asset['components'][1]['scanner']['presence'], 'possible')
        app = leaf()
        environment = leaf(cpe(product='other', version='1'), False)
        for negate in (False, True):
            rec = record(node(app, operator='AND', nodes=[node(environment, negate=negate)]))
            self.assertEqual(evaluate_cve(rec, asset)['applicability'], 'unknown')
        for status in ('affected', 'unaffected'):
            row = dict(cpes=[cpe(product='other', version='*')], context={}, unsupported=False,
                defaultStatus=status, versions=[dict(version='0', lessThan='2', versionType='numeric',
                status=status, changes=[], unsupported=False)])
            self.assertEqual(evaluate_cve(record(affected=[dict(affectedData=[row])]), asset)['applicability'], 'unknown')
        self.assertEqual(evaluate_cve(record(node(app)), asset)['applicability'], 'true')

    def test_cancel_and_failure_after_xml_preflight_preserve_previous_inventory(self):
        import wifiscope.nmap_inventory as adapter
        previous = self.load()
        original = copy.deepcopy(previous)
        raw = document(service(extra=''.join(f'<cpe>cpe:/a:acme:app:{i}</cpe>' for i in range(100))))
        xml = adapter._xml
        armed, calls = False, 0
        def preflight(data, cancel=None):
            nonlocal armed
            root = xml(data, cancel=cancel)
            armed = True
            return root
        def cancel():
            nonlocal calls
            if armed:
                calls += 1
            return calls >= 20
        with patch.object(adapter, '_xml', side_effect=preflight):
            self.refused(raw, cancel=cancel)
        self.assertGreaterEqual(calls, 20)
        self.assertEqual(previous, original)
        armed, calls = False, 0
        def broken():
            if armed:
                raise RuntimeError('PRIVATE')
            return False
        with patch.object(adapter, '_xml', side_effect=preflight):
            self.refused(raw, cancel=broken)
        self.assertEqual(previous, original)

    def test_source_row_host_attribute_and_text_limits_refuse_before_clean_result(self):
        raw = ('<nmaprun><host>'+service()+'<os>'+'<osclass/>'*65536+'</os></host></nmaprun>').encode()
        self.refused(raw)
        self.refused(('<nmaprun>'+'<host/>'*4097+'</nmaprun>').encode())
        self.refused(document(service()).replace(b'PRIVATE_PROSE', b'x'*4097))
        self.refused(document(service()).replace(b'1.2</cpe>', b'x'*65537+b'</cpe>'))

    def test_json_expansion_and_nodes_are_independent_of_xml_byte_budget(self):
        identity = 'cpe:2.3:a:'+r'\v'*128+':'+r'\p'*128+':'+r'\q'*1000+':'+r'\r'*700+':*:*:*:*:*:*'
        many = '<ports>'+''.join('<port><service><cpe>'+identity+'</cpe></service></port>' for _ in range(2700))+'</ports>'
        raw = document(many)
        self.assertLess(len(raw), 16*1024*1024)
        self.refused(raw)
        # Small literal assertions stay below the byte cap but grow the typed
        # scanner metadata past the separate 250000 JSON-node limit.
        many = '<ports>'+''.join('<port><service><cpe>cpe:/a:acme:app:1</cpe></service></port>' for _ in range(5500))+'</ports>'
        self.refused(document(many))

    def test_indexed_vendor_product_exact_256_and_257_boundaries(self):
        identity = 'cpe:/a:'+'v'*256+':'+'p'*256+':1'
        self.assertEqual(self.load(document(service(identity)))['import_context']['retained_components'], 1)
        for key in ('vendor', 'product'):
            parts = identity.split(':')
            parts[2 if key == 'vendor' else 3] += 'x'
            extra = '<cpe>'+':'.join(parts)+'</cpe>'
            inv = self.load(document(service(extra=extra)))
            context = inv['import_context']
            self.assertEqual(context['input_cpe_identifiers'], 2)
            self.assertEqual(context['retained_components'], 1)
            self.assertEqual(context['unsupported_identifiers'], 1)
            self.assertIn('unsupported-cpe', context['gaps'])

    def test_catalog_real_index_shared_projection_case_triage_and_reexport(self):
        from wifiscope.catalog_store import build_catalog, CatalogIndex
        from wifiscope.catalog_audit import audit_catalog
        from wifiscope.catalog_audit_schema import validate_catalog_audit
        from wifiscope.reports import prepare_export, export_report
        from wifiscope.case_validation import validate_report
        from wifiscope.cases import CaseStore
        from wifiscope.investigate import build_investigation, merge_reports
        from wifiscope.comparison import compare_snapshots
        from tests.test_catalog_store import cve as source_cve
        inv = self.load()
        row = source_cve(vendor='acme', product='app')
        row['configurations'][0]['nodes'][0]['cpeMatch'][0].pop('versionEndExcluding')
        feed, db = Path(self.tmp.name)/'source.json', Path(self.tmp.name)/'catalog.db'
        feed.write_text(json.dumps(dict(format='NVD_CVE', version='2.0', totalResults=1,
            startIndex=0, resultsPerPage=1, vulnerabilities=[dict(cve=row)])), encoding='utf8')
        build_catalog([feed], db)
        report = dict(schema_version=1, assets=[dict(address='192.0.2.10', services=[])])
        before = copy.deepcopy((report, inv))
        with CatalogIndex(db) as index:
            try:
                result = audit_catalog(report, inv, index)
            except ValueError as exc:
                self.fail(f'Typed Nmap catalog integration refused additive fields: {exc}')
            partial_inv = self.load(document(finish=''))
            partial = audit_catalog(report, partial_inv, index)['catalog_audit']
            self.assertEqual(partial['status'], 'partial')
            self.assertIn('inventory-input-partial', partial['gaps'])
        self.assertEqual((report, inv), before)
        self.assertEqual(result['catalog_audit']['summary']['true_pairs'], 1)
        self.assertEqual(result['catalog_audit']['results'][0]['observed_at'], ['2023-11-14T22:13:22+00:00'])
        self.assertEqual(len(result['investigation']['assets']), 2)
        projected = prepare_export(result)
        audit = projected['catalog_audit']
        validate_catalog_audit(audit)
        addresses = audit['inventory']['assets'][0]['addresses']
        self.assertEqual(audit['inventory']['assets'][0]['address'], addresses[0])
        self.assertEqual([a['address'] for a in projected['investigation']['assets']], [addresses[0]]*2)
        self.assertEqual(audit['inventory']['assets'][0]['components'][0]['scanner'],
                         inv['assets'][0]['components'][0]['scanner'])
        self.assertEqual(build_investigation(result), result)
        finding = audit['results'][0]
        self.assertEqual(finding['asset_id'], audit['inventory']['assets'][0]['id'])
        self.assertIn(finding['component_ids'][0], [c['id'] for c in audit['inventory']['assets'][0]['components']])
        for include in (False, True):
            exported = prepare_export(projected, include)
            validate_report(exported)
            exported_audit = exported['catalog_audit']
            self.assertEqual(exported_audit['inventory']['assets'][0]['components'][0]['scanner'],
                             inv['assets'][0]['components'][0]['scanner'])
            self.assertEqual(exported_audit['results'][0]['asset_id'], exported_audit['inventory']['assets'][0]['id'])
            self.assertEqual(exported_audit['inventory']['assets'][0]['address'],
                             exported_audit['inventory']['assets'][0]['addresses'][0])
            self.assertFalse(exported['identifiers_included'])
        with CaseStore(Path(self.tmp.name)/'case.db') as case:
            snap = case.add_snapshot(projected)
            stored = case.load_snapshot(snap)
            stored_finding = stored['catalog_audit']['results'][0]
            self.assertEqual(stored_finding['asset_id'], stored['catalog_audit']['inventory']['assets'][0]['id'])
            case.triage(stored_finding['id'], 'investigating', snapshot_id=snap)
            self.assertTrue(case.verify()['ok'])
            self.assertEqual(case.triage_state(snapshot_id=snap)[stored_finding['id']]['status'], 'investigating')
            export_report(prepare_export(stored, True), Path(self.tmp.name)/'bundle')
        text = ''.join(p.read_text(encoding='utf8') for p in (Path(self.tmp.name)/'bundle').iterdir()
                       if p.suffix in ('.json', '.csv', '.html'))
        for forbidden in ('192.0.2.10', '2001:db8::10', 'cpe:', 'PRIVATE',
                          inv['import_context']['source_sha256'], str(self.path)):
            self.assertNotIn(forbidden, text)
        for addresses in (['raw-private-ip'], [audit['inventory']['assets'][0]['address']]*2):
            bad = copy.deepcopy(audit)
            bad['inventory']['assets'][0]['addresses'] = addresses
            with self.assertRaises(ValueError):
                validate_catalog_audit(bad)
        with self.assertRaises(ValueError):
            merge_reports([result, result])
        with self.assertRaises(ValueError):
            compare_snapshots(result, result)

    def test_scanner_ranges_and_optional_summary_old_shape(self):
        inv = self.load()
        for key, bads in dict(confidence=(-1, 11, 0.5), accuracy=(-1, 101), port=(0, 65536),
                host_ordinal=(-1, 4096, None), entry_ordinal=(-1, 200000, None),
                cpe_ordinal=(-1, 200000, None)).items():
            for bad in bads:
                value = copy.deepcopy(inv)
                value['assets'][0]['components'][0]['scanner'][key] = bad
                with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                    validate_inventory(value)
        legacy = copy.deepcopy(inv)
        del legacy['import_context']['scanner_summary']
        self.assertEqual(validate_inventory(legacy), legacy)
        for key, value in [('format', 'cyclonedx'), ('scanner_summary', dict(extra=1))]:
            bad = copy.deepcopy(inv)
            bad['import_context'][key] = value
            with self.assertRaises(ValueError):
                validate_inventory(bad)


if __name__ == '__main__':
    unittest.main()
