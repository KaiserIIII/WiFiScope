import copy
import unittest

from wifiscope import applicability, cpe_names, inventory


def cpe(part='a', vendor='acme', product='app', version='1.2', **fields):
    values = dict(part=part, vendor=vendor, product=product, version=version,
                  update='*', edition='*', language='*', sw_edition='*',
                  target_sw='*', target_hw='*', other='*')
    values.update(fields)
    return 'cpe:2.3:' + ':'.join(values.values())


def component(identifier='component-a', **values):
    return dict(id=identifier, cpe=cpe(), **values)


def asset(*components, complete_parts=None):
    return inventory.validate_inventory(dict(schema_version=1, assets=[dict(
        id='asset-a', components=list(components) or [component()],
        complete_parts=complete_parts or [])]))['assets'][0]


def leaf(criteria=None, vulnerable=True, **values):
    return dict(criteria=criteria or cpe(version='*'), vulnerable=vulnerable,
                unsupported=False, **values)


def node(*leaves, operator='OR', negate=False, nodes=None):
    return dict(operator=operator, negate=negate, unsupported=False,
                cpeMatch=list(leaves), nodes=nodes or [])


def record(*nodes, affected=None):
    return dict(configurations=list(nodes), affected=affected or [], gaps=[],
                applicability=dict(configurations='present' if nodes else 'missing',
                                   affected='present' if affected else 'missing'))


class CPETests(unittest.TestCase):
    def test_original_spelling_does_not_change_parsed_name_equality(self):
        upper = cpe_names.parse_cpe(cpe(vendor='ACME', version=r'1.0.0-\R\C.1'))
        lower = cpe_names.parse_cpe(cpe(vendor='acme', version='1.0.0-rc.1'))
        self.assertEqual(upper.field('version').original_text, '1.0.0-RC.1')
        self.assertEqual(upper.field('version').text, '1.0.0-rc.1')
        # Compare equally quoted names: spelling metadata must not alter the
        # existing dataclass equality/hash relation over matching attributes.
        same = cpe_names.parse_cpe(cpe(vendor='acme', version=r'1.0.0-\r\c.1'))
        self.assertEqual(upper, same)
        self.assertEqual(hash(upper), hash(same))
        self.assertEqual(cpe_names.compare_cpe(upper, lower), 'true')

    def test_nist_literals_any_na_case_and_escaped_fields(self):
        compare = cpe_names.compare_cpe
        self.assertEqual(compare(cpe(vendor='ACME'), cpe()), 'true')
        self.assertEqual(compare(cpe(version='*'), cpe(version='-')), 'true')
        self.assertEqual(compare(cpe(version='-'), cpe(version='1')), 'false')
        self.assertEqual(compare(cpe(version=r'\-'), cpe(version='-')), 'false')
        self.assertEqual(compare(cpe(product=r'pro\:duct'), cpe(product=r'pro\:duct')), 'true')
        self.assertEqual(compare(cpe(product=r'pro\\duct'), cpe(product=r'pro\\duct')), 'true')
        self.assertEqual(compare(cpe(version='1.0'), cpe(version='1.0.0')), 'false')
        self.assertEqual(compare(cpe(version='1'), cpe(version='*')), 'unknown')

    def test_source_wildcards_zero_or_one_and_unsupported_target_patterns(self):
        compare = cpe_names.compare_cpe
        for value in ('ab', 'acb'):
            self.assertEqual(compare(cpe(product='a?b'), cpe(product=value)), 'unknown')
        for value in ('ab', 'abc'):
            self.assertEqual(compare(cpe(product='ab?'), cpe(product=value)), 'true')
        self.assertEqual(compare(cpe(product='ab?'), cpe(product='abcd')), 'false')
        self.assertEqual(compare(cpe(product='*app*'), cpe(product='myapplication')), 'true')
        self.assertEqual(compare(cpe(product=r'app\*'), cpe(product=r'app\*')), 'true')
        self.assertEqual(compare(cpe(product='app'), cpe(product='a*')), 'unknown')
        for key in ('update', 'edition', 'language', 'sw_edition', 'target_sw', 'target_hw', 'other'):
            self.assertEqual(compare(cpe(**{key: 'x'}), cpe(**{key: 'y'})), 'false')

    def test_part_any_na_and_escaped_logical_values(self):
        self.assertEqual(cpe_names.compare_cpe(cpe(part='*'), cpe(part='a')), 'true')
        self.assertEqual(cpe_names.compare_cpe(cpe(part='-'), cpe(part='a')), 'false')
        self.assertEqual(cpe_names.compare_cpe(cpe(version=r'\-'), cpe(version=r'\-')), 'true')
        self.assertEqual(cpe_names.compare_cpe(cpe(version=r'\*'), cpe(version='*')), 'unknown')

    def test_source_any_cannot_resolve_observed_patterns_across_attributes(self):
        fields = ('vendor','product','version','update','edition','language','sw_edition','target_sw','target_hw','other')
        for field in fields:
            with self.subTest(field=field):
                self.assertEqual(cpe_names.compare_cpe(cpe(**{field:'*'}),cpe(**{field:'1.*'})),'unknown')
                self.assertEqual(cpe_names.compare_cpe(cpe(**{field:'*'}),cpe(**{field:'a*b'})),'unknown')
                self.assertEqual(cpe_names.compare_cpe(cpe(**{field:'*'}),cpe(**{field:'-'})),'true')
                self.assertEqual(cpe_names.compare_cpe(cpe(**{field:'*'}),cpe(**{field:r'1.\*'})),'true')
        observed = component()
        observed['cpe'] = cpe(version='1.*')
        self.assertEqual(applicability.evaluate_cve(record(node(leaf())),asset(observed))['applicability'],'unknown')

    def test_types_and_bounds_fail_before_matching(self):
        for value in (None, [], 'x' * 4097, cpe() + ':extra'):
            with self.assertRaises(ValueError):
                cpe_names.parse_cpe(value)


class InventoryTests(unittest.TestCase):
    def test_normalization_independent_and_context_projection_contract(self):
        raw = dict(schema_version=1, assets=[dict(id='a', components=[dict(
            id='c', vendor='Vendor', product='Package', version=None)])])
        result = inventory.validate_inventory(raw)
        self.assertEqual(result['assets'][0]['components'][0]['source'], 'unknown')
        self.assertEqual(result['assets'][0]['components'][0]['version_scheme'], 'unknown')
        self.assertEqual(raw['assets'][0]['components'][0].keys(), {'id', 'vendor', 'product', 'version'})
        result['assets'][0]['components'][0]['version'] = '2'
        self.assertIsNone(raw['assets'][0]['components'][0]['version'])

    def test_unknown_duplicate_or_invalid_evidence_refused_without_echo(self):
        base = dict(schema_version=1, assets=[dict(id='a', components=[component()])])
        for change in ('unknown', 'duplicate', 'address', 'time', 'scheme'):
            value = copy.deepcopy(base)
            if change == 'unknown':
                value['PRIVATE_SENTINEL'] = True
            elif change == 'duplicate':
                value['assets'][0]['components'] *= 2
            elif change == 'address':
                value['assets'][0]['address'] = 'PRIVATE_SENTINEL'
            elif change == 'time':
                value['assets'][0]['components'][0]['observed_at'] = 'PRIVATE_SENTINEL'
            else:
                value['assets'][0]['components'][0]['version_scheme'] = 'PRIVATE_SENTINEL'
            with self.assertRaises(ValueError) as caught:
                inventory.validate_inventory(value)
            self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))

    def test_escaped_serialized_size_rejected_before_expansion(self):
        from unittest.mock import patch
        rows = [dict(id=str(i),vendor='"'*256,product='"'*256,version='"'*1024) for i in range(8192)]
        value = dict(schema_version=1,assets=[dict(id='a',components=rows)])
        with patch('wifiscope.inventory.json.dumps',side_effect=AssertionError('SERIALIZATION_REACHED')):
            with self.assertRaises(ValueError):
                inventory.validate_inventory(value)
            # Same maximum-length escaped identities at a valid cardinality
            # remain admissible; no arbitrary reduction of field limits.
            value['assets'][0]['components'] = rows[:4096]
            self.assertEqual(len(inventory.validate_inventory(value)['assets'][0]['components']),4096)

    def test_exact_serialized_size_escape_utf8_scalar_and_container_boundaries(self):
        import json
        from unittest.mock import patch
        value = {'"\\\n': ['"', '\\', '\b\f\n\r\t\x00\x1f', '中文é😀', True, False, None, -42, 1.25]}
        for value in (value, {}, [], '', False, True, None, -(2**63), 1e-100, -0.0, 1e100):
            size = len(json.dumps(value,ensure_ascii=False,allow_nan=False).encode('utf8'))
            with patch.object(inventory,'MAX_BYTES',size):
                inventory.bounded_json(value,allow_numbers=True)
            with patch.object(inventory,'MAX_BYTES',size-1), self.assertRaises(ValueError):
                inventory.bounded_json(value,allow_numbers=True)
        for value in ('"'*64,'\\'*64,'\x00'*64,'中文😀'*64):
            with patch.object(inventory,'MAX_BYTES',100), patch('wifiscope.inventory.json.dumps',side_effect=AssertionError('SERIALIZATION_REACHED')):
                with self.assertRaises(ValueError):
                    inventory.bounded_json(value)
        with self.assertRaises(UnicodeEncodeError):
            inventory.bounded_json('\ud800')

    def test_native_inventory_cardinality_and_c1_control_bounds(self):
        for identifier in ('bad\x85id', 'bad\x1fid', 'x'*257):
            with self.assertRaises(ValueError):
                inventory.validate_inventory(dict(schema_version=1, assets=[dict(id=identifier, components=[component()])]))
        rows = [dict(id='c'+str(i), vendor='v', product='p', version=None) for i in range(8192)]
        self.assertEqual(len(inventory.validate_inventory(dict(schema_version=1, assets=[dict(id='a', components=rows)]))['assets'][0]['components']),8192)
        with self.assertRaises(ValueError):
            inventory.validate_inventory(dict(schema_version=1, assets=[dict(id='a', components=rows+[dict(rows[0], id='extra')])]))
        assets = [dict(id=str(i), components=[dict(id='c'+str(i),vendor='v',product='p',version='1')]) for i in range(1024)]
        self.assertEqual(len(inventory.validate_inventory(dict(schema_version=1,assets=assets))['assets']),1024)
        with self.assertRaises(ValueError):
            inventory.validate_inventory(dict(schema_version=1,assets=assets+[dict(id='extra',components=[component()])]))

    def test_load_predecode_depth_nodes_duplicates_and_local_path(self):
        import json
        from pathlib import Path
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'inventory.json'
            for raw in ('{"schema_version":1,"schema_version":1,"assets":[]}', '['*33+'0'+']'*33,
                        '['+','.join('0' for _ in range(250001))+']', '"'+'x'*(16*1024*1024)+'"'):
                path.write_text(raw, encoding='utf8')
                with self.assertRaises(ValueError):
                    inventory.load_inventory(path)
            path.write_text(json.dumps(dict(schema_version=1, assets=[dict(id='a', components=[component()])])), encoding='utf8')
            self.assertEqual(inventory.load_inventory(path)['assets'][0]['id'], 'a')
        for path in ('https://example.invalid/inventory', '//server/share/inventory', r'\\server\share\inventory'):
            with patch('builtins.open', side_effect=AssertionError('must refuse before opening')):
                with self.assertRaises(ValueError):
                    inventory.load_inventory(path)

    def test_import_context_exact_types_and_limits(self):
        base = dict(schema_version=1, assets=[dict(id='a', components=[component()])], import_context=dict(
            format='spdx', source_sha256=None, document_observed_at=None, input_entries=1,
            input_cpe_identifiers=2, retained_components=1, unmapped_entries=0, unsupported_identifiers=0,
            duplicate_identifiers=1, partial=False, gaps=[]))
        self.assertEqual(inventory.validate_inventory(base)['import_context'], base['import_context'])
        for key, value in [('retained_components',0), ('input_entries',True), ('gaps',['unknown']),
                           ('format','unknown'), ('source_sha256','A'*64), ('document_observed_at','invalid')]:
            raw = copy.deepcopy(base)
            raw['import_context'][key] = value
            with self.assertRaises(ValueError):
                inventory.validate_inventory(raw)
        for value in (dict(schema_version=True, assets=[]), dict(schema_version=1, assets=[]),
                      dict(schema_version=1, assets=[dict(id='a', components=[])]) ):
            with self.assertRaises(ValueError):
                inventory.validate_inventory(value)
        cycle = []
        cycle.append(cycle)
        with self.assertRaises(ValueError):
            inventory.validate_inventory(cycle)


class ApplicabilityTests(unittest.TestCase):
    def evaluate(self, rec, observed):
        return applicability.evaluate_cve(rec, observed)['applicability']

    def test_original_decoded_version_case_controls_ranges_and_cna_declarations(self):
        observed_version = '1.0.0-RC.1'
        cpe_component = dict(id='cpe', cpe=cpe(version=observed_version), version_scheme='semver2')
        for key, bound, expected in [
                ('versionEndIncluding', observed_version, 'true'),
                ('versionEndExcluding', observed_version, 'false'),
                ('versionEndExcluding', '1.0.0-Z', 'true'),
                ('versionStartIncluding', observed_version, 'true'),
                ('versionStartExcluding', observed_version, 'false')]:
            with self.subTest(key=key, bound=bound):
                rec = record(node(leaf(**{key: bound})))
                self.assertEqual(self.evaluate(rec, asset(cpe_component)), expected)
        declarations = [
            (dict(version=observed_version), 'true'),
            (dict(version='1.0.0-rc.1'), 'false'),
            (dict(version='0', lessThan='1.0.0-Z', versionType='semver'), 'true'),
            (dict(version='0', lessThan=observed_version, versionType='semver'), 'false'),
            (dict(version='0', lessThanOrEqual=observed_version, versionType='semver'), 'true')]
        for declaration, expected in declarations:
            row = dict(vendor='acme', product='app', cpes=[cpe(version='*')], context={},
                       unsupported=False, defaultStatus='unaffected',
                       versions=[dict(status='affected', changes=[], unsupported=False, **declaration)])
            rec = record(affected=[dict(affectedData=[row])])
            before = copy.deepcopy(rec)
            for component in (cpe_component, dict(id='native', vendor='acme', product='app',
                    version=observed_version, version_scheme='semver2')):
                with self.subTest(declaration=declaration, component=component['id']):
                    self.assertEqual(self.evaluate(rec, asset(component)), expected)
            self.assertEqual(rec, before)
        cpe_component['cpe'] = cpe(version=r'release\:RC\\A\*')
        row['versions'] = [dict(version='release:RC\\A*', status='affected', changes=[], unsupported=False)]
        self.assertEqual(self.evaluate(rec, asset(cpe_component)), 'true')
        self.assertEqual(cpe_names.compare_cpe(cpe(version='1.0.0-rc.1'),
                                             cpe(version=observed_version)), 'true')
        cpe_component['cpe'] = cpe(version=observed_version)
        cpe_component['version_scheme'] = 'unknown'
        self.assertEqual(self.evaluate(record(node(leaf(versionEndIncluding=observed_version))),
                                       asset(cpe_component)), 'unknown')

    def test_older_typed_cna_dual_upper_bounds_remain_unknown(self):
        observed = asset(dict(id='native', vendor='acme', product='app', version='2', version_scheme='numeric'))
        for inclusive in ('1', '2'):
            for default in ('affected', 'unaffected'):
                declaration = dict(version='0', lessThan='2', lessThanOrEqual=inclusive,
                                   status='affected', versionType='numeric', changes=[], unsupported=False)
                row = dict(vendor='acme', product='app', defaultStatus=default, versions=[declaration],
                           context={}, cpes=[], unsupported=False)
                rec = record(affected=[dict(affectedData=[row])])
                before = copy.deepcopy(rec)
                self.assertEqual(self.evaluate(rec, observed), 'unknown')
                self.assertEqual(rec, before)
                for key, bound, expected in [('lessThan', '2', 'false'),
                                             ('lessThanOrEqual', '2', 'true'),
                                             ('lessThanOrEqual', '1', 'false')]:
                    row['defaultStatus'] = 'unaffected'
                    row['versions'] = [dict(version='0', status='affected', versionType='numeric',
                                            changes=[], unsupported=False, **{key: bound})]
                    self.assertEqual(self.evaluate(rec, observed), expected)

    def test_configuration_parser_containment_does_not_catch_work_or_callbacks(self):
        rec = record(node(leaf()))
        with self.assertRaises(applicability.WorkLimit):
            applicability.evaluate_cve(rec, asset(), budget=applicability.MatchBudget(3))
        calls = 0
        def cancel_during_comparison():
            nonlocal calls
            calls += 1
            return calls == 4
        with self.assertRaises(InterruptedError):
            applicability.evaluate_cve(rec, asset(), budget=applicability.MatchBudget(cancel=cancel_during_comparison))
        calls = 0
        def broken_callback():
            nonlocal calls
            calls += 1
            if calls == 4:
                raise RuntimeError('PRIVATE_SENTINEL')
            return False
        with self.assertRaisesRegex(ValueError, 'callback'):
            applicability.evaluate_cve(rec, asset(), budget=applicability.MatchBudget(cancel=broken_callback))

    def test_kleene_truth_tables(self):
        values = ('true', 'false', 'unknown')
        for a in values:
            for b in values:
                self.assertEqual(applicability.truth_and([a, b]),
                    'false' if 'false' in (a, b) else 'unknown' if 'unknown' in (a, b) else 'true')
                self.assertEqual(applicability.truth_or([a, b]),
                    'true' if 'true' in (a, b) else 'unknown' if 'unknown' in (a, b) else 'false')
        self.assertEqual([applicability.truth_not(a) for a in values], ['false', 'true', 'unknown'])

    def test_unknown_environment_is_not_false_or_confirmed(self):
        rec = record(node(leaf(), leaf(cpe(part='o', vendor='linux', product='kernel', version='*'), False), operator='AND'))
        self.assertEqual(self.evaluate(rec, asset()), 'unknown')
        linux = component('os', version_scheme='numeric')
        linux['cpe'] = cpe(part='o', vendor='linux', product='kernel', version='6.1')
        self.assertEqual(self.evaluate(rec, asset(component(), linux)), 'true')
        self.assertEqual(self.evaluate(rec, asset()), 'unknown')  # OS on another asset is not passed in.
        self.assertEqual(self.evaluate(rec, asset(complete_parts=['o'])), 'false')

    def test_positive_witness_cannot_be_borrowed_from_false_or_negated_branch(self):
        environment = leaf(cpe(version='*'), False)
        self.assertEqual(self.evaluate(record(node(environment)), asset()), 'unknown')
        self.assertEqual(self.evaluate(record(node(leaf(cpe(version='2')), negate=True)), asset()), 'unknown')
        self.assertEqual(self.evaluate(record(node(leaf(cpe(version='2'))), node(environment)), asset()), 'unknown')
        double = node(nodes=[node(leaf(), negate=True)], negate=True)
        self.assertEqual(self.evaluate(record(double), asset()), 'true')

    def test_explicit_version_ranges_do_not_strip_suffixes(self):
        rec = record(node(leaf(versionEndExcluding='2.0')))
        self.assertEqual(self.evaluate(rec, asset(component(version_scheme='numeric'))), 'true')
        changed = component(version_scheme='numeric')
        changed['cpe'] = cpe(version='2.0')
        self.assertEqual(self.evaluate(rec, asset(changed)), 'false')
        changed['cpe'] = cpe(version='1.2-ubuntu1')
        self.assertEqual(self.evaluate(rec, asset(changed)), 'unknown')

    def test_semver_precedence_and_openssh(self):
        compare = applicability.compare_versions
        self.assertEqual(compare('1.0.0-2', '1.0.0-alpha', 'semver2'), -1)
        self.assertEqual(compare('1.0.0+x', '1.0.0+y', 'semver2'), 0)
        self.assertIsNone(compare('1.01.0', '2.0.0', 'semver2'))
        self.assertEqual(compare('9.1p2', '9.1p10', 'openssh-portable'), -1)
        self.assertIsNone(compare('9.1p2ubuntu', '9.2p1', 'openssh-portable'))

    def test_cna_exact_default_ranges_changes_context_and_conflicts(self):
        observed = asset(dict(id='pkg', vendor='Vendor', product='Package', version='2.9', version_scheme='numeric'))
        row = dict(vendor='Vendor', product='Package', versions=[dict(version='0', lessThan='2.*',
            status='affected', versionType='numeric', changes=[], unsupported=False)], defaultStatus='unaffected',
            cpes=[], context={}, unsupported=False)
        def run(value):
            return self.evaluate(record(affected=[dict(source=None, affectedData=[value])]), observed)
        self.assertEqual(run(row), 'true')
        observed['components'][0]['version'] = '3.0'
        self.assertEqual(run(row), 'false')
        row['versions'][0]['versionType'] = 'git'
        self.assertEqual(run(row), 'unknown')
        row['versions'] = [dict(version='3.0', status='affected', versionType='git', changes=[], unsupported=False)]
        self.assertEqual(run(row), 'true')
        row['context'] = {'platforms': ['linux']}
        self.assertEqual(run(row), 'unknown')
        row['context'] = {}
        row['versions'].append(dict(version='3.0', status='unaffected', changes=[], unsupported=False))
        self.assertEqual(run(row), 'unknown')
        row['versions'] = [dict(version='0', lessThan='*', status='affected', versionType='numeric', unsupported=False,
            changes=[dict(at='3.2', status='affected'), dict(at='2.0', status='unaffected'), dict(at='3.1', status='unaffected')])]
        self.assertEqual(run(row), 'false')
        observed['components'][0]['version'] = '3.2'
        self.assertEqual(run(row), 'true')

    def test_or_true_environment_cannot_borrow_possible_or_false_nested_witness(self):
        possible = node(leaf(cpe(version='*'), versionEndIncluding='2'))
        # No declared range scheme: positive witness only possible, whereas the
        # environment branch is true. This must remain unknown.
        rec = record(node(nodes=[node(leaf(vulnerable=False)), possible]))
        self.assertEqual(self.evaluate(rec, asset()), 'unknown')
        false_branch = node(leaf(), leaf(cpe(product='other'), False), operator='AND')
        self.assertEqual(self.evaluate(record(node(nodes=[node(leaf(vulnerable=False)), false_branch])),
                                       asset(complete_parts=['a'])), 'unknown')

    def test_cna_all_versions_invalid_observation_and_conflicting_changes(self):
        observed = asset(dict(id='pkg', vendor='Vendor', product='Package', version='bad', version_scheme='numeric'))
        row = dict(vendor='Vendor', product='Package', versions=[dict(version='0', lessThan='*',
            status='affected', versionType='numeric', changes=[], unsupported=False)], defaultStatus='unaffected',
            cpes=[], context={}, unsupported=False)
        def run():
            return self.evaluate(record(affected=[dict(affectedData=[row])]), observed)
        self.assertEqual(run(), 'unknown')
        observed['components'][0]['version'] = '1'
        row['versions'][0]['changes'] = [dict(at='1', status='affected'), dict(at='1.0', status='unaffected')]
        self.assertEqual(run(), 'unknown')
        row['versions'][0] = dict(version='*', status='affected', changes=[], unsupported=False)
        self.assertEqual(run(), 'true')

    def test_semantic_source_gaps_unknown_but_metadata_gaps_do_not_suppress_match(self):
        rec = record(node(leaf()))
        rec['gaps'] = ['timestamp_unknown', 'cvss_unknown']
        self.assertEqual(self.evaluate(rec, asset()), 'true')
        rec['configurations'][0]['unsupported'] = True
        self.assertEqual(self.evaluate(rec, asset()), 'unknown')

    def test_work_budget_charges_cna_identity_changes_and_cpe_pattern_work(self):
        budget = applicability.MatchBudget(4)
        with self.assertRaises(applicability.WorkLimit):
            applicability.evaluate_cve(record(node(leaf(cpe(product='*app*')))), asset(), budget=budget)
        with self.assertRaises(ValueError):
            applicability.evaluate_cve({'configurations': [[[]]*250001]}, asset())

    def test_cna_distinct_component_versions_are_alternatives(self):
        observed = asset(dict(id='old', vendor='Vendor', product='Package', version='1', version_scheme='numeric'),
                         dict(id='new', vendor='Vendor', product='Package', version='3', version_scheme='numeric'))
        row = dict(vendor='Vendor', product='Package', versions=[dict(version='0', lessThan='2',
            status='affected', versionType='numeric', changes=[], unsupported=False)], defaultStatus='unaffected',
            cpes=[], context={}, unsupported=False)
        self.assertEqual(self.evaluate(record(affected=[dict(affectedData=[row])]), observed), 'true')

    def test_full_semver_order_and_nvd_bounds(self):
        ordered = ['1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta',
                   '1.0.0-beta.2', '1.0.0-beta.11', '1.0.0-rc.1', '1.0.0']
        for left, right in zip(ordered, ordered[1:]):
            self.assertEqual(applicability.compare_versions(left,right,'semver2'), -1)
        for bad in ('1.0', 'v1.0.0', '1.0.0-01', '1.0.0+', '1.0.0-'):
            self.assertIsNone(applicability.compare_versions(bad,'1.0.0','semver2'))
        for key, version, expected in [('versionStartIncluding','1.2','true'), ('versionStartExcluding','1.2','false'),
                                      ('versionEndIncluding','1.2','true'), ('versionEndExcluding','1.2','false')]:
            self.assertEqual(self.evaluate(record(node(leaf(**{key:version}))), asset(component(version_scheme='numeric'))), expected)

    def test_cna_trailing_infinity_excludes_next_prefix_for_both_upper_forms(self):
        observed = asset(dict(id='pkg', vendor='Vendor', product='Package', version='3', version_scheme='numeric'))
        for key in ('lessThan','lessThanOrEqual'):
            row = dict(vendor='Vendor',product='Package',defaultStatus='unaffected',context={},cpes=[],unsupported=False,
                       versions=[dict(version='0',status='affected',versionType='numeric',changes=[],unsupported=False,**{key:'2.*'})])
            self.assertEqual(self.evaluate(record(affected=[dict(affectedData=[row])]),observed),'false')

    def test_cna_semver_and_openssh_prefix_infinity(self):
        for scheme, below, above, upper in [('semver2','2.9.0','3.0.0-alpha','2.*'),
                                            ('openssh-portable','9.7p10','10.0p1','9.*')]:
            observed = asset(dict(id='pkg', vendor='Vendor', product='Package',version=below,version_scheme=scheme))
            row = dict(vendor='Vendor',product='Package',defaultStatus='unaffected',context={},cpes=[],unsupported=False,
                       versions=[dict(version='0',lessThan=upper,status='affected',versionType=scheme,changes=[],unsupported=False)])
            rec = record(affected=[dict(affectedData=[row])])
            self.assertEqual(self.evaluate(rec,observed),'true')
            observed['components'][0]['version'] = above
            self.assertEqual(self.evaluate(rec,observed),'false')

    def test_unsupported_node_cannot_establish_false_clearance(self):
        rec = record(node(leaf(cpe(version='2'))))
        rec['configurations'][0]['unsupported'] = True
        self.assertEqual(self.evaluate(rec,asset()),'unknown')

    def test_standard_cna_semver_scheme_compatibility_preserves_source(self):
        observed = asset(dict(id='pkg',vendor='Vendor',product='Package',version='1.5.0',version_scheme='semver2'))
        row = dict(vendor='Vendor',product='Package',defaultStatus='unaffected',context={},cpes=[],unsupported=False,
                   versions=[dict(version='1.0.0',lessThan='2.0.0',status='affected',versionType='semver',changes=[],unsupported=False)])
        rec = record(affected=[dict(affectedData=[row])])
        before = copy.deepcopy(rec)
        self.assertEqual(self.evaluate(rec,observed),'true')
        observed['components'][0]['version'] = '2.0.0'
        self.assertEqual(self.evaluate(rec,observed),'false')
        self.assertEqual(rec,before)
        row['versions'][0]['versionType'] = 'rpm'
        self.assertEqual(self.evaluate(rec,observed),'unknown')
        row['versions'][0]['versionType'] = 'semver'
        observed['components'][0]['version_scheme'] = 'numeric'
        self.assertEqual(self.evaluate(rec,observed),'unknown')

    def test_unsupported_retained_cna_cpes_are_contained_before_matching(self):
        for unsupported in (False,True):
            for identity in ('cpe:/a:acme:app:1','malformed-retained-cpe'):
                with self.subTest(unsupported=unsupported,identity=identity):
                    row = dict(vendor='acme',product='app',defaultStatus='affected',versions=[],context={},
                               cpes=[identity],unsupported=unsupported)
                    rec = record(affected=[dict(affectedData=[row])])
                    before = copy.deepcopy(rec)
                    result = applicability.evaluate_cve(rec,asset())
                    self.assertEqual(result['applicability'],'unknown')
                    self.assertEqual(result['model'],'cna')
                    rec['configurations'] = [node(leaf())]
                    combined = applicability.evaluate_cve(rec,asset())
                    self.assertEqual(combined['applicability'],'true')
                    self.assertEqual(combined['model'],'mixed')
                    rec['configurations'] = []
                    self.assertEqual(rec,before)
        row['cpes'] = [cpe(version='*')]
        rec = record(affected=[dict(affectedData=[row])])
        row['unsupported'] = False
        budget = applicability.MatchBudget(3)
        with self.assertRaises(applicability.WorkLimit):
            applicability.evaluate_cve(rec,asset(),budget=budget)
        self.assertEqual(budget.used,3)
        calls = 0
        def cancelled_during_comparison():
            nonlocal calls
            calls += 1
            return calls == 4
        with self.assertRaises(InterruptedError):
            applicability.evaluate_cve(rec,asset(),budget=applicability.MatchBudget(cancel=cancelled_during_comparison))
        calls = 0
        def broken():
            nonlocal calls
            calls += 1
            if calls == 4:
                raise RuntimeError('PRIVATE_SENTINEL')
            return False
        with self.assertRaisesRegex(ValueError,'callback'):
            applicability.evaluate_cve(rec,asset(),budget=applicability.MatchBudget(cancel=broken))

    def test_parallel_models_explicit_contradiction_is_unknown(self):
        observed = asset(component(), dict(id='pkg', vendor='Vendor', product='Package', version='1'))
        affected = [dict(affectedData=[dict(vendor='Vendor', product='Package', defaultStatus='unaffected',
                       versions=[], context={}, cpes=[], unsupported=False)])]
        result = applicability.evaluate_cve(record(node(leaf()), affected=affected), observed)
        self.assertEqual(result['applicability'], 'unknown')
        self.assertIn('model-conflict', result['reasons'])


if __name__ == '__main__':
    unittest.main()
