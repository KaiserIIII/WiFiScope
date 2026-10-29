"""Bounded explicit identities; fixtures are invented and never device evidence."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


CPE = 'cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*'


class InventoryImportTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('wifiscope.inventory_import'),
                             'explicit bounded SBOM adapter is missing')
        from wifiscope.inventory_import import import_inventory
        self.import_inventory = import_inventory
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'input.json'

    def run_import(self, document, kind='cyclonedx', **kwargs):
        raw = json.dumps(document).encode('utf-8')
        self.path.write_bytes(raw)
        before = self.path.read_bytes()
        result = self.import_inventory(self.path, format=kind, **kwargs)
        self.assertEqual(self.path.read_bytes(), before)
        return result

    def cdx(self, **changes):
        doc = dict(bomFormat='CycloneDX', specVersion='1.6', components=[dict(cpe=CPE)])
        doc.update(changes)
        return doc

    def test_nested_entries_metadata_and_exact_source_time_and_digest(self):
        doc = self.cdx(metadata=dict(timestamp='2026-01-02T03:04:05Z', component=dict(cpe=CPE),
                                    tools=dict(components=[dict(cpe=CPE)])),
                       components=[dict(cpe=CPE, components=[dict(purl='pkg:unknown/example')])])
        original = copy.deepcopy(doc)
        result = self.run_import(doc)
        self.assertEqual(doc, original)
        context = result['import_context']
        self.assertEqual(context['input_entries'], 3)
        self.assertEqual(context['retained_components'], 2)
        self.assertEqual(context['unmapped_entries'], 1)
        self.assertEqual(context['unsupported_identifiers'], 1)
        self.assertEqual(context['source_sha256'], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(len(result['assets']), 1)
        self.assertEqual(result['assets'][0]['complete_parts'], [])
        rows = result['assets'][0]['components']
        self.assertNotEqual(rows[0]['id'], rows[1]['id'])
        for row in rows:
            self.assertEqual(row['observed_at'], '2026-01-02T03:04:05Z')
            self.assertEqual((row['source'], row['identification']), ('sbom', 'imported'))
        self.assertEqual(result, self.import_inventory(self.path, format='cyclonedx'))

    def test_cdx_17_external_range_does_not_change_explicit_version(self):
        result = self.run_import(self.cdx(specVersion='1.7', components=[dict(
            cpe=CPE, versionRange='vers:semver/>=9.0.0', isExternal=True, scope='excluded')]))
        row = result['assets'][0]['components'][0]
        self.assertEqual(row['cpe'], CPE)
        self.assertIsNone(row['observed_at'])
        self.assertIn('runtime-state-unverified', result['import_context']['gaps'])
        self.assertIn('source-time-unknown', result['import_context']['gaps'])

    def test_spdx_duplicates_only_within_entry_and_gaps(self):
        ref = dict(referenceCategory='SECURITY', referenceType='cpe23Type', referenceLocator=CPE)
        result = self.run_import(dict(spdxVersion='SPDX-2.3', creationInfo=dict(created='2025-01-01'),
            packages=[dict(externalRefs=[ref, ref]), dict(externalRefs=[ref]),
                      dict(externalRefs=[dict(referenceCategory='PACKAGE-MANAGER', referenceType='purl',
                                              referenceLocator='pkg:example/foo')]),
                      dict(externalRefs=[dict(ref, referenceLocator='cpe:/a:acme:widget:1')])]), 'spdx')
        context = result['import_context']
        self.assertEqual([context[k] for k in ('input_entries', 'input_cpe_identifiers',
            'retained_components', 'unmapped_entries', 'unsupported_identifiers', 'duplicate_identifiers')],
            [4, 4, 2, 2, 2, 1])
        self.assertIn('duplicate-identifier', context['gaps'])

    def test_no_usable_identifier_refuses_instead_of_clean_empty_inventory(self):
        for component in [dict(purl='pkg:example/foo'), dict(cpe='cpe:/a:x:y:1'),
                          dict(cpe=CPE.replace(':widget:', ':wid*get:'))]:
            with self.subTest(component=component), self.assertRaisesRegex(ValueError, 'No usable explicit CPE'):
                self.run_import(self.cdx(components=[component]))

    def test_explicit_versions_and_formats_only(self):
        for document, kind in [(self.cdx(specVersion='1.5'), 'cyclonedx'),
                               (dict(spdxVersion='SPDX-2.3.1', packages=[]), 'spdx'),
                               (self.cdx(), 'auto'), (self.cdx(bomFormat='other'), 'cyclonedx')]:
            with self.subTest(kind=kind, document=document), self.assertRaises(ValueError):
                self.run_import(document, kind)

    def test_native_preserves_provenance_and_closure(self):
        native = dict(schema_version=1, assets=[dict(id='declared-laptop', complete_parts=['a'],
            components=[dict(id='local-c', cpe=CPE, observed_at='2026-01-01', source='local',
                             identification='declared')])])
        result = self.run_import(native, 'native')
        self.assertEqual(result['assets'][0]['complete_parts'], ['a'])
        self.assertEqual(result['assets'][0]['components'][0]['source'], 'local')

    def test_duplicate_keys_depth_nodes_bytes_and_retention_refuse(self):
        raw_cases = [b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}',
                     b'[' * 34 + b'0' + b']' * 34,
                     b'[' + b'0,' * 250001 + b'0]', b' ' * (16 * 1024 * 1024 + 1)]
        for raw in raw_cases:
            self.path.write_bytes(raw)
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                self.import_inventory(self.path, format='cyclonedx')
        with self.assertRaisesRegex(ValueError, 'retention'):
            self.run_import(self.cdx(components=[dict(cpe=CPE)] * 8193))

    def test_cancellation_and_callback_failure_are_controlled(self):
        with self.assertRaisesRegex(ValueError, 'cancelled'):
            self.run_import(self.cdx(), cancel=lambda: True)
        def failed():
            raise RuntimeError('PRIVATE INPUT')
        with self.assertRaises(ValueError) as caught:
            self.run_import(self.cdx(), cancel=failed)
        self.assertNotIn('PRIVATE', str(caught.exception))

    def test_remote_metadata_is_never_resolved(self):
        with patch('urllib.request.urlopen', side_effect=AssertionError('external access')):
            result = self.run_import(self.cdx(**{'$schema': 'https://invalid/schema',
                'externalReferences': [dict(url='https://invalid/')]}))
        self.assertEqual(result['import_context']['retained_components'], 1)

    def test_unsupported_source_duplicates_are_counted_before_filtering(self):
        ref = dict(referenceCategory='SECURITY', referenceType='cpe23Type', referenceLocator='cpe:/a:acme:widget:1')
        valid = dict(ref, referenceLocator=CPE)
        result = self.run_import(dict(spdxVersion='SPDX-2.3', packages=[dict(externalRefs=[ref, ref, valid])]), 'spdx')
        context = result['import_context']
        self.assertEqual(context['input_cpe_identifiers'], 3)
        self.assertEqual(context['unsupported_identifiers'], 2)
        self.assertEqual(context['duplicate_identifiers'], 1)

    def test_equivalent_case_and_escaped_literal_identifiers_deduplicate(self):
        ref = dict(referenceCategory='SECURITY', referenceType='cpe23Type', referenceLocator=CPE)
        equivalent = dict(ref, referenceLocator=CPE.replace(':acme:', ':ACME:').replace(':widget:', ':\\widget:'))
        result = self.run_import(dict(spdxVersion='SPDX-2.3', packages=[dict(externalRefs=[ref, equivalent])]), 'spdx')
        self.assertEqual(result['import_context']['duplicate_identifiers'], 1)
        self.assertEqual(result['import_context']['retained_components'], 1)


if __name__ == '__main__':
    unittest.main()
