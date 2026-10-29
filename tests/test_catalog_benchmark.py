import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

from wifiscope.cli import main, parser
from wifiscope.catalog_store import build_catalog
from tests.test_catalog_gui import feed


class CatalogIntegrationTests(unittest.TestCase):
    def test_explicit_inventory_format_cli_uses_shared_projection(self):
        options = next(a for a in parser()._subparsers._group_actions[0].choices['catalog']._subparsers._group_actions[0].choices['audit']._actions
                       if a.dest == 'inventory')
        self.assertIsNotNone(options)
        help_text = parser()._subparsers._group_actions[0].choices['catalog']._subparsers._group_actions[0].choices['audit'].format_help()
        self.assertIn('--inventory-format', help_text)
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            source, db, sbom = folder / 'feed.json', folder / 'index.db', folder / 'bom.json'
            source.write_text(json.dumps(feed(1)), encoding='utf-8')
            build_catalog([source], db)
            sbom.write_text(json.dumps(dict(bomFormat='CycloneDX', specVersion='1.7', components=[dict(
                cpe='cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*')])), encoding='utf-8')
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(['catalog', 'audit', '--db', str(db), '--inventory', str(sbom),
                             '--inventory-format', 'cyclonedx'])
            self.assertEqual(code, 0)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result['catalog_audit']['inventory']['import_context']['format'], 'cyclonedx')
            self.assertNotIn('cpe:2.3:a:acme:widget', stdout.getvalue())
            self.assertFalse(result['identifiers_included'])
            import hashlib
            self.assertNotIn(hashlib.sha256(sbom.read_bytes()).hexdigest(), stdout.getvalue())
            self.assertEqual(result['catalog_audit']['inventory']['import_context']['input_entries'], 1)
            self.assertTrue(all(row['status'] == 'imported-unverified' for row in result['catalog_audit']['results']))

    def test_benchmark_bounded_synthetic_receipt_and_cancel_cleanup(self):
        self.assertIsNotNone(importlib.util.find_spec('wifiscope.catalog_benchmark'), 'bounded reproducible helper missing')
        from wifiscope.catalog_benchmark import benchmark
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'new-benchmark'
            receipt = benchmark(target, records=100)
            self.assertEqual(receipt['input_records'], 100)
            self.assertEqual(receipt['stored_records'], 100)
            self.assertTrue(receipt['synthetic'])
            self.assertTrue(receipt['cancelled_build_cleaned'])
            self.assertGreater(receipt['database_bytes'], 0)
            self.assertGreater(receipt['python_traced_peak_bytes'], 0)
            self.assertNotIn(str(target), json.dumps(receipt))
            for value in (0, 1000001, True):
                with self.assertRaises(ValueError):
                    benchmark(Path(directory) / 'rejected', records=value)
            with self.assertRaises(ValueError):
                benchmark(target, records=100)


if __name__ == '__main__':
    unittest.main()
