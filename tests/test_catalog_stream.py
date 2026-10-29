import gzip
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wifiscope import catalog_stream


class StreamTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'feed'

    def read(self, data, compressed=False, pin=None):
        self.path.write_bytes(gzip.compress(data) if compressed else data)
        source = catalog_stream.FeedStream(self.path, expected_sha256=pin)
        rows = list(source)
        return rows, source.metadata

    def test_bom_unicode_chunk_boundaries_and_expanded_pin(self):
        data = ('\ufeff{"format":"NVD_CVE","version":"2.0","vulnerabilities":'
                '[{"cve":{"id":"CVE-2026-12345","descriptions":[{"value":"中\\\"{}[]"}]}}],'
                '"totalResults":1,"startIndex":0,"resultsPerPage":1}').encode('utf8')
        for chunk in range(1, 8):
            with self.subTest(chunk=chunk), patch.object(catalog_stream, 'CHUNK', chunk):
                rows, meta = self.read(data, True, hashlib.sha256(data).hexdigest().upper())
                self.assertEqual(rows[0]['cve']['id'], 'CVE-2026-12345')
                self.assertEqual(meta['expanded_sha256'], hashlib.sha256(data).hexdigest())
                self.assertEqual(meta['records'], 1)
                self.assertFalse(meta['partial'])

    def test_strict_envelope_duplicate_keys_trailing_and_types(self):
        bad = [b'[]', b'{"format":"NVD_CVE","version":"2.0","vulnerabilities":[],"vulnerabilities":[]}',
               b'{"format":"NVD_CVE","version":"2.0","vulnerabilities":[{"cve":{"id":"a","id":"b"}}]}',
               b'{"format":"NVD_CVE","version":"2.0","vulnerabilities":[]} 0',
               b'{"format":"other","version":"2.0","vulnerabilities":[]}',
               b'{"format":"NVD_CVE","version":"2.0","vulnerabilities":[],"timestamp":"PRIVATE PATH /x"}',
               b'{"format":"NVD_CVE","version":"2.0","vulnerabilities":[],"totalResults":true}',
               b'{"format":"NVD_CVE","version":"2.0","vulnerabilities":[],"totalResults":0.0}',
               b'{"format":"NVD_CVE","version":"2.0","vulnerabilities":[NaN]}',
               b'{"format":"NVD_CVE","version":"2.0","vulnerabilities":[1e999]}',
               b'{"format":"NVD_CVE","version":"2.0","vulnerabilities":[]}\xff']
        for data in bad:
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.read(data)

    def test_partial_page_and_count_contradictions(self):
        data = b'{"format":"NVD_CVE","version":"2.0","vulnerabilities":[],"totalResults":99,"resultsPerPage":10,"startIndex":0}'
        self.assertTrue(self.read(data)[1]['partial'])
        with self.assertRaises(ValueError):
            self.read(data.replace(b'99', b'0').replace(b'[]', b'[{}]'))

    def test_limits_gzip_corruption_pin_and_cancel(self):
        data = b'{"format":"NVD_CVE","version":"2.0","vulnerabilities":[{"cve":{}}]}'
        for name, limit in [('MAX_SOURCE_BYTES', 10), ('MAX_EXPANDED_BYTES', 10), ('MAX_VALUE_BYTES', 5), ('MAX_DEPTH', 1), ('MAX_NODES', 1)]:
            with self.subTest(name=name), patch.object(catalog_stream, name, limit), self.assertRaises(ValueError):
                self.read(data, True)
        with self.assertRaises(ValueError):
            self.read(data, pin='0' * 64)
        for broken in [gzip.compress(data)[:-3], gzip.compress(data)[:-8] + b'12345678']:
            self.path.write_bytes(broken)
            with self.assertRaises(ValueError):
                list(catalog_stream.FeedStream(self.path))
        self.path.write_bytes(data)
        with self.assertRaises(ValueError):
            list(catalog_stream.FeedStream(self.path, cancel=lambda: True))

    def test_unknown_envelope_does_not_smuggle_rows_and_extreme_numbers_refuse(self):
        data = b'{"format":"NVD_CVE","version":"2.0","unknown":{"vulnerabilities":[{"cve":{"id":"fake"}}]},"vulnerabilities":[]}'
        self.assertEqual(self.read(data)[0], [])
        for value in [b'1234567890123456789', b'1e-999999', b'0e999999']:
            invalid = data.replace(b'"fake"', value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.read(invalid)
        for unknown in ['x' * 257, 'x' * 1000]:
            with self.subTest(unknown=len(unknown)), self.assertRaises(ValueError):
                self.read(data.replace(b'unknown', unknown.encode()))

    def test_oversize_and_node_budgets_before_decoding_large_collections(self):
        data = b'{"format":"NVD_CVE","version":"2.0","vulnerabilities":[{"cve":{"id":"CVE-2026-12345","many":[0,0,0,0,0,0,0,0,0,0]}}]}'
        with patch.object(catalog_stream, 'MAX_NODES', 10), self.assertRaises(ValueError):
            self.read(data)
        with patch.object(catalog_stream, 'MAX_VALUE_BYTES', 50), self.assertRaises(ValueError):
            self.read(data)
        # Whole-file loaders and unbounded reads are not needed for the streaming boundary.
        reads = []
        class Reader:
            def __init__(self, file):
                self.file = file
            def read(self, size=-1):
                reads.append(size)
                if not 0 <= size <= 65536:
                    raise AssertionError('unbounded read')
                return self.file.read(size)
            def seek(self, *args):
                return self.file.seek(*args)
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.file.close()
        self.path.write_bytes(data)
        import builtins
        original_open = builtins.open
        def bounded_open(path, *args, **kwargs):
            return Reader(original_open(path, *args, **kwargs))
        with patch('builtins.open', bounded_open):
            self.assertEqual(len(list(catalog_stream.FeedStream(self.path))), 1)
        self.assertTrue(reads)


if __name__ == '__main__':
    unittest.main()
