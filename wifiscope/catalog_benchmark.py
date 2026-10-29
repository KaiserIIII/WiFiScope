"""Reproducible bounded synthetic capacity helper, no downloads or real CVEs.

Run with ``python -m wifiscope.catalog_benchmark --directory NEW_DIR --records 10000``.
Memory is tracemalloc's Python-allocation peak, NOT process/SQLite/system memory.
"""
import argparse
import gzip
import hashlib
import json
import platform
import sqlite3
import time
import tracemalloc

from .catalog_store import CatalogIndex, _safe_path, build_catalog
from .catalog_stream import CatalogCancelled


def _source(path, count):
    digest = hashlib.sha256()
    def write(stream, value):
        raw = value.encode('utf-8')
        stream.write(raw)
        digest.update(raw)
    with gzip.open(path, 'xb') as stream:
        write(stream, json.dumps(dict(format='NVD_CVE', version='2.0', totalResults=count,
             startIndex=0, resultsPerPage=count))[:-1]+',"vulnerabilities":[')
        for number in range(count):
            row = dict(cve=dict(id=f'CVE-2099-{1000000+number}', vulnStatus='Analyzed', configurations=[dict(
                nodes=[dict(operator='OR', cpeMatch=[dict(vulnerable=True,
                criteria=f'cpe:2.3:a:invented_vendor:synthetic_product_{number % 100}:1.0:*:*:*:*:*:*:*')])])]))
            write(stream, (',' if number else '')+json.dumps(row, separators=(',', ':')))
        write(stream, ']}')
    return digest.hexdigest()


def benchmark(directory, *, records=10000):
    """Create an explicit NEW local directory; retain generated input + DB there.

    One local run: source generation excluded from build/query timings. Query
    batch includes open/info/first+last get and two relevant cursor pages. A
    second build is cancelled on its third cooperative cancellation check.
    Files from a failed run remain reviewable inside this owned directory.
    """
    if type(records) is not int or not 1 <= records <= 1000000:
        raise ValueError('Synthetic record count must be 1..1000000.')
    target = _safe_path(directory, destination=True)
    if target.exists() or tracemalloc.is_tracing():
        raise ValueError('Use a new directory and a dedicated interpreter for benchmark measurement.')
    target.mkdir()
    source, database, cancelled = target / 'synthetic.json.gz', target / 'catalog.db', target / 'cancelled.db'
    tracemalloc.start()
    try:
        pin = _source(source, records)
        begin = time.perf_counter()
        info = build_catalog([source], database, expected_sha256=[pin])
        build_seconds = time.perf_counter()-begin
        begin = time.perf_counter()
        with CatalogIndex(database) as index:
            stored = index.info()['records']
            first = index.get('CVE-2099-1000000')
            last = index.get(f'CVE-2099-{999999+records}')
            identities = [dict(kind='cpe', part='a', vendor='invented_vendor', product='synthetic_product_0')]
            page = index.relevant(identities, limit=20)
            next_page = index.relevant(identities, limit=20, after=page['next_after']) if page['next_after'] else None
        query_seconds = time.perf_counter()-begin
        if stored != records or first is None or last is None:
            raise ValueError('Synthetic count/endpoint verification failed.')
        calls = 0
        def stop():
            nonlocal calls
            calls += 1
            return calls >= 3
        begin = time.perf_counter()
        try:
            build_catalog([source], cancelled, cancel=stop)
        except CatalogCancelled:
            pass
        else:
            raise ValueError('Synthetic cancellation probe did not cancel.')
        cancel_seconds = time.perf_counter()-begin
        peak = tracemalloc.get_traced_memory()[1]
        cleaned = not cancelled.exists() and not list(target.glob('.wifiscope-catalog-*'))
        return dict(synthetic=True, input_records=records, stored_records=stored,
            build_seconds=build_seconds, query_batch_seconds=query_seconds,
            cooperative_cancel_probe_seconds=cancel_seconds, cancellation_check_calls=calls,
            cancelled_build_cleaned=cleaned, python_traced_peak_bytes=peak,
            database_bytes=database.stat().st_size, source_bytes=source.stat().st_size,
            expanded_sha256=pin, catalog_id=info['catalog_id'],
            first_page_records=len(page['records']), second_page_records=len(next_page['records']) if next_page else 0,
            python=platform.python_version(), sqlite=sqlite3.sqlite_version)
    finally:
        tracemalloc.stop()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, help='NEW local directory; generated files retained')
    parser.add_argument('--records', type=int, default=10000)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(benchmark(args.directory, records=args.records), indent=2))
        return 0
    except (OSError, ValueError):
        parser.exit(2, 'Benchmark refused: check the new local directory, count and resource budgets.\n')


if __name__ == '__main__':
    raise SystemExit(main())
