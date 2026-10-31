"""Explicit local catalog operations. Stdout contains controlled public facts only."""
import json

from .catalog_store import CatalogIndex, build_catalog


def add_parser(commands):
    command = commands.add_parser('catalog', help='Build and query an immutable local NVD/CNA catalog')
    actions = command.add_subparsers(dest='catalog_action', required=True)
    build = actions.add_parser('build', help='Build a NEW database from explicit local NVD JSON/gzip files')
    build.add_argument('--input', required=True, action='append')
    build.add_argument('--out', required=True)
    build.add_argument('--sha256', action='append', help='Expanded SHA256, once per input in input order')
    audit = actions.add_parser('audit', help='Audit explicit local inventory without collection')
    audit.add_argument('--db', required=True)
    audit.add_argument('--inventory', required=True)
    audit.add_argument('--inventory-format', choices=('native', 'cyclonedx', 'spdx', 'nmap'), default='native',
                       help='Explicit local identity format; no remote resolution')
    audit.add_argument('--input')
    audit.add_argument('--sha256')
    audit.add_argument('--out')
    audit.add_argument('--include-identifiers', action='store_true')
    saved = actions.add_parser('run', help='Explicit local saved audit; raw storage requires separate consent')
    runs = saved.add_subparsers(dest='run_action', required=True)
    for name in ('start', 'continue', 'status', 'page', 'export'):
        action = runs.add_parser(name)
        action.add_argument('--run', required=True)
        if name in ('start', 'continue'):
            action.add_argument('--db', required=True)
        if name == 'start':
            action.add_argument('--inventory', required=True)
            action.add_argument('--inventory-format', choices=('native', 'cyclonedx', 'spdx', 'nmap'), default='native')
            action.add_argument('--input')
            action.add_argument('--sha256')
            action.add_argument('--page-size', type=int, default=256)
            action.add_argument('--store-raw-identifiers', action='store_true')
        if name in ('page', 'export'):
            action.add_argument('--out', required=name == 'export')
            action.add_argument('--include-identifiers', action='store_true')
        if name == 'page':
            action.add_argument('--number', type=int, required=True)
    for name in ('info', 'search'):
        action = actions.add_parser(name)
        action.add_argument('--db', required=True)
        action.add_argument('--sha256', help='Expected database SHA256 (integrity only)')
        if name == 'search':
            action.add_argument('--cve')
            action.add_argument('--vendor')
            action.add_argument('--product')
            action.add_argument('--limit', type=int, default=20)
            action.add_argument('--offset', type=int, default=0)


def _saved_run(args):
    import signal
    import threading
    from .catalog_runs import advance_run, create_run, export_run, read_run_page, run_status
    from .catalog_store import _safe_path
    from .cli import emit
    from .inventory_import import import_inventory
    from .reports import export_report
    from .workstation import load_json

    cancel = threading.Event()
    previous = None
    if args.run_action in ('start', 'continue', 'export') and threading.current_thread() is threading.main_thread():
        previous = signal.signal(signal.SIGINT, lambda *_: cancel.set())
    try:
        action = args.run_action
        if action == 'start':
            # Consent precedes any output creation and is independent of export.
            if not args.store_raw_identifiers:
                raise ValueError('Explicit local raw-identifier storage consent is required (--store-raw-identifiers).')
            evidence = load_json(_safe_path(args.input)) if args.input else dict(schema_version=1)
            inventory = import_inventory(args.inventory, format=args.inventory_format, cancel=cancel)
            create_run(args.run, evidence, inventory, args.db, expected_sha256=args.sha256,
                       page_size=args.page_size, store_raw_identifiers=True, cancel=cancel)
        if action in ('start', 'continue'):
            result = advance_run(args.run, args.db, cancel=cancel)
            print(json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2))
            if cancel.is_set() or result['stop_reason'] == 'cancelled':
                return 130
            return 0 if result['computation_complete'] and not result['source_partial'] else 1
        if action == 'status':
            result = run_status(args.run)
        elif action == 'page':
            report = read_run_page(args.run, args.number)
            if args.out:
                export_report(report, _safe_path(args.out, destination=True), args.include_identifiers)
                result = dict(status='partial', scope='page', bundle_created=True)
            else:
                emit(report, args)
                return 0
        else:
            result = export_run(args.run, args.out, include_identifiers=args.include_identifiers, cancel=cancel)
        print(json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2))
        return 0
    except ValueError:
        if cancel.is_set():
            return 130
        raise
    finally:
        if previous is not None:
            signal.signal(signal.SIGINT, previous)


def run(args):
    if args.catalog_action == 'run':
        return _saved_run(args)
    if args.catalog_action == 'audit':
        from .catalog_audit import audit_catalog
        from .inventory_import import import_inventory
        from .workstation import load_json
        from .cli import emit
        from .catalog_store import _safe_path
        evidence = load_json(_safe_path(args.input)) if args.input else dict(schema_version=1)
        with CatalogIndex(args.db, expected_sha256=args.sha256) as index:
            report = audit_catalog(evidence, import_inventory(args.inventory, format=args.inventory_format), index)
        if args.out:
            # Shared exporter produces the exclusive bundle. Its legacy return
            # contains local file paths, so only expose a controlled receipt.
            from .reports import export_report
            export_report(report, _safe_path(args.out, destination=True), args.include_identifiers)
            print(json.dumps(dict(status=report['catalog_audit']['status'], bundle_created=True)))
        else:
            emit(report, args)
        status = report['catalog_audit']['status']
        return 130 if status == 'cancelled' else 1 if status == 'partial' else 0
    if args.catalog_action == 'build':
        result = build_catalog(args.input, args.out, expected_sha256=args.sha256)
    else:
        with CatalogIndex(args.db, expected_sha256=args.sha256) as index:
            result = index.info() if args.catalog_action == 'info' else index.search(
                cve=args.cve, vendor=args.vendor, product=args.product, limit=args.limit, offset=args.offset)
    print(json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2))
    return 0
