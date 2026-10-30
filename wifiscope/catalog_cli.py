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


def run(args):
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
