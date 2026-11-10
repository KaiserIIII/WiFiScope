"""CLI entry points for the campus field audit and paired reachability."""
import getpass
import json
import signal
import sys
import threading

from .field_report import check_new_path, project_field, save_field


def add_parser(commands):
    field = commands.add_parser('field', help='Campus link, gateway, portal and controlled peer evidence')
    actions = field.add_subparsers(dest='field_action', required=True)
    audit = actions.add_parser('audit', help='Local configuration and optional explicit active checks')
    audit.add_argument('--interface', help='Select the local adapter by name')
    audit.add_argument('--source', help='Bind active connections to this local numeric address')
    audit.add_argument('--gateway', help='Explicit numeric gateway address')
    audit.add_argument('--gateway-port', action='append', type=int, dest='gateway_ports')
    audit.add_argument('--portal', action='append', default=[], dest='portals',
                       help='Explicit HTTP(S) URL, at most two; HEAD only, no redirects')
    audit.add_argument('--samples', type=int, default=3)
    audit.add_argument('--interval', type=float, default=1)
    audit.add_argument('--timeout', type=float, default=2)
    audit.add_argument('--peer', action='append', default=[], dest='peers',
                       help='One explicit numeric peer address, up to eight')
    audit.add_argument('--peer-port', action='append', type=int, dest='peer_ports')
    audit.add_argument('--dns', help='Explicit UDP DNS resolver IP')
    audit.add_argument('--ntp', help='Explicit UDP NTP server IP')
    audit.add_argument('--doh', help='Explicit HTTPS DoH URL')
    audit.add_argument('--download', help='Explicit HTTPS download URL for a bounded sample')
    audit.add_argument('--include-identifiers', action='store_true')
    listen = actions.add_parser('listen', help='Open a temporary paired test listener on this device')
    listen.add_argument('--bind', required=True)
    listen.add_argument('--expect-peer', required=True)
    listen.add_argument('--seconds', type=float, default=60)
    check = actions.add_parser('check', help='Check a temporary paired listener on the other device')
    check.add_argument('--target', required=True)
    check.add_argument('--port', required=True, type=int)
    check.add_argument('--source')
    check.add_argument('--timeout', type=float, default=2)
    check.add_argument('--code', help='Test code (omit to enter it without terminal echo)')
    for action in (audit, listen, check):
        action.add_argument('--authorized', action='store_true')
        action.add_argument('--out', help='New JSON file in an existing directory')


def _emit(report, args):
    include = getattr(args, 'include_identifiers', False)
    if args.out:
        print(json.dumps({'json': save_field(report, args.out, include)}, ensure_ascii=False))
    else:
        print(json.dumps(project_field(report, include), ensure_ascii=False, indent=2, allow_nan=False))


def run(args):
    if args.out:
        check_new_path(args.out)
    cancel = threading.Event()
    handler = None
    if threading.current_thread() is threading.main_thread():
        handler = signal.signal(signal.SIGINT, lambda *_: cancel.set())
    try:
        if args.field_action == 'audit':
            from .field_audit import run_field

            options = vars(args).copy()
            for key in ('command', 'field_action', 'include_identifiers', 'out'):
                options.pop(key)
            report = run_field(**{k: v for k, v in options.items() if v is not None}, cancel=cancel)
            code = 0
        else:
            from .field_pair import check_peer, serve_peer

            if args.authorized is not True:
                raise ValueError('Explicit authorization is required for the paired check.')
            if args.field_action == 'listen':
                report = serve_peer(args.bind, args.expect_peer, seconds=args.seconds, authorized=True,
                                    cancel=cancel, ready=lambda row: print(json.dumps(row), file=sys.stderr, flush=True))
                report.update(role='listener', source=args.bind, target=args.expect_peer)
            else:
                # A cooperative SIGINT handler would keep a password prompt blocked.
                if args.code is None and handler is not None:
                    signal.signal(signal.SIGINT, handler)
                code = args.code if args.code is not None else getpass.getpass('Temporary pairing code: ')
                if args.code is None and handler is not None:
                    signal.signal(signal.SIGINT, lambda *_: cancel.set())
                report = check_peer(args.target, args.port, code, source=args.source,
                                    timeout=args.timeout, authorized=True, cancel=cancel)
                report.update(role='client', source=args.source, target=args.target)
            report.update(kind='campus-peer-check', schema_version=1)
            code = 0 if report['status'] == 'handshake_verified' else 1
        _emit(report, args)
        return 130 if report['status'] == 'cancelled' else code
    finally:
        if handler is not None:
            signal.signal(signal.SIGINT, handler)
