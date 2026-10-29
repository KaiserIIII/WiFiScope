"""Command-line workstation; stdout reports share the bundle privacy boundary."""
import argparse
import json
import sys

from .batch import audit_scope, plan_scope
from .cases import CaseStore, STATUSES
from .collect import collect_local
from .comparison import compare_snapshots
from .demo import demo_report
from .investigate import build_investigation, merge_reports
from .probe import probe_hosts
from .reports import export_report, prepare_export
from .workstation import controlled_report, existing_case, load_json, open_evidence, snapshot_triage, with_triage


def parser():
    p = argparse.ArgumentParser(prog='wifiscope', description='Local evidence workstation. Active checks require an explicit authorized target. No dependency installation required.')
    commands = p.add_subparsers(dest='command')
    from .vulnerability_cli import add_parser
    add_parser(commands)
    from .capture_cli import add_parser as add_capture_parser
    add_capture_parser(commands)
    from .survey_cli import add_parser as add_survey_parser
    add_survey_parser(commands)
    commands.add_parser('gui', help='Open the Chinese Tk workstation (default)')
    for name in ('demo', 'collect', 'probe', 'audit', 'analyze', 'import-scan', 'packets', 'compare', 'merge'):
        sub = commands.add_parser(name)
        sub.add_argument('--out', help='New bundle directory; existing paths are refused')
        sub.add_argument('--include-identifiers', action='store_true', help='Explicitly retain identifiers in this export/stdout (separate from case retention)')
        if name in ('analyze', 'import-scan', 'packets', 'merge'):
            sub.add_argument('--input', required=True, action='append' if name == 'merge' else 'store')
        if name in ('analyze', 'import-scan'):
            sub.add_argument('--format', required=True, choices=('netsh', 'nmcli') if name == 'analyze' else ('nmap', 'greenbone'))
        if name == 'compare':
            sub.add_argument('before')
            sub.add_argument('after')
        if name in ('probe', 'audit'):
            sub.add_argument('--authorized', action='store_true')
            sub.add_argument('--port', type=int, action='append')
            sub.add_argument('--timeout', type=float, default=.5 if name == 'audit' else 2)
        if name == 'probe':
            sub.add_argument('--host', action='append', required=True)
            sub.add_argument('--attempts', type=int, default=3)
            sub.add_argument('--url', action='append', default=[])
        if name == 'audit':
            sub.add_argument('--scope', action='append', required=True, help='Explicit IP or CIDR; aggregate max 64 hosts')
            sub.add_argument('--deadline', type=float, default=300)
            sub.set_defaults(require_out=True)
    case = commands.add_parser('case', help='Local append-only case snapshots and triage')
    actions = case.add_subparsers(dest='action', required=True)
    for action in ('list', 'add', 'show', 'verify', 'triage', 'compare'):
        sub = actions.add_parser(action)
        sub.add_argument('--db', required=True)
        if action == 'list':
            sub.add_argument('--limit', type=int, default=100)
            sub.add_argument('--offset', type=int, default=0)
        if action == 'add':
            sub.add_argument('--input', required=True)
            sub.add_argument('--include-identifiers', action='store_true', help='Retain raw identifiers in the case database')
        if action in ('show', 'triage'):
            sub.add_argument('--snapshot', type=int, required=True)
        if action in ('show', 'compare'):
            sub.add_argument('--include-identifiers', action='store_true', help='Explicit raw/persisted-ID stdout export')
            sub.add_argument('--out')
        if action == 'verify':
            sub.add_argument('--expected-head', help='Trusted external SHA256 receipt')
        if action == 'triage':
            sub.add_argument('--finding', required=True, help='Persisted finding ID from case show --include-identifiers')
            sub.add_argument('--status', required=True, choices=sorted(STATUSES))
            sub.add_argument('--note', default='', help='Local-only note; never exported')
        if action == 'compare':
            sub.add_argument('before', type=int)
            sub.add_argument('after', type=int)
    return p


def _json(value):
    print(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False))


def emit(report, args):
    report = controlled_report(report)
    if args.out:
        _json(export_report(report, args.out, args.include_identifiers))
    else:
        _json(prepare_export(report, args.include_identifiers))


def case_command(args):
    if args.action != 'add':
        existing_case(args.db)
    with CaseStore(args.db) as store:
        if args.action == 'verify':
            result = store.verify(args.expected_head)
            _json(result)
            return 0 if result['ok'] else 1
        if args.action == 'list':
            if not store.verify()['ok']:
                raise ValueError('Case integrity verification failed; preserve the database.')
            # Only typed metadata; no report bodies, notes or event payloads.
            pages = store.snapshots(args.limit, args.offset)
            for row in pages:
                row['summary'] = {key: value for key, value in row['summary'].items()
                                  if key in ('assets', 'findings', 'measured', 'imported', 'unknown')
                                  and type(value) is int and value >= 0}
            _json(pages)
        elif args.action == 'add':
            identifier = store.add_snapshot(load_json(args.input), include_identifiers=args.include_identifiers)
            _json(dict(snapshot_id=identifier, identifiers_included=store.load_snapshot(identifier)['identifiers_included']))
        elif args.action == 'show':
            report = store.load_snapshot(args.snapshot)
            emit(with_triage(report, snapshot_triage(store, args.snapshot, report)), args)
        elif args.action == 'triage':
            seq = store.triage(args.finding, args.status, args.note, snapshot_id=args.snapshot)
            _json(dict(event_seq=seq, snapshot_id=args.snapshot, triage_status=args.status))
        elif args.action == 'compare':
            report = compare_snapshots(store.load_snapshot(args.before), store.load_snapshot(args.after), before_id=args.before, after_id=args.after)
            if report['comparison']['mode'] == 'counts-only':
                print('Counts only: both persisted snapshots must retain identifiers for identity correlation.', file=sys.stderr)
            emit(report, args)
    return 0


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command in (None, 'gui'):
            try:
                from .gui import launch
            except ImportError:
                print('WiFiScope: Tk unavailable. Use python -m wifiscope demo --out NEW_DIR; enable your OS Python Tk package for the GUI.', file=sys.stderr)
                return 2
            return launch()
        if args.command == 'case':
            return case_command(args)
        if getattr(args, 'require_out', False) and not args.out:
            raise ValueError('audit requires --out with a new bundle directory for partial evidence.')
        if args.command == 'demo':
            report = demo_report()
        elif args.command == 'capture':
            if args.list_interfaces:
                from .capture_cli import list_interfaces
                _json(list_interfaces(args))
                return 0
            from .capture_cli import run
            report = run(args)
        elif args.command == 'vuln':
            from .vulnerability_cli import run
            report = run(args)
        elif args.command == 'survey':
            from .survey_cli import run
            report = run(args)
        elif args.command == 'collect':
            report = build_investigation(collect_local())
        elif args.command == 'probe':
            report = build_investigation(dict(connectivity=probe_hosts(args.host, args.port or [], authorized=args.authorized, attempts=args.attempts, timeout=args.timeout, urls=args.url)))
        elif args.command == 'audit':
            plan = plan_scope(args.scope, args.port)
            print(f"Planned: {len(plan['hosts'])} hosts, {len(plan['ports'])} ports; {plan['planned_connections']} connections including TLS diagnostics; approximate rate-based planning estimate {plan['minimum_seconds']:.2f}s at 4 connections/s (first start can be immediate). Ports: {plan['ports']}", file=sys.stderr)
            report = audit_scope(args.scope, args.port, authorized=args.authorized, timeout=args.timeout, deadline=args.deadline)
        elif args.command in ('analyze', 'import-scan'):
            report = open_evidence(args.input, args.format)
        elif args.command == 'packets':
            from .workstation import read_bounded
            from .packets import analyze_capture
            report = build_investigation(analyze_capture(read_bounded(args.input)))
        elif args.command == 'merge':
            if len(args.input) > 16:
                raise ValueError('Merge at most 16 bounded reports at a time.')
            report = merge_reports([load_json(path) for path in args.input])
        else:
            report = compare_snapshots(load_json(args.before), load_json(args.after))
            if report['comparison']['mode'] == 'counts-only':
                print('Counts only: per-export pseudonyms cannot correlate identities. Use both identifier-retaining snapshots.', file=sys.stderr)
        emit(report, args)
        # Historical run cancellation is evidence, not cancellation of this merge.
        if args.command == 'merge':
            return 0
        if args.command == 'capture':
            return 130 if report['capture_session']['status'] == 'cancelled' else 1 if report['capture_session']['status'] == 'partial' else 0
        run = report.get('run', {})
        return 130 if run.get('status') == 'cancelled' else 1 if run.get('status') in ('partial', 'deadline') else 0
    except (OSError, ValueError, UnicodeError, RecursionError, TypeError, KeyError) as error:
        # Bounded known instructions only: no untrusted file contents/paths/notes.
        message = str(error) if isinstance(error, ValueError) and not isinstance(error, json.JSONDecodeError) else 'Cannot process evidence; check format, permissions and a new output directory.'
        if len(message) > 240:
            message = 'Cannot process evidence; check the selected format and bounded typed report schema.'
        print('WiFiScope: ' + message, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('WiFiScope: cancelled. Use audit for retained partial batch evidence.', file=sys.stderr)
        return 130
