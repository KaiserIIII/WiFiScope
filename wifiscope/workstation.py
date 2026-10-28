"""Bounded offline input and local case operations shared by CLI and Tk."""
import copy
import json
from pathlib import Path

from .audit import assess
from .cases import CaseStore
from .importers import import_nmap, import_greenbone
from .investigate import build_investigation
from .packets import analyze_capture
from .wifi import decode_console, parse_netsh, parse_nmcli

MAX_INPUT = 16 * 1024 * 1024


def read_bounded(path, limit=MAX_INPUT):
    with Path(path).open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Input exceeds the 16 MiB limit; split the evidence file.')
    return data


def existing_case(path):
    if not Path(path).is_file():
        raise ValueError('Case file does not exist; check the path or use case add to create one.')
    return path


def load_json(path):
    def reject_constant(value):
        raise ValueError('Non-finite JSON values are unsupported.')
    try:
        report = json.loads(read_bounded(path), parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('Invalid bounded UTF-8 report JSON; select a WiFiScope snapshot.') from None
    if not isinstance(report, dict):
        raise ValueError('Report JSON must be an object.')
    # Enforce nested/typed budgets before processing or rendering arbitrary JSON.
    from .case_validation import validate_report
    validate_report(report)
    for target in report.get('connectivity', []):
        if 'dns' in target and not isinstance(target['dns'], dict):
            raise ValueError('Connectivity DNS evidence must be a typed record.')
    return report


def open_evidence(path, kind):
    if kind == 'json':
        return load_json(path)
    data = read_bounded(path)
    if kind in ('pcap', 'pcapng'):
        # The selected container must agree with its magic; parser validates body.
        if (data.startswith(b'\x0a\x0d\x0d\x0a')) != (kind == 'pcapng'):
            raise ValueError('Capture format does not match the selected file type.')
        report = analyze_capture(data)
    elif kind in ('nmap', 'greenbone'):
        report = (import_nmap if kind == 'nmap' else import_greenbone)(data)
    elif kind in ('netsh', 'nmcli'):
        report = dict(wifi=(parse_netsh if kind == 'netsh' else parse_nmcli)(decode_console(data)), gaps=[])
        report['findings'] = assess(report)
    else:
        raise ValueError('Choose nmap, greenbone, pcap, pcapng, netsh, nmcli or json explicitly.')
    return build_investigation(report)


def with_triage(report, overlay):
    result = copy.deepcopy(report)
    for row in result.get('investigation', {}).get('findings', []):
        state = overlay.get(row.get('id'))
        if state:
            row['triage_status'] = state['status']
    return result


def controlled_report(report):
    """Workstation exports use registered finding prose, including raw opt-ins.

    The legacy report API can preserve local top-level prose for its callers;
    imported workstation data never treats that prose as an export instruction.
    """
    if isinstance(report, dict):
        return {key: controlled_report(value) for key, value in report.items()
                if key not in ('title', 'recommendation', 'retest')}
    if isinstance(report, list):
        return [controlled_report(value) for value in report]
    return report


def snapshot_triage(store, snapshot_id, report):
    """Collect all relevant snapshot states through bounded history pages.

    Notes stay in the local overlay. Only with_triage's status projection is
    eligible for an ordinary report export.
    """
    relevant = {row.get('id') for row in report.get('findings', [])}
    relevant.update(row.get('id') for row in report.get('investigation', {}).get('findings', []))
    relevant.discard(None)
    overlay, offset = {}, 0
    while relevant - overlay.keys():
        page = store.triage_state(snapshot_id=snapshot_id, limit=100, offset=offset)
        overlay.update({key: state for key, state in page.items() if key in relevant})
        if len(page) < 100:
            break
        offset += 100
    return overlay


def case_snapshot(path, snapshot_id):
    with CaseStore(existing_case(path)) as store:
        report = store.load_snapshot(snapshot_id)
        overlay = snapshot_triage(store, snapshot_id, report)
        return dict(report=report, overlay=overlay, snapshot_id=snapshot_id, case_path=str(path), history=store.snapshots(limit=100))
