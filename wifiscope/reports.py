"""Privacy-preserving local report bundles."""
import csv
import html
import io
import json
import os
from pathlib import Path
import shutil
import tempfile

def prepare_export(report: dict, include_identifiers: bool = False) -> dict:
    """Return an independent allowlisted snapshot with per-export pseudonyms."""
    from .export_schema import project_report
    return project_report(report, include_identifiers)


def _csv_cell(value):
    text = '' if value is None else str(value)
    # Leading whitespace can hide formula prefixes in spreadsheet programs.
    if text.lstrip().startswith(('=', '+', '-', '@')) or text.startswith(('\t', '\r', '\n')):
        return "'" + text
    return text


def _packets_html(prepared):
    contexts = prepared.get('packet_analysis_contexts')
    if not isinstance(contexts, list):
        contexts = [prepared['packet_analysis']] if isinstance(prepared.get('packet_analysis'), dict) else []
    if not contexts:
        return ''
    rows = ''.join('<tr>' + ''.join('<td>' + html.escape(str(context.get(field, '')), quote=True) + '</td>'
        for field in ('source_sha256', 'packets', 'captured_bytes', 'plaintext_http_packets', 'dns_queries', 'dns_nxdomain', 'partial')) + '</tr>'
        for context in contexts if isinstance(context, dict))
    return '<section><h2>Offline packet metadata</h2><p>Only bounded metadata is retained. Capture scope and gaps limit conclusions; checksums, retransmission causes, timing accuracy and offload behavior are not established. Distinct captures retain separate counts.</p><table><tr><th>Source</th><th>Packets</th><th>Captured bytes</th><th>HTTP requests</th><th>DNS queries</th><th>NXDOMAIN responses</th><th>Partial</th></tr>' + rows + '</table></section>'


def export_report(report: dict, directory: str | Path, include_identifiers: bool = False) -> dict[str, str]:
    """Publish complete JSON/CSV/HTML files in a newly created bundle directory.

    An existing directory (even empty) is rejected. Files are staged in a sibling
    directory and atomically linked only after all formats are fully written.
    """
    directory = Path(directory).absolute()
    if directory.exists():
        raise FileExistsError('Choose a new report bundle directory.')
    directory.parent.mkdir(parents=True, exist_ok=True)
    prepared = prepare_export(report, include_identifiers)
    rows = []

    def flatten(value, path='report'):
        if isinstance(value, dict):
            for name, content in value.items():
                flatten(content, path + '.' + name)
        elif isinstance(value, list):
            for index, content in enumerate(value):
                flatten(content, path + '[' + str(index) + ']')
        else:
            rows.append((path, value))

    flatten(prepared)
    buffer = io.StringIO(newline='')
    writer = csv.writer(buffer)
    writer.writerow(('field', 'value'))
    writer.writerows((_csv_cell(field), _csv_cell(value)) for field, value in rows)
    html_rows = ''.join('<tr><th>' + html.escape(field, quote=True) + '</th><td>' + html.escape('' if value is None else str(value), quote=True) + '</td></tr>' for field, value in rows)
    from .report_html import render
    document = render(prepared, html_rows, _packets_html(prepared))
    staging = Path(tempfile.mkdtemp(prefix='.wifiscope-', dir=directory.parent))
    published = []
    reserved = False
    try:
        (staging / 'report.json').write_text(json.dumps(prepared, ensure_ascii=False, indent=2, allow_nan=False) + '\n', encoding='utf-8')
        (staging / 'report.csv').write_text(buffer.getvalue(), encoding='utf-8-sig', newline='')
        (staging / 'report.html').write_text(document, encoding='utf-8')
        # Both directory reservation and hard-link creation fail if the output
        # already exists. Hard links expose only completed files and never replace.
        directory.mkdir(exist_ok=False)
        reserved = True
        for suffix in ('json', 'csv', 'html'):
            target = directory / ('report.' + suffix)
            os.link(staging / ('report.' + suffix), target)
            published.append(target)
    except BaseException:
        for target in published:
            target.unlink(missing_ok=True)
        if reserved:
            try:
                directory.rmdir()
            except OSError:
                pass  # Never remove files created by someone else.
        raise
    finally:
        shutil.rmtree(staging)
    return {suffix: str(directory / ('report.' + suffix)) for suffix in ('json', 'csv', 'html')}


def compare_reports(before: dict, after: dict) -> dict:
    """Compare BSSID observations only when snapshots retain identifiers."""
    if before.get('identifiers_included') is False or after.get('identifiers_included') is False:
        raise ValueError('Per-export pseudonyms cannot be correlated. Compare in-memory reports or explicitly export both with identifiers included.')
    def keyed(report):
        return {row['bssid']: row for row in report.get('wifi', []) if isinstance(row, dict) and row.get('bssid')}
    left, right = keyed(before), keyed(after)
    changes = [dict(bssid=bssid, before=left.get(bssid), after=right.get(bssid)) for bssid in sorted(left.keys() | right.keys()) if left.get(bssid) != right.get(bssid)]
    return dict(wifi_changes=changes, findings_before=len(before.get('findings', [])), findings_after=len(after.get('findings', [])), gaps_before=before.get('gaps', []), gaps_after=after.get('gaps', []))
