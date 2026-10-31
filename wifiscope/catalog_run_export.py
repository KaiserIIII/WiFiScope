"""Consistent, private-by-default local bundles of bounded saved-run pages.

One ephemeral key links a bundle's pages. Local SQLite integrity checks do not
authenticate replacement of a run by someone able to rewrite the local file.
"""
import json
import os
from pathlib import Path
import secrets
import shutil
import tempfile

from .catalog_runs import _RunReader
from .catalog_store import _safe_path
from .case_validation import validate_report
from .export_schema import _project_identity, _project_report
from .reports import export_report


def _check_cancel(cancel):
    try:
        stopped = cancel is not None and bool(cancel() if callable(cancel) else cancel.is_set())
    except Exception:
        raise ValueError('Cannot check local run export cancellation.') from None
    if stopped:
        raise ValueError('Local run export cancelled.')


def _publish(staging, destination, cancel):
    """Reserve exclusively; on failure remove only files/directories we created."""
    files, directories = [], []
    def enumeration_error(error):
        raise error
    try:
        _check_cancel(cancel)
        destination.mkdir(exist_ok=False)
        directories.append(destination)
        for source_root, _, names in os.walk(staging, onerror=enumeration_error):
            target_root = destination / Path(source_root).relative_to(staging)
            if target_root != destination:
                _check_cancel(cancel)
                target_root.mkdir(exist_ok=False)
                directories.append(target_root)
            for name in names:
                _check_cancel(cancel)
                target = target_root / name
                os.link(Path(source_root) / name, target)
                files.append(target)
        _check_cancel(cancel)
    except BaseException:
        for target in reversed(files):
            target.unlink(missing_ok=True)
        for directory in reversed(directories):
            try:
                directory.rmdir()
            except OSError:
                pass  # Preserve unrelated files created during publication.
        raise


def export_run(run_path, destination, *, include_identifiers=False, cancel=None):
    """Export one reader snapshot; receipt contains only state, count and success.

    Destination must be new, local, link-free, and in an existing directory.
    No source database, binding paths or secret key is copied to the bundle.
    """
    staging = None
    try:
        if type(include_identifiers) is not bool:
            raise ValueError('Identifier retention requires a boolean choice.')
        destination = _safe_path(destination, destination=True)
        _check_cancel(cancel)
        with _RunReader(run_path) as reader:
            status = reader.status()
            key = secrets.token_bytes(32)
            _check_cancel(cancel)
            staging = Path(tempfile.mkdtemp(prefix='.wifiscope-run-', dir=destination.parent))
            retained = include_identifiers
            for number in range(1, status['page_count'] + 1):
                _check_cancel(cancel)
                projected = _project_report(reader.read_page(number), include_identifiers, key)
                validate_report(projected)
                retained = retained and projected['identifiers_included']
                _check_cancel(cancel)
                # Already projected: preserve IDs and the effective retention flag.
                export_report(projected, staging / f'page-{number:04d}', include_identifiers=True)
                _check_cancel(cancel)
            summary = dict(status, scope='run', identifiers_included=retained)
            summary['run_id'] = _project_identity(status['run_id'], include_identifiers, key)
            _check_cancel(cancel)
            (staging / 'summary.json').write_text(
                json.dumps(summary, ensure_ascii=False, indent=2, allow_nan=False) + '\n', encoding='utf8')
            _publish(staging, destination, cancel)
            return dict(status=status['state'], page_count=status['page_count'], bundle_created=True)
    except Exception:
        raise ValueError('Cannot export this local catalog audit run.') from None
    finally:
        if staging is not None:
            try:
                shutil.rmtree(staging)
            except OSError:
                raise ValueError('Cannot clean up this local catalog audit export.') from None
