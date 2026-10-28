"""Display-independent controller. Workers deliver values; poll owns model updates."""
import copy
import queue
import threading

from .case_validation import validate_report
from .cases import CaseStore
from .investigate import merge_reports, run_summary
from .reports import export_report
from .guidance import ERRORS, GuidanceError
from .workstation import case_snapshot, controlled_report, existing_case, open_evidence, with_triage


class Controller:
    def __init__(self):
        self.report = None
        self.overlay = {}
        self.snapshot_id = None
        self.case_path = None
        self.history = []
        self.status = 'Ready / 就绪'
        self.source = 'No evidence / 尚无证据'
        self.result = None
        self.busy = False
        self.worker = None
        self.stop = threading.Event()
        self.messages = queue.Queue()
        self.owner = threading.get_ident()

    def _main(self):
        if threading.get_ident() != self.owner:
            raise RuntimeError('Controller model updates belong to the main thread.')

    def start(self, label, work, kind='report', *, error_code='unknown'):
        self._main()
        if self.busy:
            raise GuidanceError('busy')
        self.busy = True
        self.stop = threading.Event()
        self.status = 'Running / 进行中: ' + label
        self.result = None
        def execute():
            try:
                result = work(self.stop)
                self.messages.put((kind, label, result, self.stop.is_set()))
            except Exception as error:
                code = error.code if isinstance(error, GuidanceError) else error_code
                self.messages.put(('error', label, ERRORS.get(code, ERRORS['unknown']), self.stop.is_set()))
        self.worker = threading.Thread(target=execute, daemon=True, name='wifiscope-worker')
        self.worker.start()

    def cancel(self):
        self.stop.set()
        self.status = 'Cancelling / 正在取消；已获得的观测会保留。'

    def accept(self, report, source):
        self._main()
        validate_report(report)
        self.report = report
        self.source = source
        self.overlay = {}
        self.snapshot_id = None
        self.case_path = None
        self.history = []

    def poll(self):
        self._main()
        changed = False
        while True:
            try:
                kind, label, value, cancelled = self.messages.get_nowait()
            except queue.Empty:
                break
            changed = True
            self.busy = False
            self.result = value
            if kind == 'error':
                self.status = value
                continue
            try:
                if kind == 'report':
                    self.accept(value, label)
                elif kind == 'case':
                    self.accept(value['report'], label)
                    self.overlay = value['overlay']
                    self.snapshot_id = value['snapshot_id']
                    self.case_path = value['case_path']
                    self.history = value['history']
                elif kind == 'history':
                    self.history = value
            except (ValueError, TypeError, KeyError):
                self.status = 'Invalid evidence format / 证据格式无效；请检查类型化字段或重新加载演示。Previous snapshot preserved.'
                continue
            if kind == 'verification':
                self.status = ('Verified / 验证通过' if value['ok'] else 'Integrity failure / 完整性失败') + f" · {value['checked_events']} events · receipt: {value['head']}"
            else:
                state = run_summary(self.report or {}).get('status', 'unknown')
                self.status = ('cancelled / 已取消，保留部分结果' if cancelled else state + ' / 操作完成（请核查覆盖范围）') + ': ' + label
        return changed

    def import_evidence(self, path, kind, *, merge=False):
        current = copy.deepcopy(self.report) if merge else None
        def work(cancel):
            imported = open_evidence(path, kind)
            if current is not None and (current.get('identifiers_included') is False or imported.get('identifiers_included') is False):
                raise GuidanceError('privacycompare')
            if cancel.is_set():
                return current if current is not None else imported
            return merge_reports([current, imported]) if current is not None else imported
        self.start(('Merge / 合并: ' if current is not None else 'New snapshot / 替换当前: ') + kind, work, error_code='fileformat')

    def save_case(self, path, *, include_identifiers=False):
        if self.report is None:
            raise ValueError('Load evidence before saving a case snapshot.')
        report = copy.deepcopy(self.report)
        def work(cancel):
            with CaseStore(path) as store:
                identifier = store.add_snapshot(report, include_identifiers=include_identifiers)
            # A new worker-owned connection reloads the actual persisted IDs.
            return case_snapshot(path, identifier)
        self.start('Saved case / 已存案件快照', work, 'case')

    def open_case(self, path, snapshot_id):
        self.start('Opened case / 已打开案件', lambda cancel: case_snapshot(path, snapshot_id), 'case')

    def triage(self, finding_id, status, note=''):
        if self.case_path is None or self.snapshot_id is None:
            raise ValueError('Save or open a persisted snapshot before triage.')
        path, identifier = self.case_path, self.snapshot_id
        def work(cancel):
            with CaseStore(existing_case(path)) as store:
                store.triage(finding_id, status, note, snapshot_id=identifier)
            return case_snapshot(path, identifier)
        self.start('Triage / 本地处置', work, 'case')

    def verify_case(self, expected_head=None):
        if self.case_path is None:
            raise ValueError('Open a case first.')
        path = self.case_path
        def work(cancel):
            with CaseStore(existing_case(path)) as store:
                return store.verify(expected_head)
        self.start('Case integrity / 案件完整性', work, 'verification')

    def history_page(self, offset=0):
        if self.case_path is None:
            raise ValueError('Open a case first.')
        path = self.case_path
        def work(cancel):
            with CaseStore(existing_case(path)) as store:
                if not store.verify()['ok']:
                    raise ValueError('Case integrity failed.')
                return store.snapshots(limit=100, offset=offset)
        self.start('History page / 历史分页', work, 'history')

    def export(self, directory, include_identifiers=False):
        if self.report is None:
            raise ValueError('Load evidence before export.')
        return export_report(controlled_report(with_triage(self.report, self.overlay)), directory, include_identifiers)
