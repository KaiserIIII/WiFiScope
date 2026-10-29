"""Conservative typed comparisons; missing observations never imply resolution."""
import copy

from .investigate import build_investigation


def _synthetic(report):
    return report.get('synthetic') is True or 'synthetic-demo' in report.get('gaps', [])


def comparison_notice(report):
    """Accurate visible provenance, including older comparison side gap flags."""
    comparison = report.get('comparison')
    if not isinstance(comparison, dict):
        return ''
    before, after = _synthetic(comparison['before']), _synthetic(comparison['after'])
    if before and after:
        return 'SYNTHETIC COMPARISON · 合成证据比较 · Both snapshots contain invented synthetic evidence.'
    if before or after:
        return ('MIXED SYNTHETIC COMPARISON · 含合成证据的混合比较 · Before: '
                + ('synthetic' if before else 'not marked synthetic') + ' · After: '
                + ('synthetic' if after else 'not marked synthetic')
                + '. Do not interpret invented evidence as a measured retest.')
    return ''


def compare_snapshots(before, after, *, before_id=None, after_id=None):
    if 'catalog_audit' in before or 'catalog_audit' in after:
        raise ValueError('Compare catalog audit contexts separately; inventory applicability cannot be reduced to address changes.')
    identity = before.get('identifiers_included') is True and after.get('identifiers_included') is True

    def side(report):
        built = report if 'investigation' in report else build_investigation(report)
        investigation = built['investigation']
        return dict(collected_at=built.get('collected_at'), synthetic=_synthetic(built), sources=copy.deepcopy(built.get('sources', [])),
                    assets=copy.deepcopy(investigation.get('assets', [])) if identity else [],
                    summary=dict(assets=len(investigation.get('assets', [])), findings=len(investigation.get('findings', []))),
                    coverage=copy.deepcopy(investigation.get('coverage', [])), gaps=copy.deepcopy(built.get('gaps', [])),
                    run=copy.deepcopy(built.get('run', {})))
    left, right = side(before), side(after)
    for snapshot_id, snapshot in ((before_id, left), (after_id, right)):
        if snapshot_id is not None:
            if type(snapshot_id) is not int or snapshot_id < 1:
                raise ValueError('Comparison requires positive persisted snapshot IDs.')
            snapshot['snapshot_id'] = snapshot_id
    changes = []
    wifi_changes = []
    if identity:
        left_addresses = {a.get('address') for a in left['assets'] if a.get('address')}
        right_addresses = {a.get('address') for a in right['assets'] if a.get('address')}
        changes = [dict(address=a, status='not-observed' if a not in right_addresses else 'observed')
                   for a in sorted(left_addresses ^ right_addresses)]
        l_wifi = {w.get('bssid'): w for w in before.get('wifi', []) if w.get('bssid')}
        r_wifi = {w.get('bssid'): w for w in after.get('wifi', []) if w.get('bssid')}
        wifi_changes = [dict(bssid=b, before=l_wifi.get(b), after=r_wifi.get(b),
                            status='not-observed' if b not in r_wifi else 'observed')
                        for b in sorted(l_wifi.keys() | r_wifi.keys()) if l_wifi.get(b) != r_wifi.get(b)]
    return dict(comparison=dict(mode='identity' if identity else 'counts-only', partial=True,
                before=left, after=right, asset_changes=changes, wifi_changes=wifi_changes), gaps=['comparison-scope-limited'],
                synthetic=left['synthetic'] and right['synthetic'], schema_version=1)
