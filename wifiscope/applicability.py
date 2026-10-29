"""Pure bounded three-valued CPE/CNA applicability; no installed-state inference."""
import re
from functools import cmp_to_key
from .cpe_names import compare_cpe, parse_cpe
from .inventory import bounded_json, validate_inventory

# Provider spelling compatibility only; source declarations remain unchanged.
CNA_SCHEMES = {'numeric': 'numeric', 'semver': 'semver2', 'semver2': 'semver2',
               'openssh-portable': 'openssh-portable'}


def truth_and(values):
    values = list(values)
    return 'false' if 'false' in values else 'unknown' if 'unknown' in values else 'true'


def truth_or(values):
    values = list(values)
    return 'true' if 'true' in values else 'unknown' if 'unknown' in values else 'false'


def truth_not(value):
    return {'true': 'false', 'false': 'true', 'unknown': 'unknown'}[value]


def _version(value, scheme):
    if not isinstance(value, str) or not 1 <= len(value) <= 1024:
        return None
    if scheme == 'numeric' and re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', value):
        return tuple(int(x) for x in value.split('.'))
    if scheme == 'openssh-portable':
        m = re.fullmatch(r'([0-9]+)\.([0-9]+)p([0-9]+)', value)
        return tuple(map(int, m.groups())) if m else None
    if scheme == 'semver2':
        m = re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?', value)
        if not m:
            return None
        pre = m[4].split('.') if m[4] else None
        if pre and any(x.isdigit() and len(x) > 1 and x[0] == '0' for x in pre):
            return None
        return tuple(map(int, m.group(1, 2, 3))), pre
    return None


def compare_versions(a, b, scheme):
    x, y = _version(a, scheme), _version(b, scheme)
    if x is None or y is None:
        return None
    if scheme == 'numeric':
        size = max(len(x), len(y))
        x, y = x + (0,) * (size-len(x)), y + (0,) * (size-len(y))
    if scheme == 'semver2':
        if x[0] != y[0]:
            return (x[0] > y[0]) - (x[0] < y[0])
        p, q = x[1], y[1]
        if p is None or q is None:
            return (p is None) - (q is None)
        for u, v in zip(p, q):
            if u == v:
                continue
            if u.isdigit() and v.isdigit():
                return (int(u) > int(v)) - (int(u) < int(v))
            if u.isdigit() != v.isdigit():
                return -1 if u.isdigit() else 1
            return (u > v) - (u < v)
        return (len(p) > len(q)) - (len(p) < len(q))
    return (x > y) - (x < y)


class WorkLimit(ValueError):
    pass


class MatchBudget:
    def __init__(self, limit=500000, cancel=None):
        if type(limit) is not int or not 1 <= limit <= 500000:
            raise ValueError('Invalid catalog predicate budget.')
        self.limit, self.used, self.cancel = limit, 0, cancel

    def charge(self):
        if self.used >= self.limit:
            raise WorkLimit('Catalog predicate budget reached.')
        self.used += 1
        try:
            stopped = self.cancel is not None and (self.cancel() if callable(self.cancel) else self.cancel.is_set())
        except Exception:
            raise ValueError('Catalog audit cancellation callback failed.') from None
        if stopped:
            raise InterruptedError('Catalog audit cancelled.')


def _range_leaf(match, component, budget):
    budget.charge()
    value = compare_cpe(match['criteria'], component['cpe'], budget=budget.charge)
    if value == 'false':
        return value
    observed = parse_cpe(component['cpe']).field('version')
    for key, sign in [('versionStartIncluding', 'ge'), ('versionStartExcluding', 'gt'),
                      ('versionEndIncluding', 'le'), ('versionEndExcluding', 'lt')]:
        if key not in match:
            continue
        budget.charge()
        order = compare_versions(observed.original_text, match[key], component.get('version_scheme', 'unknown')) if observed.kind == 'literal' else None
        value = truth_and([value, 'unknown' if order is None else 'true' if
            {'ge': order >= 0, 'gt': order > 0, 'le': order <= 0, 'lt': order < 0}[sign] else 'false'])
    return value


def _leaf(match, asset, polarity, budget):
    budget.charge()
    if match.get('unsupported') or 'criteria' not in match:
        return 'unknown', set(), 'unknown'
    try:
        source = parse_cpe(match['criteria'])
    except ValueError:
        # Retained lexical/legacy criteria need not fit the strict matcher.
        # Only parsing is contained; budget/cancel/callback errors propagate.
        return 'unknown', set(), 'unknown'
    values, ids = [], set()
    for component in asset['components']:
        budget.charge()
        if 'cpe' not in component:
            continue
        value = _range_leaf(match, component, budget)
        values.append(value)
        if value != 'false':
            ids.add(component['id'])
    value = truth_or(values)
    if value == 'false' and source.field('part').text not in asset.get('complete_parts', []):
        # A literal same-identity observed version disproves this leaf; unrelated
        # components do not establish absence in an open-world inventory.
        identity = [c for c in asset['components'] if 'cpe' in c and all(
            parse_cpe(c['cpe']).field(k).text == source.field(k).text for k in ('part', 'vendor', 'product'))]
        if not identity:
            value = 'unknown'
    if not polarity:
        value = truth_not(value)
    witness = value if match.get('vulnerable') is True and polarity else 'false'
    return value, ids, witness


def _node(node, asset, polarity, budget):
    budget.charge()
    negated = node.get('negate', False)
    effective = polarity != negated
    children = [_leaf(m, asset, effective, budget) for m in node.get('cpeMatch', [])]
    children += [_node(n, asset, effective, budget) for n in node.get('nodes', [])]
    op = node.get('operator', 'OR')
    # Evaluate in negation normal form. Witnesses have their own three-valued
    # satisfying-path state; a merely possible OR witness cannot authorize a
    # known-true environmental alternative.
    op = op if effective else ('OR' if op == 'AND' else 'AND')
    value = (truth_and if op == 'AND' else truth_or)(r[0] for r in children) if children else 'unknown'
    if node.get('unsupported'):
        value = 'unknown'
    witness = truth_or(r[2] for r in children)
    if op == 'AND':
        witness = truth_and([value, witness])
    if node.get('unsupported'):
        witness = truth_and(['unknown', witness])
    viable = [r for r in children if r[0] != 'false']
    return value, set().union(*(r[1] for r in viable)), witness


def _cna_version(declaration, version, scheme, budget):
    budget.charge()
    def order(a, b):
        budget.charge()
        return compare_versions(a, b, scheme)
    if (declaration.get('unsupported') or version is None
            or 'lessThan' in declaration and 'lessThanOrEqual' in declaration):
        return 'unknown'
    lower = declaration.get('version')
    upper = declaration.get('lessThan', declaration.get('lessThanOrEqual'))
    if upper is None:
        return declaration.get('status', 'unknown') if lower == '*' or version == lower else None
    declared = declaration.get('versionType', 'unknown')
    if CNA_SCHEMES.get(declared) != scheme or scheme == 'unknown':
        return 'unknown'
    if _version(version, scheme) is None:
        return 'unknown'
    low = 1 if lower == '0' else order(version, lower)
    if upper == '*':
        high = -1
    elif upper.endswith('.*'):
        prefix = upper[:-2]
        if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', prefix):
            return 'unknown'
        pieces = prefix.split('.')
        parsed = _version(version, scheme)
        core = parsed[0] if scheme == 'semver2' else parsed
        if scheme != 'numeric' and (len(pieces) > (3 if scheme == 'semver2' else 2)
                or any(len(p) > 1 and p[0] == '0' for p in pieces)):
            return 'unknown'
        bound = tuple(map(int, pieces))
        observed_prefix = (core + (0,) * len(pieces))[:len(pieces)]
        budget.charge()
        # Prefix infinity is greater than every version with that prefix,
        # including a prerelease at the next major prefix's first version.
        high = -1 if observed_prefix <= bound else 1
    else:
        high = order(version, upper)
    if low is None or high is None:
        return 'unknown'
    if low < 0 or high > 0 or high == 0 and ('lessThanOrEqual' not in declaration or upper.endswith('.*')):
        return None
    status = declaration.get('status', 'unknown')
    changes = declaration.get('changes', [])
    for c in changes:
        budget.charge()
        if order(c.get('at'), version) is None:
            return 'unknown'
    def order_changes(a, b):
        return order(a['at'], b['at'])
    ordered = sorted(changes, key=cmp_to_key(order_changes))
    for first, second in zip(ordered, ordered[1:]):
        budget.charge()
        if order(first['at'], second['at']) == 0 and first['status'] != second['status']:
            return 'unknown'
    for change in ordered:
        budget.charge()
        if order(version, change['at']) >= 0:
            status = change['status']
    return status


def _cna(row, component, budget):
    budget.charge()
    if 'cpe' in component:
        if not row.get('cpes'):
            return None
        if row.get('unsupported') or row.get('context'):
            return 'unknown'
        identities = []
        for cpe in row['cpes']:
            budget.charge()
            try:
                criteria = parse_cpe(cpe)
            except ValueError:
                # Task1 retains unsupported identifier evidence, including CPE
                # 2.2. Contain only strict parsing here; never catch matching
                # WorkLimit/cancellation/callback failures or guess conversion.
                identities.append('unknown')
                continue
            identities.append(compare_cpe(criteria, component['cpe'], budget=budget.charge))
        identity = truth_or(identities)
        if identity == 'false':
            return None
        version = parse_cpe(component['cpe']).field('version')
        version = version.original_text if version.kind == 'literal' else None
    else:
        if (row.get('vendor'), row.get('product')) != (component['vendor'], component['product']):
            return None
        identity, version = 'true', component['version']
    if row.get('unsupported') or row.get('context') or identity == 'unknown':
        return 'unknown'
    statuses = [_cna_version(v, version, component['version_scheme'], budget) for v in row.get('versions', [])]
    statuses = {s for s in statuses if s is not None}
    if 'unknown' in statuses or len(statuses) > 1:
        return 'unknown'
    status = next(iter(statuses)) if statuses else row.get('defaultStatus', 'unknown')
    return {'affected': 'true', 'unaffected': 'false'}.get(status, 'unknown')


def evaluate_cve(record, asset, *, budget=None):
    """Return applicability, sorted component_ids, model and controlled reasons.

    Inputs are normalized Task1 record and validated single inventory asset.
    budget is an optional shared MatchBudget (raises on exhaustion/cancellation).
    """
    bounded_json(record, allow_numbers=True)
    if not isinstance(record, dict) or not isinstance(asset, dict):
        raise ValueError('Applicability requires a typed record and inventory asset.')
    asset = validate_inventory(dict(schema_version=1, assets=[asset]))['assets'][0]
    budget = budget if budget is not None else MatchBudget()
    models, ids, reasons = {}, set(), set()
    if record.get('configurations'):
        rows = [_node(n, asset, True, budget) for n in record['configurations']]
        value = truth_or(v for v, _, _ in rows)
        witnesses = [r for r in rows if r[0] != 'false' and r[2] != 'false']
        if value == 'true' and truth_or(r[2] for r in rows) != 'true':
            value = 'unknown'
            reasons.add('positive-witness-missing')
        models['cpe'] = value
        ids.update(i for _, members, _ in witnesses for i in members)
    cna_rows = {}
    for container in record.get('affected', []):
        for row in container.get('affectedData', []):
            for component in asset['components']:
                value = _cna(row, component, budget)
                if value is not None:
                    cna_rows.setdefault(component['id'], []).append(value)
                    ids.add(component['id'])
    if cna_rows:
        per_component = ['unknown' if 'true' in values and 'false' in values else truth_or(values)
                         for values in cna_rows.values()]
        models['cna'] = truth_or(per_component)
    if 'true' in models.values() and 'false' in models.values():
        value = 'unknown'
        reasons.add('model-conflict')
    else:
        value = truth_or(models.values()) if models else 'unknown'
    if value == 'unknown':
        reasons.add('applicability-unknown')
    return dict(applicability=value, component_ids=sorted(ids), model='mixed' if len(models) > 1 else next(iter(models), 'unknown'), reasons=sorted(reasons))
