"""Bounded CPE 2.3 formatted names and conservative directional matching."""
from dataclasses import dataclass, field as dataclass_field
import unicodedata

FIELDS = ('part', 'vendor', 'product', 'version', 'update', 'edition', 'language',
          'sw_edition', 'target_sw', 'target_hw', 'other')


@dataclass(frozen=True)
class Attribute:
    kind: str  # any, na, literal, pattern, unsupported
    text: str
    tokens: tuple
    original_text: str | None = dataclass_field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class CPEName:
    attributes: tuple

    def field(self, name):
        return self.attributes[FIELDS.index(name)]


def parse_cpe(text):
    """Parse eleven fields without losing which characters were quoted."""
    if (not isinstance(text, str) or not 1 <= len(text) <= 4096
            or not text.startswith('cpe:2.3:') or any(unicodedata.category(c) == 'Cc' for c in text)):
        raise ValueError('Invalid bounded CPE 2.3 formatted name.')
    fields, tokens, quoted = [], [], False
    for char in text[8:]:
        if quoted:
            tokens.append((char, True))
            quoted = False
        elif char == '\\':
            quoted = True
        elif char == ':':
            fields.append(tokens)
            tokens = []
        else:
            tokens.append((char, False))
    fields.append(tokens)
    if quoted or len(fields) != 11 or any(not f or len(f) > 1024 for f in fields):
        raise ValueError('Invalid bounded CPE 2.3 formatted name.')
    attributes = []
    for field in fields:
        original = ''.join(c for c, _ in field)
        literal = original.casefold()
        if field == [('*', False)]:
            kind = 'any'
        elif field == [('-', False)]:
            kind = 'na'
        else:
            wildcard = [i for i, (c, q) in enumerate(field) if c in '*?' and not q]
            kind = 'literal'
            if wildcard:
                # NIST source patterns allow wildcard runs only at the edges.
                first = next((i for i, (c, q) in enumerate(field) if c not in '*?' or q), len(field))
                last = next((i for i in range(len(field) - 1, -1, -1)
                             if field[i][0] not in '*?' or field[i][1]), -1)
                kind = 'unsupported' if any(first < i < last for i in wildcard) or any(len(c.casefold()) != 1 for c, _ in field) else 'pattern'
        attributes.append(Attribute(kind, literal, tuple((c.casefold(), q) for c, q in field), original))
    if attributes[0].kind not in ('any', 'na') and (
            attributes[0].kind != 'literal' or attributes[0].text not in ('a', 'o', 'h')):
        raise ValueError('Invalid bounded CPE part.')
    return CPEName(tuple(attributes))


def _pattern_match(tokens, target, charge):
    # Bounded dynamic programming, not regular expression backtracking. '?' is
    # zero OR one character in the CPE source relation.
    previous = [True] + [False] * len(target)
    for char, quoted in tokens:
        charge()
        current = [False] * (len(target) + 1)
        if char == '*' and not quoted:
            current[0] = previous[0]
            for i in range(1, len(current)):
                charge()
                current[i] = previous[i] or current[i - 1]
        elif char == '?' and not quoted:
            current[0] = previous[0]
            for i in range(1, len(current)):
                charge()
                current[i] = previous[i] or previous[i - 1]
        else:
            for i in range(1, len(current)):
                charge()
                current[i] = previous[i - 1] and target[i - 1] == char
        previous = current
    return previous[-1]


def compare_attribute(source, target, charge):
    charge()
    if target.kind in ('pattern', 'unsupported') or source.kind == 'unsupported':
        return 'unknown'
    if source.kind == 'any':
        return 'true'
    if target.kind == 'any':
        return 'unknown'
    if source.kind == 'na' or target.kind == 'na':
        return 'true' if source.kind == target.kind else 'false'
    if source.kind == 'pattern':
        return 'true' if _pattern_match(source.tokens, target.text, charge) else 'false'
    return 'true' if source.text == target.text else 'false'


def _validate_name(name):
    """Validate every rich attribute before any directional comparison."""
    if not isinstance(name, CPEName):
        raise ValueError('CPE comparison requires typed formatted names.')
    if (not isinstance(name.attributes, tuple) or len(name.attributes) != 11
            or any(not isinstance(a, Attribute) or not isinstance(a.text, str)
                   or not isinstance(a.tokens, tuple) or len(a.text) > 2048 or len(a.tokens) > 1024
                   or (a.original_text is not None and (not isinstance(a.original_text, str) or len(a.original_text) > 1024))
                   or a.kind not in ('any', 'na', 'literal', 'pattern', 'unsupported')
                   or any(not isinstance(t, tuple) or len(t) != 2 or not isinstance(t[0], str)
                          or not 1 <= len(t[0]) <= 3 or type(t[1]) is not bool for t in a.tokens)
                   for a in name.attributes)):
        raise ValueError('Invalid typed CPE attributes.')


def _compare_valid_names(source, target, charge):
    """Compare parsed/validated internal names, charging only performed work."""
    result = 'true'
    for a, b in zip(source.attributes, target.attributes):
        value = compare_attribute(a, b, charge)
        if value == 'false':
            return 'false'
        if value == 'unknown':
            result = 'unknown'
    return result


def compare_cpe(criteria, observed, *, budget=None):
    source = parse_cpe(criteria) if isinstance(criteria, str) else criteria
    target = parse_cpe(observed) if isinstance(observed, str) else observed
    if not isinstance(source, CPEName) or not isinstance(target, CPEName):
        raise ValueError('CPE comparison requires typed formatted names.')
    _validate_name(source)
    _validate_name(target)
    work = 0
    def charge():
        nonlocal work
        work += 1
        if budget is not None:
            budget()
        elif work > 131072:
            raise OverflowError
    try:
        return _compare_valid_names(source, target, charge)
    except OverflowError:
        if budget is not None:
            raise
        return 'unknown'
