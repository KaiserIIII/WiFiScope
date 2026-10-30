"""Bounded conversion of a finite, reviewed CPE URI binding profile.

Raw fields admit ASCII letters/digits, underscore, dot, hyphen and legacy
tilde. Literal punctuation otherwise requires one of the explicit NIST percent
mappings below; 01/02 denote question/star patterns, and decoding happens once.
Only edge question runs or a single edge star around a nonwildcard core are
supported. Language is limited to 2..3 letters with an optional 2-letter or
3-digit region. This is not full legacy URI, RFC5646 or NIST certification.

Input and formatted output are each at most 4096 characters; decoded fields
are at most 1024 tokens. Missing fields are ANY. No IO or matching model lives
here: the existing formatted parser supplies the rich CPE representation.
"""
from .cpe_names import CPEName, parse_cpe


_ERROR = 'Invalid bounded CPE URI name.'
_PUNCTUATION = {
    '21': '!', '22': '"', '23': '#', '24': '$', '25': '%', '26': '&',
    '27': "'", '28': '(', '29': ')', '2a': '*', '2b': '+', '2c': ',',
    '2f': '/', '3a': ':', '3b': ';', '3c': '<', '3d': '=', '3e': '>',
    '3f': '?', '40': '@', '5b': '[', '5c': '\\', '5d': ']', '5e': '^',
    '60': '`', '7b': '{', '7c': '|', '7d': '}', '7e': '~',
}


def _decode_field(raw):
    if not raw:
        return [('*', False)]
    if raw == '-':
        return [('-', False)]
    tokens = []
    offset = 0
    while offset < len(raw):
        char = raw[offset]
        quoted = False
        if char == '%':
            code = raw[offset + 1:offset + 3].lower()
            if code in ('01', '02'):
                char = '?' if code == '01' else '*'
            elif code in _PUNCTUATION:
                char = _PUNCTUATION[code]
                quoted = True
            else:
                raise ValueError(_ERROR)
            offset += 3
        elif char.isascii() and (char.isalnum() or char in '._-~'):
            quoted = char == '~'
            offset += 1
        else:
            raise ValueError(_ERROR)
        if len(tokens) >= 1024:
            raise ValueError(_ERROR)
        tokens.append((char, quoted))

    core = [i for i, (char, quoted) in enumerate(tokens)
            if quoted or char not in '*?']
    if not core:
        raise ValueError(_ERROR)
    first, last = core[0], core[-1]
    if any(not quoted and char in '*?' for char, quoted in tokens[first:last + 1]):
        raise ValueError(_ERROR)
    for edge in (tokens[:first], tokens[last + 1:]):
        if edge and edge != [('*', False)] and any(char != '?' for char, _ in edge):
            raise ValueError(_ERROR)
    return tokens


def _language_supported(raw):
    if raw in ('', '-'):
        return True
    parts = raw.split('-')
    if len(parts) > 2 or not 2 <= len(parts[0]) <= 3 or not parts[0].isalpha():
        return False
    if len(parts) == 1:
        return True
    region = parts[1]
    return (len(region) == 2 and region.isalpha()) or (len(region) == 3 and region.isdigit())


def uri_to_formatted(text: str) -> str:
    """Return all eleven formatted fields, preserving literal spelling/quotes.

    Unsupported, malformed or over-limit input raises ValueError with a fixed
    message. Prefix/part and percent hex are case insensitive; part is emitted
    lowercase. An encoded leading edition tilde is literal, never packing.
    """
    if (not isinstance(text, str) or not 1 <= len(text) <= 4096
            or text[:5].lower() != 'cpe:/'
            or any(not 0x20 <= ord(char) <= 0x7e for char in text)):
        raise ValueError(_ERROR)
    fields = text[5:].split(':')
    if len(fields) > 7 or fields[0].lower() not in ('', 'a', 'o', 'h'):
        raise ValueError(_ERROR)
    fields.extend([''] * (7 - len(fields)))
    fields[0] = fields[0].lower()
    if not _language_supported(fields[6]):
        raise ValueError(_ERROR)
    edition = fields[5]
    fields.extend([''] * 4)
    if edition.startswith('~'):
        packed = edition[1:].split('~')
        if len(packed) != 5:
            raise ValueError(_ERROR)
        fields[5], fields[7], fields[8], fields[9], fields[10] = packed

    output = ['cpe:2.3:']
    length = 8
    for index, raw in enumerate(fields):
        if index:
            if length >= 4096:
                raise ValueError(_ERROR)
            output.append(':')
            length += 1
        for char, quoted in _decode_field(raw):
            value = '\\' + char if quoted else char
            if length + len(value) > 4096:
                raise ValueError(_ERROR)
            output.append(value)
            length += len(value)
    return ''.join(output)


def parse_cpe_uri(text: str) -> CPEName:
    """Convert the reviewed URI profile to the existing rich CPEName type."""
    formatted = uri_to_formatted(text)
    try:
        return parse_cpe(formatted)
    except ValueError:
        raise ValueError(_ERROR) from None
