"""Bounded binary record readers. Packet contents never leave the analysis call."""
from datetime import datetime, timedelta, timezone
import struct

MAX_BYTES = 16 * 1024 * 1024
MAX_PACKETS = 100000


def timestamp(seconds):
    try:
        return (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)).isoformat()
    except (OverflowError, ValueError):
        return None


def _options(body, start, endian):
    options = {}
    while start < len(body):
        if len(body) - start < 4:
            raise ValueError('Invalid PCAPNG option header.')
        code, length = struct.unpack_from(endian + 'HH', body, start)
        start += 4
        padded = (length + 3) & ~3
        if start + padded > len(body) or code == 0 and length:
            raise ValueError('Invalid PCAPNG option length.')
        if code == 0:
            if any(body[start:]):
                raise ValueError('Data after PCAPNG option terminator.')
            break
        if code in options:
            # Repeated uninterpreted comments are allowed, timing options are not.
            if code in (9, 14):
                raise ValueError('Duplicate PCAPNG timestamp option.')
        options[code] = body[start:start + length]
        start += padded
    return options


def records(data, gaps):
    """Yield linktype, bounded frame, original time, wire length."""
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise ValueError('Capture must be bytes of at most 16 MiB.')
    magic = data[:4]
    formats = {b'\xd4\xc3\xb2\xa1': ('<', 1000000), b'\xa1\xb2\xc3\xd4': ('>', 1000000),
               b'\x4d\x3c\xb2\xa1': ('<', 1000000000), b'\xa1\xb2\x3c\x4d': ('>', 1000000000)}
    if magic in formats:
        endian, unit = formats[magic]
        if len(data) < 24:
            raise ValueError('Truncated PCAP global header.')
        major, minor, _, _, snaplen, link = struct.unpack_from(endian + 'HHIIII', data, 4)
        if (major, minor) != (2, 4) or not 0 < snaplen <= MAX_BYTES:
            raise ValueError('Unsupported PCAP version or snaplen.')
        offset, count = 24, 0
        while offset < len(data):
            if len(data) - offset < 16:
                gaps.add('packet-truncated')
                break
            sec, fraction, captured, original = struct.unpack_from(endian + 'IIII', data, offset)
            if captured > snaplen or captured > original or fraction >= unit:
                raise ValueError('Inconsistent PCAP packet length or timestamp.')
            offset += 16
            count += 1
            if count > MAX_PACKETS:
                raise ValueError('Capture exceeds 100000 packets.')
            frame = data[offset:offset + captured]
            if len(frame) < captured or captured < original:
                gaps.add('packet-truncated')
            # Upper bits carry link-layer metadata such as FCS presence/length.
            yield link & 0xffff, frame, timestamp(sec + fraction / unit), original
            offset += captured
        return
    if magic != b'\x0a\x0d\x0d\x0a':
        raise ValueError('Expected a classic PCAP or PCAPNG capture.')
    offset, count, endian, section_end = 0, 0, None, None
    interfaces = []
    while offset < len(data):
        if len(data) - offset < 12:
            gaps.add('packet-truncated')
            break
        section = data[offset:offset + 4] == b'\x0a\x0d\x0d\x0a'
        if section:
            bom = data[offset + 8:offset + 12]
            current = {b'\x4d\x3c\x2b\x1a': '<', b'\x1a\x2b\x3c\x4d': '>'}.get(bom)
            if current is None:
                raise ValueError('Invalid PCAPNG section byte order.')
            if section_end is not None and section_end != offset:
                raise ValueError('Inconsistent PCAPNG section length.')
            endian = current
        if endian is None:
            raise ValueError('PCAPNG requires a section header.')
        kind, length = struct.unpack_from(endian + 'II', data, offset)
        if length < 12 or length % 4 or length > MAX_BYTES:
            raise ValueError('Invalid PCAPNG block length/alignment.')
        if offset + length > len(data):
            gaps.add('packet-truncated')
            break
        if section_end is not None and not section and offset + length > section_end:
            raise ValueError('PCAPNG block crosses section boundary.')
        if struct.unpack_from(endian + 'I', data, offset + length - 4)[0] != length:
            raise ValueError('PCAPNG block trailer does not match.')
        body = memoryview(data)[offset + 8:offset + length - 4]
        if section:
            if len(body) < 16:
                raise ValueError('Truncated PCAPNG section header.')
            major, minor, declared = struct.unpack_from(endian + 'HHq', body, 4)
            if (major, minor) != (1, 0) or declared < -1:
                raise ValueError('Unsupported PCAPNG section version/length.')
            _options(body, 16, endian)
            section_end = offset + length + declared if declared >= 0 else None
            interfaces = []
        elif kind == 1:
            if len(body) < 8:
                raise ValueError('Truncated PCAPNG interface.')
            link, reserved, snaplen = struct.unpack_from(endian + 'HHI', body)
            if reserved or snaplen > MAX_BYTES:
                raise ValueError('Invalid PCAPNG interface snaplen/reserved field.')
            opts = _options(body, 8, endian)
            resolution = 1000000
            if 9 in opts:
                if len(opts[9]) != 1:
                    raise ValueError('Invalid PCAPNG timestamp resolution.')
                exponent = opts[9][0]
                resolution = (2 ** (exponent & 127)) if exponent & 128 else (10 ** exponent)
            shift = 0
            if 14 in opts:
                if len(opts[14]) != 8:
                    raise ValueError('Invalid PCAPNG timestamp offset.')
                shift = struct.unpack(endian + 'q', opts[14])[0]
            interfaces.append((link, snaplen or MAX_BYTES, resolution, shift))
        elif kind in (3, 6):
            if kind == 6:
                if len(body) < 20:
                    raise ValueError('Truncated PCAPNG enhanced packet header.')
                interface, high, low, captured, original = struct.unpack_from(endian + 'IIIII', body)
                start = 20
            else:
                if len(body) < 4 or not interfaces:
                    raise ValueError('PCAPNG simple packet requires interface zero.')
                interface, start = 0, 4
                original = struct.unpack_from(endian + 'I', body)[0]
                captured = min(original, interfaces[0][1])
            if interface >= len(interfaces):
                raise ValueError('Unknown PCAPNG packet interface.')
            link, snaplen, resolution, shift = interfaces[interface]
            end = start + ((captured + 3) & ~3)
            if captured > original or captured > snaplen or end > len(body):
                raise ValueError('Inconsistent PCAPNG packet/snaplen length.')
            if kind == 3 and end != len(body):
                raise ValueError('Invalid PCAPNG simple packet padding/length.')
            if kind == 6:
                _options(body, end, endian)
            if captured < original:
                gaps.add('packet-truncated')
            count += 1
            if count > MAX_PACKETS:
                raise ValueError('Capture exceeds 100000 packets.')
            yield link, body[start:start + captured], timestamp(((high << 32) | low) / resolution + shift) if kind == 6 else None, original
        else:
            gaps.add('packet-block-unsupported')
        offset += length
    if section_end is not None and section_end != len(data):
        gaps.add('packet-truncated')
