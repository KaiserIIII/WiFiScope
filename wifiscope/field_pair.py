"""One explicitly authorized TCP exchange between two controlled endpoints."""

import errno
import hmac
import ipaddress
import re
import secrets
import select
import socket
import time
from datetime import datetime, timezone

_CHALLENGE = b'WSP1?'
_REQUEST = b'WSP1>'
_RESPONSE = b'WSP1<'
_NONCE_BYTES = 16
_PROOF_BYTES = 32
_PENDING = {errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK, errno.EINTR,
            getattr(errno, 'WSAEWOULDBLOCK', 10035), getattr(errno, 'WSAEINPROGRESS', 10036),
            getattr(errno, 'WSAEALREADY', 10037)}
_REFUSED = {errno.ECONNREFUSED, getattr(errno, 'WSAECONNREFUSED', 10061)}
_TIMED_OUT = {errno.ETIMEDOUT, getattr(errno, 'WSAETIMEDOUT', 10060)}


class _Cancelled(Exception):
    pass


class _Mismatch(Exception):
    pass


def _endpoint(value, *, require_scope=True):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError('Use a concrete numeric unicast IP address.')
    host, separator, scope = value.partition('%')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError('Use a concrete numeric unicast IP address.') from None
    if address.is_unspecified or address.is_multicast:
        raise ValueError('Use a concrete numeric unicast IP address.')
    if address.version == 4:
        if separator or address.is_reserved or address.packed[0] == 0:
            raise ValueError('Use a concrete numeric unicast IP address.')
    elif address.ipv4_mapped is not None:
        raise ValueError('Use a native IPv4 or IPv6 address.')
    if separator:
        if (address.version != 6 or not address.is_link_local or
                re.fullmatch(r'[0-9]{1,10}', scope) is None or not 1 <= int(scope) <= 0xffffffff):
            raise ValueError('Use a numeric scope ID only with link-local IPv6.')
    elif address.version == 6 and address.is_link_local and require_scope:
        raise ValueError('Link-local IPv6 endpoints require a numeric scope ID.')
    return address, int(scope) if separator else 0


def _sockaddr(endpoint, port):
    address, scope = endpoint
    if address.version == 6:
        return str(address), port, 0, scope
    return str(address), port


def _socket_for(endpoint):
    family = socket.AF_INET if endpoint[0].version == 4 else socket.AF_INET6
    return socket.socket(family, socket.SOCK_STREAM)


def _operation(authorized, seconds, maximum, cancel):
    if authorized is not True:
        raise ValueError('Controlled peer pairing requires explicit authorization.')
    if type(seconds) not in (int, float) or not .1 <= seconds <= maximum:
        raise ValueError(f'Duration must be between 0.1 and {maximum} seconds.')
    if cancel is not None:
        cancel = getattr(cancel, 'is_set', cancel)
        if not callable(cancel):
            raise ValueError('Cancellation requires an event or a callable.')
    return cancel


def _check_cancel(cancel):
    if cancel is not None and cancel():
        raise _Cancelled


def _wait(sock, deadline, cancel, *, writable=False):
    reads, writes, errors = ([], [sock], [sock]) if writable else ([sock], [], [])
    while True:
        _check_cancel(cancel)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        timeout = min(remaining, .1) if cancel is not None else remaining
        ready_read, ready_write, ready_error = select.select(reads, writes, errors, timeout)
        if ready_read or ready_write or ready_error:
            return


def _send(sock, payload, deadline, cancel):
    remaining = memoryview(payload)
    while remaining:
        _wait(sock, deadline, cancel, writable=True)
        try:
            count = sock.send(remaining)
        except BlockingIOError:
            continue
        if count == 0:
            raise _Mismatch
        remaining = remaining[count:]


def _read(sock, size, deadline, cancel, *, final=False):
    data = bytearray()
    limit = size + int(final)
    while len(data) < limit:
        _wait(sock, deadline, cancel)
        try:
            piece = sock.recv(limit - len(data))
        except BlockingIOError:
            continue
        if not piece:
            break
        data.extend(piece)
    if len(data) != size:
        raise _Mismatch
    return bytes(data)


def _proof(key, label, challenge, nonce):
    return hmac.digest(key, label + challenge + nonce, 'sha256')


def _result(status, port):
    return {'status': status, 'port': port, 'timestamp': datetime.now(timezone.utc).isoformat()}


def _answer(conn, key, deadline, cancel):
    conn.setblocking(False)
    challenge = secrets.token_bytes(_NONCE_BYTES)
    _send(conn, _CHALLENGE + challenge, deadline, cancel)
    request = _read(conn, len(_REQUEST) + _NONCE_BYTES + _PROOF_BYTES, deadline, cancel, final=True)
    nonce = request[len(_REQUEST):-_PROOF_BYTES]
    expected = _REQUEST + nonce + _proof(key, _REQUEST, challenge, nonce)
    if not hmac.compare_digest(request, expected):
        raise _Mismatch
    response = _RESPONSE + _proof(key, _RESPONSE, challenge, nonce)
    _send(conn, response, deadline, cancel)
    conn.shutdown(socket.SHUT_WR)


def serve_peer(bind, expected_peer, *, authorized=False, seconds=60, ready=None, cancel=None):
    """Wait for one authenticated exchange from the explicit peer IP."""
    cancel = _operation(authorized, seconds, 300, cancel)
    local = _endpoint(bind)
    peer, peer_scope = _endpoint(expected_peer, require_scope=False)
    if local[0].version != peer.version:
        raise ValueError('The bind and expected peer IP versions must match.')
    if ready is not None and not callable(ready):
        raise ValueError('The readiness callback must be callable.')

    port = 0
    try:
        _check_cancel(cancel)
        with _socket_for(local) as listener:
            listener.bind(_sockaddr(local, 0))
            listener.listen(4)
            listener.setblocking(False)
            port = listener.getsockname()[1]
            key = secrets.token_bytes(16)
            deadline = time.monotonic() + seconds
            _check_cancel(cancel)
            if ready is not None:
                address = str(local[0]) if local[1] == 0 else f'{local[0]}%{local[1]}'
                ready({'address': address, 'port': port, 'code': key.hex()})

            while True:
                _wait(listener, deadline, cancel)
                try:
                    conn, remote = listener.accept()
                except BlockingIOError:
                    continue
                with conn:
                    if ipaddress.ip_address(remote[0]) != peer or (peer_scope and remote[3] != peer_scope):
                        continue
                    try:
                        _answer(conn, key, min(deadline, time.monotonic() + 2), cancel)
                    except (OSError, _Mismatch):
                        continue
                    return _result('handshake_verified', port)
    except _Cancelled:
        return _result('cancelled', port)
    except TimeoutError:
        return _result('listener_timeout', port)
    except OSError:
        return _result('listener_error', port)


def _connect(sock, address, deadline, cancel):
    sock.setblocking(False)
    _check_cancel(cancel)
    error = sock.connect_ex(address)
    if error in _PENDING:
        _wait(sock, deadline, cancel, writable=True)
        error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    if error:
        raise OSError(error, 'Peer connection failed.')


def check_peer(target, port, code, *, source=None, authorized=False, timeout=2.0, cancel=None):
    """Verify one application exchange from this device to the controlled peer."""
    cancel = _operation(authorized, timeout, 10, cancel)
    remote = _endpoint(target)
    local = _endpoint(source) if source is not None else None
    if local is not None and local[0].version != remote[0].version:
        raise ValueError('The source and target IP versions must match.')
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Use a TCP port between 1 and 65535.')
    if not isinstance(code, str) or re.fullmatch(r'[0-9a-fA-F]{32}', code) is None:
        raise ValueError('Use the 32-character hexadecimal setup code.')

    key = bytes.fromhex(code)
    deadline = time.monotonic() + timeout
    try:
        _check_cancel(cancel)
        with _socket_for(remote) as conn:
            if local is not None:
                conn.bind(_sockaddr(local, 0))
            _connect(conn, _sockaddr(remote, port), deadline, cancel)
            try:
                challenge_frame = _read(conn, len(_CHALLENGE) + _NONCE_BYTES, deadline, cancel)
                if not challenge_frame.startswith(_CHALLENGE):
                    raise _Mismatch
                challenge = challenge_frame[len(_CHALLENGE):]
                nonce = secrets.token_bytes(_NONCE_BYTES)
                request = _REQUEST + nonce + _proof(key, _REQUEST, challenge, nonce)
                _send(conn, request, deadline, cancel)
                conn.shutdown(socket.SHUT_WR)
                response = _read(conn, len(_RESPONSE) + _PROOF_BYTES, deadline, cancel, final=True)
                expected = _RESPONSE + _proof(key, _RESPONSE, challenge, nonce)
                if not hmac.compare_digest(response, expected):
                    raise _Mismatch
            except TimeoutError:
                return _result('handshake_timeout', port)
            except (OSError, _Mismatch):
                return _result('handshake_mismatch', port)
            return _result('handshake_verified', port)
    except _Cancelled:
        return _result('cancelled', port)
    except TimeoutError:
        return _result('connect_timeout', port)
    except OSError as exc:
        if exc.errno in _REFUSED:
            return _result('connection_refused', port)
        if exc.errno in _TIMED_OUT:
            return _result('connect_timeout', port)
        return _result('connect_error', port)
