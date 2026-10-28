"""Shared finite measurement range, without converting Python integers to float."""
import math

MAX_MAGNITUDE = 2**64


def supported_number(value):
    """Return numeric type membership; reject unsupported measurement magnitudes."""
    if type(value) not in (int, float):
        return False
    if not -MAX_MAGNITUDE <= value <= MAX_MAGNITUDE or (type(value) is float and not math.isfinite(value)):
        raise ValueError('Evidence numbers must be finite and within +/-2**64.')
    return True
