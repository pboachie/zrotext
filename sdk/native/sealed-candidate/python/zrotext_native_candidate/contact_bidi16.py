# SPDX-License-Identifier: AGPL-3.0-only
"""Supplement the maintained URL parser with Unicode 16 RFC 5893 checks."""
from bisect import bisect_right
from .contact_bidi16_data import RANGES

_STARTS=tuple(row[0] for row in RANGES)
_LTR,_RTL,_EN,_AN,_ALLOW_RTL,_ALLOW_LTR,_NSM=1,2,4,8,16,32,64


def _flags(character):
    code=ord(character)
    return RANGES[bisect_right(_STARTS,code)-1][2]


def valid_bidi16_host(host):
    labels=host.split('.')
    if not any(label.startswith('xn--') for label in labels):return True
    labels=[label[4:].encode('ascii').decode('punycode') if label.startswith('xn--') else label for label in labels]
    values=[[_flags(character) for character in label] for label in labels]
    if not any(flags&(_RTL|_AN) for label in values for flags in label):return True
    for label in values:
        if not label:continue
        rtl=bool(label[0]&_RTL)
        if not rtl and not label[0]&_LTR:return False
        allowed=_ALLOW_RTL if rtl else _ALLOW_LTR
        if any(not flags&allowed for flags in label):return False
        final=next((flags for flags in reversed(label) if not flags&_NSM),0)
        if not final&((_RTL|_EN|_AN) if rtl else (_LTR|_EN)):return False
        if rtl and any(flags&_EN for flags in label) and any(flags&_AN for flags in label):return False
    return True
