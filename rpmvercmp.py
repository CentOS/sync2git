#! /usr/bin/python

""" Rpm compatible version comparison in python.
    Ported from: https://github.com/james-antill/repos/blob/main/rpmvercmp.go
"""


# Maybe doesn't need to be at the top level but eh.
from __future__ import print_function

import string

#  The basic way rpm works is to take a string and split it into segments
# of alpha/numeric/tilde/other chars. All the "other" parts are considered
# equal. A tilde is newer. , the others are compared
# as normal strings ... but numbers are kinda special because leading zeros
# are ignored.

conf_tilde = True
conf_caret = True

_vT_NUM = 1
_vT_ALP = 2
_vT_TIL = 3
_vT_CAR = 4
_vT_MSC = 99
_vT_END = 999

def _getTByte(d):
    if False: pass
    elif d >= '0' and d <= '9':
        return _vT_NUM
    elif d >= 'a' and d <= 'z':
        return _vT_ALP
    elif d >= 'A' and d <= 'Z':
        return _vT_ALP
    elif d == '~':
        if conf_tilde:
            return _vT_TIL
    elif d == '^':
        if conf_caret:
            return _vT_CAR
    return _vT_MSC

def _nextSlice(d):
    if len(d) <= 0:
        return d, _vT_END, d

    t = _getTByte(d[0])

    for num in range(1, len(d)):
        if _getTByte(d[num]) != t:
            return d[:num], t, d[num:]

    return d, t, ""

# T_MSC slices aren't useful, they just split things that don't split on their own.
# own. See rpmvercmp testcases like TestRpmvercmpOdd
# tl;dr 1.x == 1x
def _nextUsefulSlice(d):
    cs1, t1, s1 = _nextSlice(d)
    if t1 == _vT_MSC:
        cs1, t1, s1 = _nextSlice(s1)

    return cs1, t1, s1

def rpmvercmp(s1, s2):
    while len(s1) > 0 or len(s2) > 0:
        cs1, t1, shadows1 = _nextUsefulSlice(s1)
        s1 = shadows1
        cs2, t2, shadows2 = _nextUsefulSlice(s2)
        s2 = shadows2

        # Tilde sections mean it's older...
        if t1 == _vT_TIL or t2 == _vT_TIL:
            if t1 == _vT_TIL and t2 == _vT_TIL:
                if len(cs1) == len(cs2):
                    continue

                if len(cs1) < len(cs2):
                    cs1, t1, s1 = _nextUsefulSlice(s1)
                else:
                    cs2, t2, s2 = _nextUsefulSlice(s2)

            if t1 == _vT_TIL:
                return -1
            if t2 == _vT_TIL:
                return 1

        # Caret is almost the same as tilde,
        # differs when it's the end of the string...
        if t1 == _vT_CAR and t2 == _vT_CAR:
            if t1 == _vT_CAR and t2 == _vT_CAR:
                if len(cs1) == len(cs2):
                    continue
                if len(cs1) < len(cs2):
                    cs1, t1, s1 = _nextUsefulSlice(s1)
                else:
                    cs2, t2, s2 = _nextUsefulSlice(s2)

            if t1 == _vT_CAR and t2 == _vT_END:
                return 1
            if t2 == _vT_CAR and t1 == _vT_END:
                return -1

            if t1 == _vT_CAR:
                return -1
            if t2 == _vT_CAR:
                return 1

        if t1 != t2:
            if t1 == _vT_END:
                return -1
            if t2 == _vT_END:
                return 1
            if t1 == _vT_ALP and t2 == _vT_NUM:
                return -1
            if t2 == _vT_ALP and t1 == _vT_NUM:
                return 1
            if t1 == _vT_MSC:
                return -1
            return 1

        if t1 == _vT_MSC:
            continue

        if t1 == _vT_NUM:

            while len(cs1) > 0 and cs1[0] == '0':
                cs1 = cs1[1:]
            while len(cs2) > 0 and cs2[0] == '0':
                cs2 = cs2[1:]
            if len(cs1) < len(cs2):
                return -1
            if len(cs1) > len(cs2):
                return 1

        ret = cmp(cs1, cs2) # bytes.Compare(cs1, cs2)
        if ret != 0:
            return ret

    return 0

def main():
    import sys
    if len(sys.argv) < 3:
        print("Usage: rpmvercmp <string> <string>")
        sys.exit(1)
    val = rpmvercmp(sys.argv[1], sys.argv[2])
    print("rpmvercmp(" + sys.argv[1] + ",", sys.argv[2] + ")", "=", val)

if __name__ == "__main__":
    main()

