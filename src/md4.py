#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2015 Antoine Catton
#
# This file is part of purepython-crypto.
#
# purepython-crypto is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# purepython-crypto is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# purepython-crypto. If not, see <http://www.gnu.org/licenses/>.

import copy
import struct
import base64

# Overflow modulo
OF = 1 << 32  # 32 bit integers
BYTE_SIZE = 8


def plus(a, b):
    return (a + b) % OF


def plus3(a, b, c):
    """
    Add three 32 bit integers
    """
    return (a + b + c) % OF


def plus4(a, b, c, d):
    """
    Add four 32 bit integers
    """
    return (a + b + c + d) % OF


def rot(n, s):
    """
    Circular left rotate of s bit of n

    (n is treated as a 32 bit integer)
    """
    return ((n << s) % OF) | (n >> (32 - s))


def limit_length(l):
    return l % (1 << 64)  # Length can't be greater than 64


class MD4:
    """
    md4 hash algorithm as described in the RFC 1320 from the IETF::

        >>> MD4().hexdigest()
        '31d6cfe0d16ae931b73c59d7e0c089c0'
        >>> MD4(b'a').hexdigest()
        'bde52cb31de33e46245e05fbdbd6fb24'
        >>> MD4(b'abc').hexdigest()
        'a448017aaf21d8525fc10ae87aa6729d'
        >>> MD4(b'message digest').hexdigest()
        'd9130a8164549fe818874806e1c7014b'
        >>> MD4(b'abcdefghijklmnopqrstuvwxyz').hexdigest()
        'd79e1c308aa5bbcdeea8ed63df412da9'
        >>> MD4(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789').hexdigest()
        '043f8582f241db351ce627e153e7f0e4'
        >>> MD4(
        ...   b'12345678901234567890123456789012345678901234567890123456789012345678901234567890'
        ... ).hexdigest()
        'e33b4ddc9c38f2199c3e7b164fcc0536'
    """

    def __init__(self, data=None):
        self.a = 0x67452301
        self.b = 0xefcdab89
        self.c = 0x98badcfe
        self.d = 0x10325476
        self.buf = b''
        self.length = 0

        if data:
            self.update(data)

    def update(self, data):
        self.buf += data
        self.length += len(data) * BYTE_SIZE

        while len(self.buf) >= 64:
            block, self.buf = self.buf[0:64], self.buf[64:]
            self._process_block(block)

    def digest(self):
        md = copy.copy(self)
        md.update(b'\x80')

        to_pad = (64 + 56 - len(md.buf)) % 64
        md.update(b'\x00' * to_pad)
        md.update(struct.pack('<Q', limit_length(self.length)))

        assert len(md.buf) == 0

        return struct.pack('<LLLL', md.a, md.b, md.c, md.d)

    def hexdigest(self):
        return base64.b16encode(self.digest()).decode('ascii').lower()

    def _process_block(self, raw_block):
        assert len(raw_block) == 64

        block = struct.unpack('<' + 'I' * 16, raw_block)
        assert len(block) == 16

        def f(x, y, z):
            return (x & y) | ((~x) & z)

        def g(x, y, z):
            return (x & y) | (x & z) | (y & z)

        def h(x, y, z):
            return (x ^ y ^ z)

        def ff(a, b, c, d, k, s):
            return rot(plus3(a, f(b, c, d), block[k]), s)

        def gg(a, b, c, d, k, s):
            return rot(plus4(a, g(b, c, d), block[k], 0x5A827999), s)

        def hh(a, b, c, d, k, s):
            return rot(plus4(a, h(b, c, d), block[k], 0x6ED9EBA1), s)

        def round1(a, b, c, d):
            a = ff(a, b, c, d, 0, 3)
            d = ff(d, a, b, c, 1, 7)
            c = ff(c, d, a, b, 2, 11)
            b = ff(b, c, d, a, 3, 19)

            a = ff(a, b, c, d, 4, 3)
            d = ff(d, a, b, c, 5, 7)
            c = ff(c, d, a, b, 6, 11)
            b = ff(b, c, d, a, 7, 19)

            a = ff(a, b, c, d, 8, 3)
            d = ff(d, a, b, c, 9, 7)
            c = ff(c, d, a, b, 10, 11)
            b = ff(b, c, d, a, 11, 19)

            a = ff(a, b, c, d, 12, 3)
            d = ff(d, a, b, c, 13, 7)
            c = ff(c, d, a, b, 14, 11)
            b = ff(b, c, d, a, 15, 19)

            return a, b, c, d

        def round2(a, b, c, d):
            a = gg(a, b, c, d, 0, 3)
            d = gg(d, a, b, c, 4, 5)
            c = gg(c, d, a, b, 8, 9)
            b = gg(b, c, d, a, 12, 13)

            a = gg(a, b, c, d, 1, 3)
            d = gg(d, a, b, c, 5, 5)
            c = gg(c, d, a, b, 9, 9)
            b = gg(b, c, d, a, 13, 13)

            a = gg(a, b, c, d, 2, 3)
            d = gg(d, a, b, c, 6, 5)
            c = gg(c, d, a, b, 10, 9)
            b = gg(b, c, d, a, 14, 13)

            a = gg(a, b, c, d, 3, 3)
            d = gg(d, a, b, c, 7, 5)
            c = gg(c, d, a, b, 11, 9)
            b = gg(b, c, d, a, 15, 13)

            return a, b, c, d

        def round3(a, b, c, d):
            a = hh(a, b, c, d, 0, 3)
            d = hh(d, a, b, c, 8, 9)
            c = hh(c, d, a, b, 4, 11)
            b = hh(b, c, d, a, 12, 15)

            a = hh(a, b, c, d, 2, 3)
            d = hh(d, a, b, c, 10, 9)
            c = hh(c, d, a, b, 6, 11)
            b = hh(b, c, d, a, 14, 15)

            a = hh(a, b, c, d, 1, 3)
            d = hh(d, a, b, c, 9, 9)
            c = hh(c, d, a, b, 5, 11)
            b = hh(b, c, d, a, 13, 15)

            a = hh(a, b, c, d, 3, 3)
            d = hh(d, a, b, c, 11, 9)
            c = hh(c, d, a, b, 7, 11)
            b = hh(b, c, d, a, 15, 15)

            return a, b, c, d

        a = self.a
        b = self.b
        c = self.c
        d = self.d

        a, b, c, d = round1(a, b, c, d)
        a, b, c, d = round2(a, b, c, d)
        a, b, c, d = round3(a, b, c, d)

        self.a = plus(self.a, a)
        self.b = plus(self.b, b)
        self.c = plus(self.c, c)
        self.d = plus(self.d, d)
