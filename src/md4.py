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


SHIFT_TABLE = (
    3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 5, 9, 13, 3, 5,
    9, 13, 3, 5, 9, 13, 3, 5, 9, 13, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15,
    3, 9, 11, 15,
)


K_TABLE = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 4, 8, 12, 1, 5, 9,
    13, 2, 6, 10, 14, 3, 7, 11, 15, 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3,
    11, 7, 15,
)


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

        a = self.a
        b = self.b
        c = self.c
        d = self.d

        for i in range(48):
            if i < 16:
                f = (b & c) | ((~b) & d)
                val = 0
            elif i < 32:
                f = (b & c) | (b & d) | (c & d)
                val = 0x5a827999
            else:
                f = (b ^ c ^ d)
                val = 0x6ed9eba1

            k = K_TABLE[i]
            s = SHIFT_TABLE[i]
            a = rot(plus4(a, f, block[k], val), s)
            a, b, c, d = d, a, b, c

        self.a = plus(self.a, a)
        self.b = plus(self.b, b)
        self.c = plus(self.c, c)
        self.d = plus(self.d, d)
