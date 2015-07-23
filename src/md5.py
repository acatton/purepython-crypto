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


SHIFT_TABLE = (
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4,
    11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6,
    10, 15, 21,
)


T_TABLE = (
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
)


def limit_length(l):
    return l % (1 << 64)  # Length can't be greater than 64


class MD5:
    """
    md5 hash algorithm as described in the RFC 1320 from the IETF::

        >>> MD5().hexdigest()
        'd41d8cd98f00b204e9800998ecf8427e'
        >>> MD5(b'a').hexdigest()
        '0cc175b9c0f1b6a831c399e269772661'
        >>> MD5(b'abc').hexdigest()
        '900150983cd24fb0d6963f7d28e17f72'
        >>> MD5(b'message digest').hexdigest()
        'f96b697d7cb7938d525a2f31aaf161d0'
        >>> MD5(b'abcdefghijklmnopqrstuvwxyz').hexdigest()
        'c3fcd3d76192e4007dfb496cca67e13b'
        >>> MD5(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789').hexdigest()
        'd174ab98d277d9f5a5611c2c9f419d9f'
        >>> MD5(
        ...   b'12345678901234567890123456789012345678901234567890123456789012345678901234567890'
        ... ).hexdigest()
        '57edf4a22be3c955ac49da2e2107b67a'
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

        for i in range(64):
            if i < 16:
                f = (b & c) | ((~b) & d)
                k = i
            elif i < 32:
                f = (b & d) | (c & (~d))
                k = (5 * i + 1) % 16
            elif i < 48:
                f = (b ^ c ^ d)
                k = (3 * i + 5) % 16
            else:
                f = c ^ (b | (~d))
                k = (7 * i) % 16

            s = SHIFT_TABLE[i]

            a = plus(b, rot(plus4(a, f, block[k], T_TABLE[i]), s))
            a, b, c, d = d, a, b, c

        self.a = plus(self.a, a)
        self.b = plus(self.b, b)
        self.c = plus(self.c, c)
        self.d = plus(self.d, d)
