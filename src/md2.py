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

from base64 import b16encode
import copy

PI_SUBST = [
    41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19, 98, 167, 5, 243, 192, 199,
    115, 140, 152, 147, 43, 217, 188, 76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66,
    111, 24, 138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47,
    238, 122, 169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93,
    154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165, 181, 209,
    215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226,
    156, 116, 4, 241, 69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
    96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71, 163, 35, 221, 81,
    175, 58, 195, 92, 249, 206, 186, 197, 234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205,
    244, 65, 129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,
    120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14,
    102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237, 31, 26,
    219, 153, 141, 51, 159, 17, 131, 20,
]


class MD2:
    """
    md2 hash algorith as described in the RFC 1319 from the IETF::

        >>> MD2().hexdigest()
        '8350e5a3e24c153df2275c9f80692773'
        >>> MD2(b'a').hexdigest()
        '32ec01ec4a6dac72c0ab96fb34c0b5d1'
        >>> MD2(b'abc').hexdigest()
        'da853b0d3f88d99b30283a69e6ded6bb'
        >>> MD2(b'message digest').hexdigest()
        'ab4f496bfb2a530b219ff33031fe06b0'
        >>> MD2(b'abcdefghijklmnopqrstuvwxyz').hexdigest()
        '4e8ddff3650292ab5a4108c3aa47940b'
        >>> MD2(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789').hexdigest()
        'da33def2a42df13975352846c30338cd'
        >>> MD2(
        ...   b'12345678901234567890123456789012345678901234567890123456789012345678901234567890'
        ... ).hexdigest()
        'd5976f79d83d3a0dc9806c3c66f3efd8'

    """
    def __init__(self, data=None):
        self.checksum = [0] * 16
        self.md = [0] * 48
        self.buf = b''

        if data:
            self.update(data)

    def update(self, data):
        self.buf += data
        while len(self.buf) >= 16:
            block, self.buf = self.buf[0:16], self.buf[16:]
            self._update_checksum(self.checksum, block)
            self._update_md(self.md, block)

    def digest(self):
        end = self._pad_block(self.buf)
        md = copy.copy(self.md)
        checksum = copy.copy(self.checksum)

        self._update_checksum(checksum, end)
        self._update_md(md, end)
        self._update_md(md, checksum)

        return bytes(md[:16])

    def hexdigest(self):
        return b16encode(self.digest()).decode('ascii').lower()

    @staticmethod
    def _update_checksum(checksum, block):
        assert len(block) == 16
        l = checksum[-1]
        for j in range(16):
            c = block[j]
            checksum[j] = checksum[j] ^ PI_SUBST[c ^ l]
            l = checksum[j]

    @staticmethod
    def _update_md(md, block):
        assert len(block) == 16
        for j in range(16):
            md[16+j] = block[j]
            md[32+j] = (md[16+j] ^ md[j])

        t = 0
        for j in range(18):
            for k in range(48):
                t = md[k] = (md[k] ^ PI_SUBST[t])
            t = (t+j) % 256

    @staticmethod
    def _pad_block(block):
        assert len(block) < 16
        to_pad = 16 - len(block)
        return block + bytes([to_pad] * to_pad)
