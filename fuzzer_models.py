# Copyright (C) 2018  Bruno Melo <brunom@lasca.ic.unicamp.br>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
from collections import OrderedDict

from scapy.all import *

# USER: user-defined list of additional strings to be used during a campaign
string_list = []

option_model = {
    # name:             [num, type, min, max, [ special_rand_sing_class, special_seq_sing_class ], ext_list ]
    "If-Match":         [ 1, 'opaque', 0, 8, [], [] ],
    "Uri-Host":         [ 3, 'string', 1, 255, [], string_list ],
    "ETag":             [ 4, 'opaque', 1, 8, [], [] ],
    "If-None-Match":    [ 5, 'empty', 0, 1, [], [-1] ], # empty is a special case of uint, with ext_list=[-1] added to SeqSingNum
    "Observe":          [ 6, 'uint', 0, 2**24-1, [], [] ], # [0, 1] are special cases, but are always present anyway
    "Uri-Port":         [ 7, 'uint', 0, 2**16-1,
        [ getattr(scapy.all, 'RandSingBinPortNumber'), getattr(scapy.all, 'SeqSingBinPortNumber') ], [] ],
    "Location-Path":    [ 8, 'string', 0, 255, [], string_list ], # Response
    "Uri-Path":         [ 11, 'string', 0, 255, [], string_list ],
    "Content-Format":   [ 12, 'uint', 0, 2**16-1,
        [ getattr(scapy.all, 'RandSingContentFormat'), getattr(scapy.all, 'SeqSingContentFormat') ], [] ],
    "Max-Age":          [ 14, 'uint', 0, 2**32-1, [], [] ], # Response
    "Uri-Query":        [ 15, 'string', 0, 255,
        [ getattr(scapy.all, 'RandSingQueryAttribute'), getattr(scapy.all, 'SeqSingQueryAttribute') ], string_list ],
    "Accept":           [ 17, 'uint', 0, 2**16-1,
        [ getattr(scapy.all, 'RandSingContentFormat'), getattr(scapy.all, 'SeqSingContentFormat') ], [] ],
    "Location-Query":   [ 20, 'string', 0, 255,
        [ getattr(scapy.all, 'RandSingQueryAttribute'), getattr(scapy.all, 'SeqSingQueryAttribute') ], string_list ], # Response
    "Block2":           [ 23, 'uint', 0, 2**24-1,
        [ getattr(scapy.all, 'RandSingBlock'), getattr(scapy.all, 'SeqSingBlock') ], [] ],
    "Block1":           [ 27, 'uint', 0, 2**24-1,
        [ getattr(scapy.all, 'RandSingBlock'), getattr(scapy.all, 'SeqSingBlock') ], [] ],
    "Size2":            [ 28, 'uint', 0, 2**32-1, [], [] ],
    "Proxy-Uri":        [ 35, 'string', 1, 1034, [], string_list ], # Forward-Proxy
    "Proxy-Scheme":     [ 39, 'string', 1, 255, [], string_list ], # Forward-Proxy
    "Size1":            [ 60, 'uint', 0, 2**32-1, [], [] ],
}
option_model = OrderedDict(sorted(option_model.items(), key=lambda t: t[1][0]))

option_type_model = {
    # type:     [rand_class, rand_sing_class, seq_sing_class]
    "empty":    [ getattr(scapy.all, 'RandBinNum'), getattr(scapy.all, 'RandSingBinNum'), getattr(scapy.all, 'SeqSingBinNum') ],
    "uint":     [ getattr(scapy.all, 'RandBinNum'), getattr(scapy.all, 'RandSingBinNum'), getattr(scapy.all, 'SeqSingBinNum') ],
    "string":   [ getattr(scapy.all, 'RandString'), getattr(scapy.all, 'RandSingString'), getattr(scapy.all, 'SeqSingString') ],
    "opaque":   [ getattr(scapy.all, 'RandBin'), getattr(scapy.all, 'RandSingBin'), getattr(scapy.all, 'SeqSingBin') ],
}
