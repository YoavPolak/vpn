# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""Portmap / rpcbind."""

from pypacker import pypacker

PMAP_PROG = 100000
PMAP_PROCDUMP = 4
PMAP_VERS = 2


class Pmap(pypacker.Packet):
	__hdr__ = (
		("prog", "I", 0),
		("vers", "I", 0),
		("prot", "I", 0),
		("port", "I", 0),
	)
