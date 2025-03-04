# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""Dynamic Trunking Protocol."""
import logging

from pypacker import pypacker, triggerlist
from pypacker.structcbs import unpack_HH

logger = logging.getLogger("pypacker")

TRUNK_NAME	= 0x01
MAC_ADDR	= 0x04


class DTP(pypacker.Packet):
	__hdr__ = (
		("v", "B", 0),
		("tvs", None, triggerlist.TriggerList)
	)

	@staticmethod
	def _dissect_tvs(collect_tvs=True):
		collect = [collect_tvs]

		def _dissect_tvs_sub(buf):
			off = 0
			dlen = len(buf)
			tvs = []

			while off < dlen:
				# length: inclusive header
				_, hlen = unpack_HH(buf[off: off + 4])
				if collect_tvs:
					packet = TV(buf[off: off + hlen])
					tvs.append(packet)
				off += hlen
			return tvs if collect[0] else off
		return _dissect_tvs_sub

	def _dissect(self, buf):
		off_tvs = 1
		tvlen = DTP._dissect_tvs(collect_tvs=False)(buf[off_tvs:])
		#logger.debug(tvlen)
		self.tvs(buf[off_tvs: off_tvs + tvlen], DTP._dissect_tvs())
		return off_tvs + tvlen


class TV(pypacker.Packet):
	__hdr__ = (
		("t", "H", 0),
		("len", "H", 0)
	)
