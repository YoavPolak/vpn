# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""
Prism header.
This packet type exists just for convenience. Radiotap should be prefered over prism
because of its superior flexibility. Only use this if there is no support for Radiotap
eg for some Broadcom-Chipsets (stop buying crap man).
"""
import logging

from pypacker import pypacker, triggerlist
# handler
from pypacker.layer12 import ieee80211

logger = logging.getLogger("pypacker")


PRISM_TYPE_80211	= 0
PRISM_DID_RSSI		= 0x41400000


class Did(pypacker.Packet):
	__hdr__ = (
		("id", "I", 0),
		("status", "H", 0),
		("len", "H", 0),
		("value", "I", 0),
	)


class Prism(pypacker.Packet):
	__hdr__ = (
		("code", "I", 0),
		("len", "I", 144),
		("dev", "16s", b"\x00" * 16),
		("dids", None, triggerlist.TriggerList),
	)

	__handler__ = {
		PRISM_TYPE_80211: ieee80211.IEEE80211
	}

	@staticmethod
	def _dissect_dids(buf, collect_dids=True):
		off = 0
		# Assume 10 DIDs, 24 + 10*12 = 144 bytes prism header
		end = off + 10 * 12
		dids = []

		while off < end:
			if collect_dids:
				did = Did(buf[off:off + 12])
				dids.append(did)
			off += 12

		return dids if collect_dids else off

	def _dissect(self, buf):
		off_tl = 24
		self.dids(buf[off_tl:], Prism._dissect_dids)
		hlen = off_tl + Prism._dissect_dids(buf[off_tl:], collect_dids=False)
		return hlen, PRISM_TYPE_80211
