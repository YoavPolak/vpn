# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""Ethernet Flow Control"""
import logging

from pypacker import pypacker, triggerlist
from pypacker.structcbs import pack_H, unpack_H

logger = logging.getLogger("pypacker")

PAUSE_OPCODE	= 0x0001		# Pause frame IEEE 802.3x
PFC_OPCODE	= 0x0101		# Priority Flow Control IEEE 802.1Qbb


class FlowControl(pypacker.Packet):
	__hdr__ = (
		("opcode", "H", PAUSE_OPCODE),
	)

	def _dissect(self, buf):
		if buf[:2] == b"\x01\x01":
			ul_type = PFC_OPCODE
		else:
			ul_type = PAUSE_OPCODE
		return 2, ul_type

	class Pause(pypacker.Packet):
		__hdr__ = (
			("ptime", "H", 0x0000),
		)

	class PFC(pypacker.Packet):
		__hdr__ = (
			("ms", "B", 0),  # Most significant octet is reserved,set to zero
			("ls", "B", 0),  # Least significant octet indicates time_vector parameter
			("time", None, triggerlist.TriggerList),
		)

		# Conveniant access to ls field(bit representation via list)
		# e.g. 221 -> [1, 1, 0, 1, 1, 1, 0, 1]
		def _get_ls(self):
			#return [(self.ls >> x) & 1 for x in reversed(range(8))]
			return [int(bstr) for bstr in bin(self.ls)[2:]]

		# e.g. [1, 1, 0, 1, 1, 1, 0, 1] -> 221
		def _set_ls(self, value):
			#self.ls = int("".join(map(str, value)), 2)
			self.ls = int("".join(["%d" % bint for bint in value]), 2)
		ls_list = property(_get_ls, _set_ls)

		# Conveniant access to time field (decimal representation via list)
		def _get_time(self):
			return [unpack_H(x)[0] for x in self.time]

		def _set_time(self, value):
			self.time = [pack_H(x) for x in value]
		time_list = property(_get_time, _set_time)

		@staticmethod
		def _get_times(buf):
			times = []
			for i in range(0, 16, 2):
				times.append(buf[i:i + 2].tobytes())
			return times

		def _dissect(self, buf):
			#logger.debug("Buf for PFC: %r" % buf.tobytes())
			self.time(buf[2:], FlowControl.PFC._get_times)
			return len(buf)

	__handler__ = {
		PAUSE_OPCODE: Pause,
		PFC_OPCODE: PFC
	}
