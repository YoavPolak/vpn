# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""Point-to-Point Protocol."""
import logging

from pypacker import pypacker, triggerlist
from pypacker.structcbs import unpack_H

# handler
from pypacker.layer3 import ip, ip6


logger = logging.getLogger("pypacker")

# http://www.iana.org/assignments/ppp-numbers
PPP_IP	= 0x21		# Internet Protocol
PPP_IP6 = 0x57		# Internet Protocol v6

# Protocol field compression
PFC_BIT	= 0x01


class PPP(pypacker.Packet):
	__hdr__ = (
		("p", None, triggerlist.TriggerList),
	)

	__handler__ = {
		PPP_IP: ip.IP,
		PPP_IP6: ip6.IP6
	}

	def _dissect(self, buf):
		hlen = 1
		ppp_type = buf[0]

		if ppp_type & PFC_BIT == 0:
			ppp_type = unpack_H(buf[:2])[0]
			hlen = 2
			self.p(buf[0:2], lambda tval: tval)
		else:
			self.p(buf[0:1], lambda tval: tval)

		return hlen, ppp_type
