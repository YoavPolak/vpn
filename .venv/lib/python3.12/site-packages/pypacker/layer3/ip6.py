# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""
Internet Protocol version 6..for whoever needs it (:

RFC 2460
"""
import logging

from pypacker import pypacker, triggerlist
from pypacker.layer3.ip_shared import IP_PROTO_HOPOPTS, IP_PROTO_IP6, IP_PROTO_ROUTING, IP_PROTO_FRAGMENT,\
	IP_PROTO_AH, IP_PROTO_ESP, IP_PROTO_DSTOPTS, IP_PROTO_ICMP6, IP_PROTO_IGMP, IP_PROTO_TCP,\
	IP_PROTO_UDP, IP_PROTO_PIM, IP_PROTO_IPXIP, IP_PROTO_SCTP, IP_PROTO_OSPF
from pypacker.pypacker import FIELD_FLAG_AUTOUPDATE, FIELD_FLAG_IS_TYPEFIELD
from pypacker.structcbs import unpack_H
# Handler
from pypacker.layer3 import esp, icmp6, igmp, ipx, ospf, pim
from pypacker.layer4 import tcp, udp, sctp


logger = logging.getLogger("pypacker")

EXT_HDRS = {
	IP_PROTO_HOPOPTS,
	IP_PROTO_IP6,
	IP_PROTO_ROUTING,
	IP_PROTO_FRAGMENT,
	IP_PROTO_AH,
	IP_PROTO_ESP,
	IP_PROTO_DSTOPTS,
	# TODO: to be implemented
	# IP_PROTO_MOBILITY
	# IP_PROTO_NONEXT
}


class IP6(pypacker.Packet):
	__hdr__ = (
		("v_fc_flow", "I", 0x60000000),
		("dlen", "H", 0, FIELD_FLAG_AUTOUPDATE),  # Length of extension header (opts header) + upwards data
		# Body handler type OR type of first extension hedader (opts header)
		("nxt", "B", 0),
		("hlim", "B", 0),  # hop limit
		("src", "16s", b"\x00" * 16),
		("dst", "16s", b"\x00" * 16),
		("opts", None, triggerlist.TriggerList)
	)

	def __get_v(self):
		return self.v_fc_flow >> 28

	def __set_v(self, v):
		self.v_fc_flow = (self.v_fc_flow & ~0xF0000000) | (v << 28)
	v = property(__get_v, __set_v)

	def __get_fc(self):
		return (self.v_fc_flow >> 20) & 0xFF

	def __set_fc(self, v):
		self.v_fc_flow = (self.v_fc_flow & ~0xFF00000) | (v << 20)
	fc = property(__get_fc, __set_fc)

	def __get_flow(self):
		return self.v_fc_flow & 0xFFFFF

	def __set_flow(self, v):
		self.v_fc_flow = (self.v_fc_flow & ~0xFFFFF) | (v & 0xFFFFF)
	flow = property(__get_flow, __set_flow)

	# Convenient access for: src[_s], dst[_s]
	src_s = pypacker.get_property_ip6("src")
	dst_s = pypacker.get_property_ip6("dst")
	nxt_t = pypacker.get_property_translator("nxt", "IP_PROTO_")

	__handler__ = {
		IP_PROTO_ICMP6: icmp6.ICMP6,
		IP_PROTO_IGMP: igmp.IGMP,
		IP_PROTO_TCP: tcp.TCP,
		IP_PROTO_UDP: udp.UDP,
		IP_PROTO_ESP: esp.ESP,
		IP_PROTO_PIM: pim.PIM,
		IP_PROTO_IPXIP: ipx.IPX,
		IP_PROTO_SCTP: sctp.SCTP,
		IP_PROTO_OSPF: ospf.OSPF
	}

	update_dependants = {tcp.TCP, udp.UDP}

	def _dissect_opts(self, buf, collect_opts=True):
		off = 0
		opts = []
		type_current = self._type_first
		OPT_BASEHEADER_LEN = 8
		OPT_OFF_OLEN_SUB = 1
		OPT_OFF_TYPENXT_IP6 = 6
		OPTLEN_IP6 = 40

		while type_current in EXT_HDRS and off < len(buf):
			# Assume there is at least one option.
			# Different header structure for IP6 and sub-header
			# IP6: Total length = 8 + Payload length
			if type_current != IP_PROTO_IP6:
				optlen = OPT_BASEHEADER_LEN + buf[off + OPT_OFF_OLEN_SUB] * 8
				type_next = buf[off]
			else:
				# Fixed header length
				optlen = OPTLEN_IP6
				type_next = buf[off + OPT_OFF_TYPENXT_IP6]

			if collect_opts:
				opt = ext_hdrs_cls[type_current](buf[off:off + optlen])
				opts.append(opt)
			#logger.debug("Current type=%d, next type=%d, optlen=%d, %r" % (
			#	type_current, type_next, optlen, buf[off:off + optlen]))
			type_current = type_next
			off += optlen

		return (off, type_current) if not collect_opts else opts

	def _dissect(self, buf):
		BASEHEADER_LEN = 40  # w/o opts
		TYPENXT_OFF = 6
		type_last = buf[TYPENXT_OFF]
		optlen = 0
		#logger.debug("1st type: %r" % type_last)

		# Parse options until type is an upper layer one
		if type_last in EXT_HDRS:
			dlen = unpack_H(buf[4: 6])[0]
			# Used by tl
			self._type_first = type_last
			optlen, type_last = self._dissect_opts(buf[BASEHEADER_LEN: BASEHEADER_LEN + dlen],
				collect_opts=False)
			#logger.debug("Handler will be=%r, optlen=%r" % (type_last, optlen))
			self.opts(buf[BASEHEADER_LEN: BASEHEADER_LEN + optlen], self._dissect_opts)

		return BASEHEADER_LEN + optlen, type_last

	def _update_fields(self):
		if self.dlen_au_active:
			self.dlen = len(self.opts.bin()) + len(self.body_bytes)
		# Set type value in nxt OR in last opts element (if present)
		# Updating is a bit more complicated so we can't use FIELD_FLAG_IS_TYPEFIELD
		# idval is None if body handler is None
		# logger.debug("handler %r -> %r", self.__class__, self.higher_layer.__class__)
		idval = pypacker.Packet.get_id_for_handlerclass(self.__class__, self.higher_layer.__class__)
		#logger.debug("nxt will be %r", idval)

		if idval is not None:
			if len(self.opts) == 0:
				self.nxt = idval
			else:
				# problem if opts[-1] is immutable
				try:
					self.opts[-1].nxt = idval
				except:
					pass

	def direction(self, other):
		# logger.debug("checking direction: %s<->%s" % (self, next))
		if self.src == other.src and self.dst == other.dst:
			# consider packet to itself: can be DIR_REV
			return pypacker.Packet.DIR_SAME | pypacker.Packet.DIR_REV
		if self.src == other.dst and self.dst == other.src:
			return pypacker.Packet.DIR_REV
		return pypacker.Packet.DIR_UNKNOWN

	def reverse_address(self):
		self.src, self.dst = self.dst, self.src


#
# Basic shared option classes
#
class IP6OptsHeader(pypacker.Packet):
	__hdr__ = (
		("nxt", "B", 0),  # next extension header protocol
		("len", "B", 0),  # option data length in 8 octect units (ignoring first 8 octets) so, len 0 == 64bit header
		("opts", None, triggerlist.TriggerList)
	)

	@staticmethod
	def parse_opts(buf):
		off = 0
		opts = []

		while off < len(buf):
			opt_type = buf[off]
			#logger.debug("IP6OptsHeader: type: %d" % opt_type)

			# http://tools.ietf.org/html/rfc2460#section-4.2
			# PAD1 option: no length or data field
			if opt_type == 1:
				#logger.debug("IP6OptionPad")
				opt = IP6OptionPad(buf[off: off + 2])
				off += 2  # type field + length field
			else:
				#logger.debug("IP6Option")
				opt_len = buf[off + 1]
				opt = IP6Option(buf[off: off + opt_len])
				off += 2 + opt_len  # type field + length field + dat

			opts.append(opt)
		#logger.debug("Returning opts: %r" % opts)
		return opts

	def _dissect(self, buf):
		hlen = 8 + buf[1] * 8
		OPTS_OFF = 2

		self.opts(buf[OPTS_OFF: hlen], IP6OptsHeader.parse_opts)
		return hlen


class IP6Option(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
		("len", "B", 0)
	)


class IP6OptionPad(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
	)


class IP6HopOptsHeader(IP6OptsHeader):
	def _dissect(self, buf):
		# logger.debug("IP6HopOptsHeader parsing")
		return IP6OptsHeader._dissect(self, buf)


class IP6RoutingHeader(pypacker.Packet):
	__hdr__ = (
		("nxt", "B", 0),  # next extension header protocol
		("len", "B", 0),  # extension data length in 8 octect units (ignoring first 8 octets) (<= 46 for type 0)
		("type", "B", 0),  # routing type (currently, only 0 is used)
		("segs_left", "B", 0),  # remaining segments in route, until destination (<= 23)
		("lastentry", "B", 0),
		("flags", "B", 0),
		("tag", "H", 0),
		("addresses", None, triggerlist.TriggerList)
	)

	def __get_sl_bits(self):
		return self.rsvd_sl_bits & 0xFFFFFF

	def __set_sl_bits(self, v):
		self.rsvd_sl_bits = (self.rsvd_sl_bits & ~0xFFFFF) | (v & 0xFFFFF)

	sl_bits = property(__get_sl_bits, __set_sl_bits)

	def _dissect(self, buf):
		hdr_size = 8
		addr_size = 16
		num_addresses = int(buf[1] / 2)
		buf_opts = buf[hdr_size: hdr_size + num_addresses * addr_size]
		self.addresses(buf_opts,
			lambda buf: [buf[i * addr_size: i * addr_size + addr_size].tobytes() for i in range(num_addresses)])

		return hdr_size + num_addresses * addr_size


class IP6FragmentHeader(pypacker.Packet):
	__hdr__ = (
		("nxt", "B", 0),			# next extension header protocol
		("resv", "B", 0),			# reserved, set to 0
		("frag_off_resv_m", "H", 0),		# frag offset (13 bits), reserved zero (2 bits), More frags flag
		("id", "I", 0)				# fragments id
	)

	def __get_frag_off(self):
		return self.frag_off_resv_m >> 3

	def __set_frag_off(self, v):
		self.frag_off_resv_m = (self.frag_off_resv_m & ~0xFFF8) | (v << 3)
	frag_off = property(__get_frag_off, __set_frag_off)

	def __get_m_flag(self):
		return self.frag_off_resv_m & 1

	def __set_m_flag(self, v):
		self.frag_off_resv_m = (self.frag_off_resv_m & ~0xFFFE) | v
	m_flag = property(__get_m_flag, __set_m_flag)


class IP6AHHeader(pypacker.Packet):
	__hdr__ = (
		("nxt", "B", 0),			 # next extension header protocol
		("len", "B", 0),			 # length of header in 4 octet units (ignoring first 2 units)
		("resv", "H", 0),			 # reserved, 2 bytes of 0
		("spi", "I", 0),			 # SPI security parameter index
		("seq", "I", 0)				 # sequence no.
	)


class IP6ESPHeader(pypacker.Packet):
	def _dissect(self, buf):
		raise NotImplementedError("ESP extension headers are not supported.")


class IP6DstOptsHeader(IP6OptsHeader):
	def _dissect(self, buf):
		# logger.debug("IP6DstOptsHeader parsing")
		IP6OptsHeader._dissect(self, buf)

ext_hdrs_cls = {
	IP_PROTO_IP6: IP6,
	IP_PROTO_HOPOPTS: IP6HopOptsHeader,
	IP_PROTO_ROUTING: IP6RoutingHeader,
	IP_PROTO_FRAGMENT: IP6FragmentHeader,
	IP_PROTO_ESP: IP6ESPHeader,
	IP_PROTO_AH: IP6AHHeader,
	IP_PROTO_DSTOPTS: IP6DstOptsHeader
	# IP_PROTO_MOBILITY:
	# IP_PROTO_NONEXT:
}
