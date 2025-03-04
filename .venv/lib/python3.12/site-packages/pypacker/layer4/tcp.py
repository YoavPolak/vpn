# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""
Transmission Control Protocol (TCP)

RFC 675 - Specification of Internet Transmission Control Program, December 1974 Version
RFC 793 - TCP v4
RFC 1122 - includes some error corrections for TCP
RFC 1323 - TCP-Extensions
RFC 1379 - Extending TCP for Transactions—Concepts
RFC 1948 - Defending Against Sequence Number Attacks
RFC 2018 - TCP Selective Acknowledgment Options
RFC 4614 - A Roadmap for TCP Specification Documents
RFC 5681 - TCP Congestion Control
RFC 6298 - Computing TCP's Retransmission Timer
RFC 6824 - TCP Extensions for Multipath Operation with Multiple Addresses
"""
import logging
import struct

from pypacker import pypacker, triggerlist, checksum
from pypacker.pypacker import FIELD_FLAG_AUTOUPDATE, FIELD_FLAG_IS_TYPEFIELD
from pypacker.structcbs import unpack_H, pack_ipv4_header, pack_ipv6_header

from pypacker.layer4 import ssl
from pypacker.layer567 import bgp, http, mqtt, rtp, sip, telnet, tpkt, pmap

# avoid references for performance reasons
in_cksum = checksum.in_cksum

logger = logging.getLogger("pypacker")

# TCP control flags
TH_FIN		= 0x01		# end of data
TH_SYN		= 0x02		# synchronize sequence numbers
TH_RST		= 0x04		# reset connection
TH_PUSH		= 0x08		# push
TH_ACK		= 0x10		# acknowledgment number set
TH_URG		= 0x20		# urgent pointer set
TH_ECE		= 0x40		# ECN echo, RFC 3168
TH_CWR		= 0x80		# congestion window reduced

TCP_PORT_MAX	= 65535		# maximum port
TCP_WIN_MAX	= 65535		# maximum (unscaled) window

# TCP Options (opt_type) - http://www.iana.org/assignments/tcp-parameters
TCP_OPT_EOL		= 0		# end of option list
TCP_OPT_NOP		= 1		# no operation
TCP_OPT_MSS		= 2		# maximum segment size
TCP_OPT_WSCALE		= 3		# window scale factor, RFC 1072
TCP_OPT_SACKOK		= 4		# SACK permitted, RFC 2018
TCP_OPT_SACK		= 5		# SACK, RFC 2018
TCP_OPT_ECHO		= 6		# echo (obsolete), RFC 1072
TCP_OPT_ECHOREPLY	= 7		# echo reply (obsolete), RFC 1072
TCP_OPT_TIMESTAMP	= 8		# timestamp, RFC 1323
TCP_OPT_POCONN		= 9		# partial order conn, RFC 1693
TCP_OPT_POSVC		= 10		# partial order service, RFC 1693
TCP_OPT_CC		= 11		# connection count, RFC 1644
TCP_OPT_CCNEW		= 12		# CC.NEW, RFC 1644
TCP_OPT_CCECHO		= 13		# CC.ECHO, RFC 1644
TCP_OPT_ALTSUM		= 14		# alt checksum request, RFC 1146
TCP_OPT_ALTSUMDATA	= 15		# alt checksum data, RFC 1146
TCP_OPT_SKEETER		= 16		# Skeeter
TCP_OPT_BUBBA		= 17		# Bubba
TCP_OPT_TRAILSUM	= 18		# trailer checksum
TCP_OPT_MD5		= 19		# MD5 signature, RFC 2385
TCP_OPT_SCPS		= 20		# SCPS capabilities
TCP_OPT_SNACK		= 21		# selective negative acks
TCP_OPT_REC		= 22		# record boundaries
TCP_OPT_CORRUPT		= 23		# corruption experienced
TCP_OPT_SNAP		= 24		# SNAP
TCP_OPT_TCPCOMP		= 26		# TCP compression filter
TCP_OPT_MAX		= 27


class TCPOptSingle(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
	)

	type_t = pypacker.get_property_translator("type", "TCP_OPT_")


class TCPOptMulti(pypacker.Packet):
	"""
	len = total length (header + data)
	"""
	__hdr__ = (
		("type", "B", 0),
		("len", "B", 2, FIELD_FLAG_AUTOUPDATE)
	)

	type_t = pypacker.get_property_translator("type", "TCP_OPT_")

	def _update_fields(self):
		if self.len_au_active:
			self.len = len(self)

TCP_PROTO_TELNET	= 23
TCP_PROTO_TPKT		= 102
TCP_PROTO_PMAP		= 111
TCP_PROTO_BGP		= 179
TCP_PROTO_SSL		= 443
TCP_PROTO_MQTT		= (1883, 8883)
TCP_PROTO_HTTP		= (80, 8008, 8080)
TCP_PROTO_RTP 		= (5004, 5005)
TCP_PROTO_SIP		= (5060, 5061)

TCP_OFF_BTS_OPTS	= 20


def cb_get_flag_description(value, value_name):
	descr = [name_d for value_d, name_d in value_name.items() if value_d & value != 0]
	return " | ".join(descr)


class TCP(pypacker.Packet):
	__hdr__ = (
		("sport", "H", 0xDEAD),
		("dport", "H", 0, FIELD_FLAG_IS_TYPEFIELD),
		("seq", "I", 0xDEADBEEF),
		("ack", "I", 0),
		("off_x2", "B", ((5 << 4) | 0), FIELD_FLAG_AUTOUPDATE),  # off=# 4-byte words, 10*4 Byte
		("flags", "B", TH_SYN),  # acces via (obj.flags & TH_XYZ)
		("win", "H", TCP_WIN_MAX),
		("sum", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("urp", "H", 0),
		("opts", None, triggerlist.TriggerList)
	)

	# 4 bits | 4 bits
	# offset | reserved
	# offset * 4 = header length
	def __get_off(self):
		return self.off_x2 >> 4

	def __set_off(self, value):
		self.off_x2 = (value << 4) | (self.off_x2 & 0xF)
	off = property(__get_off, __set_off)

	# return real header length based on header info
	def __get_hlen(self):
		return self.off * 4

	# set real header length based on header info (should be n*4)
	def __set_hlen(self, value):
		self.off = int(value / 4)

	hlen = property(__get_hlen, __set_hlen)
	flags_t = pypacker.get_property_translator("flags", "TH_", cb_get_description=cb_get_flag_description)

	__handler__ = {
		TCP_PROTO_BGP: bgp.BGP,
		TCP_PROTO_TELNET: telnet.Telnet,
		TCP_PROTO_TPKT: tpkt.TPKT,
		TCP_PROTO_PMAP: pmap.Pmap,
		TCP_PROTO_MQTT: mqtt.MQTTBase,
		TCP_PROTO_HTTP: http.HTTP,
		TCP_PROTO_SSL: ssl.SSL,
		TCP_PROTO_RTP: rtp.RTP,
		TCP_PROTO_SIP: sip.SIP
	}

	def _update_fields(self):
		# TCP-checksum needs to be updated on one of the following:
		# - this layer itself or any higher layer changed
		# - changes to the IP-pseudoheader
		update = True
		# update header length. NOTE: needs to be a multiple of 4 Bytes.
		# options length need to be multiple of 4 Bytes
		if self._header_value_changed and self.off_x2_au_active:
			self.off = int(self.header_len / 4) & 0xF

		# we need some IP as lower layer
		if self._lower_layer is None:
			return

		#self._update_higherlayer_id()

		try:
			# changes to IP-layer, don't mind if this isn't IP
			if not self._lower_layer._header_value_changed:
				# pseudoheader didn't change, further check for changes in layers
				update = self._changed()
				#logger.debug("Changes in this + upper layer: %r" % update)
			#else:
			#	logger.debug("Lower layer %r changed!" % self._lower_layer.__class__)
		except:
			# Assume not an IP packet: we can't calculate the checksum
			update = False

		if update and self.sum_au_active:
			self._calc_sum()

	def _dissect(self, buf):
		# Header length: 20 + len(opts)
		# XXXX???? (headerlen:4 reserved:4) -zero out-> 0000XXXX -*4-> 00XXXX00 (0x3C)
		olen = ((buf[12] >> 2) & 0x3C) - TCP_OFF_BTS_OPTS  # optlen = dataoffset - fixedlen

		if olen > 0:
			# Parse options, add offset-length to standard-length
			opts_bytes = buf[TCP_OFF_BTS_OPTS: TCP_OFF_BTS_OPTS + olen]
			self.opts(opts_bytes, TCP._dissect_opts)
		elif olen < 0:
			raise Exception("TCP length is invalid: %d" % olen)

		htype = None

		try:
			# Source or destination port should match
			ports = [unpack_H(buf[0:2])[0], unpack_H(buf[2:4])[0]]
			htype = [x for x in ports if x in self._id_handlerclass_dct[TCP]][0]
			#logger.debug("TCP: trying to set handler, type: %d = %s" %
			#(type, self._id_handlerclass_dct[TCP][type]))
		except:
			# No type found
			pass
		return 20 + olen, htype

	__TCP_OPT_SINGLE = {TCP_OPT_EOL, TCP_OPT_NOP}

	@staticmethod
	def _dissect_opts(buf):
		"""Parse TCP options using buf and return them as List."""
		#logger.debug("Parsing opts")
		optlist = []
		off = 0

		while off < len(buf):
			# logger.debug("got TCP-option type %s" % buf[i])
			if buf[off] in TCP.__TCP_OPT_SINGLE:
				opt = TCPOptSingle(buf[off: off + 1])
				off += 1
			else:
				olen = buf[off + 1]
				# p = TCPOptMulti(type=buf[i], len=olen, body_bytes=buf[i + 2: i + olen])
				opt = TCPOptMulti(buf[off: off + olen])
				off += olen  # typefield + lenfield + data-len
			optlist.append(opt)
		# logger.debug("tcp: parseopts finished, length: %d" % len(optlist))
		return optlist

	def _calc_sum(self):
		"""Recalculate the TCP-checksum. This won't reset changed state."""
		# TCP and underwriting are freaky bitches: we need the IP pseudoheader
		# to calculate their checksum.
		try:
			# we need src/dst for checksum-calculation
			src, dst = self._lower_layer.src, self._lower_layer.dst
			self.sum = 0
			# logger.debug("TCP sum recalc: IP=%d / %s / %s" % (len(src), src, dst))

			tcp_bin = self.header_bytes + self.body_bytes
			# IP-pseudoheader, check if version 4 or 6
			if len(src) == 4:
				s = pack_ipv4_header(src, dst, 6, len(tcp_bin))  # 6 = TCP
			else:
				s = pack_ipv6_header(src, dst, 6, len(tcp_bin))  # 6 = TCP

			# Get checksum of concatenated pseudoheader+TCP packet
			# logger.debug("pseudoheader: %r" % s)
			# logger.debug("tcp_bin: %r" % tcp_bin)
			# assign via non-shadowed variable to trigger re-packing
			self.sum = in_cksum(s + tcp_bin)
			# logger.debug(">>> new checksum: %0X" % self._sum)
		except:
			# Not an IP packet as lower layer (src, dst not present) or invalid src/dst
			# logger.debug("could not calculate checksum: %r" % e)
			pass

	def direction(self, other):
		direction = 0
		# logger.debug("checking direction: %s<->%s" % (self, other))
		if self.sport == other.sport and self.dport == other.dport:
			direction |= pypacker.Packet.DIR_SAME
		if self.sport == other.dport and self.dport == other.sport:
			direction |= pypacker.Packet.DIR_REV
		if direction == 0:
			direction = pypacker.Packet.DIR_UNKNOWN
		return direction

	def reverse_address(self):
		self.sport, self.dport = self.dport, self.sport

	# Segments collected by ra_collect
	ra_segments = pypacker.get_ondemand_property("ra_segments", lambda: {})
	# Amount of bytes collected by ra_collect
	ra_bts_cnt = pypacker.get_ondemand_property("ra_bts_cnt", lambda: 0)

	def ra_collect(self, pkt_list):
		"""
		Collect TCP segments which have the same direction as this packet for later reassemblation.
		Concatenated segments can be retrieved via ra_bin(). Does not check for missing
		segments.
		return -- ra_bytes_cnt, [True|False]: amount of bytes added (sum of body bytes),
			final packet found (RST or FIN). True indicates that ra_bin() can be called.
		"""
		if type(pkt_list) is not list:
			pkt_list = [pkt_list]

		for segment in pkt_list:
			if self.direction(segment) != pypacker.Packet.DIR_SAME or len(segment.body_bytes) == 0:
				continue

			seq_store = segment.seq
			# Final packet found: connection is going to be terminated
			if (segment.flags & TH_FIN) != 0 or (segment.flags & TH_RST) != 0:
				return 0, True

			if seq_store < self.seq:
				logger.warning("Seq of new segment is lower than start, assuming overflow")
				seq_store += 0xFFFF

			self.ra_segments[seq_store] = segment.body_bytes
			self.ra_bts_cnt += len(segment.body_bytes)

		return self.ra_bts_cnt, False

	def ra_bin(self):
		"""
		Re-assemble retrieved TCP segments in sorted order (body bytes of TCP segments) and
		flush the internal buffer.
		"""
		self.ra_segments[self.seq] = self.body_bytes
		sorted_list = sorted(self.ra_segments.items(), key=lambda t: t[0])
		bts_lst = [bts for _, bts in sorted_list]
		self.ra_segments.clear()
		self.ra_bts_cnt = 0
		return b"".join(bts_lst)
