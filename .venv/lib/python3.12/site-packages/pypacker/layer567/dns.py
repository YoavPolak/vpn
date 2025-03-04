# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""Domain Name System."""
import logging

from pypacker import pypacker, triggerlist
from pypacker.pypacker import FIELD_FLAG_AUTOUPDATE
from pypacker.structcbs import unpack_H, unpack_HHHH

logger = logging.getLogger("pypacker")


DNS_Q			= 0
DNS_R			= 1

# Opcodes
DNS_QUERY		= 0
DNS_IQUERY		= 1
DNS_STATUS		= 2
DNS_NOTIFY		= 4
DNS_UPDATE		= 5

# Flags
DNS_AN			= 0x8000		# this is a response
DNS_CD			= 0x0010		# checking disabled
DNS_AD			= 0x0020		# authenticated data
DNS_Z			= 0x0040		# unused
DNS_RA			= 0x0080		# recursion available
DNS_RD			= 0x0100		# recursion desired
DNS_TC			= 0x0200		# truncated
DNS_AA			= 0x0400		# authoritative answer

# Response codes
DNS_RCODE_NOERR		= 0
DNS_RCODE_FORMERR	= 1
DNS_RCODE_SERVFAIL	= 2
DNS_RCODE_NXDOMAIN	= 3
DNS_RCODE_NOTIMP	= 4
DNS_RCODE_REFUSED	= 5
DNS_RCODE_YXDOMAIN	= 6
DNS_RCODE_YXRRSET	= 7
DNS_RCODE_NXRRSET	= 8
DNS_RCODE_NOTAUTH	= 9
DNS_RCODE_NOTZONE	= 10

# RR types
DNS_A			= 1
DNS_NS			= 2
DNS_CNAME		= 5
DNS_SOA			= 6
DNS_WKS			= 11
DNS_PTR			= 12
DNS_HINFO		= 13
DNS_MINFO		= 14
DNS_MX			= 15
DNS_TXT			= 16
DNS_RP			= 17
DNS_SIG			= 24
DNS_GPOS		= 27
DNS_AAAA		= 28
DNS_LOC			= 29
DNS_SRV			= 33
DNS_NAPTR		= 35
DNS_KX			= 36
DNS_CERT		= 37
DNS_DNAME		= 39
DNS_DS			= 43
DNS_SSHFP		= 44
DNS_IPSECKEY		= 45
DNS_RRSIG		= 46
DNS_NSEC		= 47
DNS_DNSKEY		= 48
DNS_DHCID		= 49
DNS_NSEC3		= 50
DNS_NSEC3PARAM		= 51
DNS_TLSA		= 52
DNS_SPF			= 99
DNS_TKEY		= 249
DNS_TSIG		= 250
DNS_IXFR		= 251
DNS_AXFR		= 252
DNS_CAA			= 257
DNS_TA			= 32768
DNS_DLV			= 32769


# RR classes
DNS_IN			= 1
DNS_CHAOS		= 3
DNS_HESIOD		= 4
DNS_ANY			= 255


def get_bts_for_msg_compression(tl_packet):
	"""return -- header bytes of DNS or b"" """
	# DNS.Triggestlist[sub] -> sub._triggelistpacket_parent == DNS
	if tl_packet._triggelistpacket_parent is not None:
		#logger.debug("Returning parent header bytes")
		return tl_packet._triggelistpacket_parent.header_bytes
	#logger.debug("No parent header bytes :/")
	return b""


class DNS(pypacker.Packet):
	__hdr__ = (
		("id", "H", 0x1234),
		("flags", "H", DNS_AD | DNS_RD),
		("questions_amount", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("answers_amount", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("authrr_amount", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("addrr_amount", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("queries", None, triggerlist.TriggerList),
		("answers", None, triggerlist.TriggerList),
		("auths", None, triggerlist.TriggerList),
		("addrecords", None, triggerlist.TriggerList)
	)

	class Query(pypacker.Packet):
		"""DNS question."""
		__hdr__ = (
			("name", None, b"\x03www\x04test\x03com\x00"),
			("type", "H", DNS_A),
			("cls", "H", DNS_IN)
		)

		name_s = pypacker.get_property_dnsname("name", cb_mc_bytes=get_bts_for_msg_compression)

		def _dissect(self, buf):
			q_end = DNS.get_dns_length(buf)
			self.name = buf[:q_end]
			#logger.debug("val / format: %s %s" % (self._name, self._name_format))
			return len(buf)  # name (including 0) + type + cls

	class Answer(pypacker.Packet):
		"""DNS resource record."""
		__hdr__ = (
			("name", None, b"\xc0\x0c"),
			("type", "H", DNS_A),
			("cls", "H", DNS_IN),
			("ttl", "I", 180),
			("dlen", "H", 4),			# length of the next field
			("address", None, b"1234")		# eg IPv4
		)

		name_s = pypacker.get_property_dnsname("name", cb_mc_bytes=get_bts_for_msg_compression)

		def _get_address_readable(self):
			if self.type == DNS_A:
				return pypacker.ip4_bytes_to_str(self.address)
			elif self.type == DNS_AAAA:
				return pypacker.ip6_bytes_to_str(self.address)
			elif self.type == DNS_CNAME:
				return pypacker.dns_name_decode(self.address)
			else:
				# Unknown type
				return ""

		address_s = property(_get_address_readable)

		def _dissect(self, buf):
			name_end = DNS.get_dns_length(buf)
			self.name = buf[:name_end]
			# needed set format
			start = name_end + 8
			addr_len = unpack_H(buf[start:start + 2])[0]
			self.address = buf[start + 2:start + 2 + addr_len]
			#logger.debug("address: %s" % self.address)
			return start + 2 + addr_len

	class Auth(pypacker.Packet):
		"""Auth, generic type."""
		__hdr__ = (
			("name", "H", 0),
			("type", "H", 0),
			("cls", "H", 0),
			("ttl", "I", 0),
			("dlen", "H", 0),		# length of the rest of header: server + x, x becmoes body content
			("server", None, b"\x03www\x04test\x03com\x00")
		)

		server_s = pypacker.get_property_dnsname("server", cb_mc_bytes=get_bts_for_msg_compression)

		def _dissect(self, buf):
			# Needed set format
			# Find server name by 0-termination
			buf_bts = buf.tobytes()
			off_end = buf_bts.find(b"\x00", 12)

			if off_end == -1:
				off_end = len(buf)
			else:
				off_end += 1
			self.server = buf[12: off_end]
			#logger.debug("server: %s" % self.server)

			return off_end

	class AuthSOA(pypacker.Packet):
		"""
		Auth type SOA.
		Not used atm
		"""
		__hdr__ = (
			("name", "H", 0),
			("type", "H", 0),
			("cls", "H", 0),
			("ttl", "I", 0),
			("dlen", "H", 0),
			("name2", None, b"\x03www\x04test\x03com\x00"),
			("mailbox", None, b"\x03www\x04test\x03com\x00"),
			("pserver", "H", 0),
			("mbox", "H", 0),
			("serial", "H", 0),
			("refresh", "H", 0),
			("retry", "H", 0),
			("expire", "H", 0),
			("minttl", "H", 0)
		)

		name_s = pypacker.get_property_dnsname("name", get_bts_for_msg_compression)
		mailbox_s = pypacker.get_property_dnsname("mailbox", get_bts_for_msg_compression)

		def _dissect(self, buf):
			# Set format
			# Find server name by 0-termination
			buf_bts = buf.tobytes()
			idx = buf_bts.find(b"\x00", 12)
			#logger.debug(buf[12: idx+1])
			# Don't add trailing \0
			self.name = buf[12: idx + 1]
			#logger.debug("name: %s" % buf[idx + 1: -14])
			self.mailbox = buf[idx + 1: -14]
			return len(buf)

	class AddRecord(pypacker.Packet):
		"""DNS additional records."""
		__hdr__ = (
			("name", "H", 0),
			("type", "H", 0x0001),
			("clz", "H", 0x0001),
			("ts", "I", 0),
			("dlen", "H", 0),
			("addr", None, b"\x01\x02\x03\x04")
		)

		def _dissect(self, buf):
			#logger.debug(buf[0: idx+1])
			self.addr = buf[12:]
			#logger.debug("addr: %s" % self.addr)
			return len(buf)

	class AddRecordRoot(pypacker.Packet):
		"""DNS additional records."""
		__hdr__ = (
			("name", "B", 0),
			("type", "H", 0x0001),
			("udpsize", "H", 0x0001),
			("rcode", "B", 0),
			("v", "B", 0),
			("z", "H", 0),
			("dlen", "H", 0)
		)

	@staticmethod
	def get_dns_length(bts):
		"""
		return -- Length of DNS name including terminating 0 (if present)
		"""
		off = 0

		while off < len(bts):
			# Check for pointer
			if bts[off] & 0xC0:
				#logger.debug("Found pointer at %d", off)
				return off + 2
			# Found terminating 0
			elif bts[off] == 0x00:
				#logger.debug("Found 0 byte at %d", off)
				return off + 1
			off += bts[off] + 1

		return 0

	@staticmethod
	def _dissect_queries(amount, collect_queries=True):
		amount_collect = [amount, collect_queries]

		def _dissect_queries_sub(buf):
			#logger.debug(">> Dissecting questions: %r" % amount_collect)
			queries = []
			off = 0
			while amount_collect[0] > 0 and off < len(buf):
				# Find name by 0-termination
				q_end = off + DNS.get_dns_length(buf[off:]) + 4

				if amount_collect[1]:
					q = DNS.Query(buf[off: q_end])
					queries.append(q)
				off = q_end
				amount_collect[0] -= 1
			return queries if amount_collect[1] else off
		return _dissect_queries_sub

	@staticmethod
	def _dissect_answers(amount, collect_answers=True):
		amount_collect = [amount, collect_answers]

		def _dissect_answers_sub(buf):
			#logger.debug(">> Dissecting answers: %r" % amount_collect)
			answers = []
			off = 0

			while amount_collect[0] > 0 and off < len(buf):
				# Find name by label/0-termination
				# DNS name:x + type:2 + class:2 + ttl:4
				a_end = off + DNS.get_dns_length(buf[off:]) + 2 + 2 + 4
				dlen = unpack_H(buf[a_end: a_end + 2])[0]
				# dlen header: 2 + dlen
				a_end += (2 + dlen)

				if amount_collect[1]:
					a = DNS.Answer(buf[off: a_end])
					answers.append(a)
				off = a_end
				amount_collect[0] -= 1
			return answers if amount_collect[1] else off
		return _dissect_answers_sub

	@staticmethod
	def _dissect_authserver(amount, collect_authserver=True):
		amount_collect = [amount, collect_authserver]

		def _dissect_authserver_sub(buf):
			#logger.debug(">> Dissecting authserver: %r" % amount_collect)
			authserver = []
			off = 0

			while amount_collect[0] > 0 and off < len(buf):
				dlen = unpack_H(buf[off + 10: off + 12])[0]
				authlen = 12 + dlen

				if amount_collect[1]:
					a = DNS.Auth(buf[off: off + authlen])
					authserver.append(a)
				off += authlen
				amount_collect[0] -= 1
			return authserver if amount_collect[1] else off
		return _dissect_authserver_sub

	@staticmethod
	def _dissect_addreq(amount, collect_addreq=True):
		amount_collect = [amount, collect_addreq]

		def _dissect_addreq_sub(buf):
			#logger.debug(">> Dissecting addreq: %r" % amount_collect)
			addrecords = []
			off = 0

			while amount_collect[0] > 0 and off < len(buf):
				if buf[off: off + 3] == b"\x00\x00\x29":
					if amount_collect[1]:
						a = DNS.AddRecordRoot(buf[off: off + 11])
						addrecords.append(a)
					off += 11
				else:
					dlen = unpack_H(buf[off + 10: off + 10 + 2])[0]

					if amount_collect[1]:
						a = DNS.AddRecord(buf[off: off + 12 + dlen])
						addrecords.append(a)
					off += 12 + dlen

				amount_collect[0] -= 1
			return addrecords if amount_collect[1] else off
		return _dissect_addreq_sub

	def _dissect(self, buf):
		# Unpack basic data to get things done
		quests_amount, ans_amount, authserver_amount, addreq_amount = unpack_HHHH(buf[4: 12])
		# Sanity check: assume max amount of 50 addresses
		if quests_amount > 50 or ans_amount > 50 or authserver_amount > 50 or addreq_amount > 50:
			raise Exception("Address count too high, invalid packet")
		off = 12
		#logger.debug(self.__class__)
		addlen = DNS._dissect_queries(quests_amount, collect_queries=False)(buf[off:])
		self.queries(buf[off: off + addlen], DNS._dissect_queries(quests_amount))
		off += addlen

		addlen = DNS._dissect_answers(ans_amount, collect_answers=False)(buf[off:])
		self.answers(buf[off: off + addlen], DNS._dissect_answers(ans_amount))
		off += addlen

		addlen = DNS._dissect_authserver(authserver_amount, collect_authserver=False)(buf[off:])
		self.auths(buf[off: off + addlen], DNS._dissect_authserver(authserver_amount))
		off += addlen

		addlen = DNS._dissect_addreq(addreq_amount, collect_addreq=False)(buf[off:])
		self.addrecords(buf[off: off + addlen], DNS._dissect_addreq(addreq_amount))
		off += addlen

		return off

	def _update_fields(self):
		if self._header_value_changed:
			#logger.debug("Updating lenghts")

			if self.questions_amount_au_active:
				self.questions_amount = len(self.queries)
			if self.answers_amount_au_active:
				self.answers_amount = len(self.answers)
			if self.authrr_amount_au_active:
				self.authrr_amount = len(self.auths)
			if self.addrr_amount_au_active:
				self.addrr_amount = len(self.addrecords)
			#logger.debug("finished updating lengths")

	def get_resolved_addresses(self):
		ret = {}

		if self.answers_amount == 0 or self.questions_amount == 0:
			return ret
		"""
		if self.questions_amount > 1:
			# Only one question for now
			logger.warning("More than 1 question")
			logger.warning(self.queries)
		"""
		question_dns = self.queries[0].name_s

		for answer in self.answers:
			# Assume answer for first query
			if answer.type in [DNS_A, DNS_AAAA]:
				ret[answer.address_s] = question_dns[:-1]

		return ret
