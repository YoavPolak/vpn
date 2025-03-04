# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""
Message Queuing Telemetry Transport (MQTT)
https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html

Note: Most lengths are *not* en/decoded via special MQTT format (see MQTTBase.en/decode_length())
but via standard pack/unpack. Change to more complex/inperformant en/decoding if needed.
"""
import logging

from pypacker.pypacker import Packet
from pypacker.triggerlist import TriggerList
from pypacker.structcbs import pack_B, unpack_H

logger = logging.getLogger("pypacker")

# Message Types:
MSGTYPE_RESERVED = 0
MSGTYPE_CONNECT = 1
MSGTYPE_CONNACK = 2
MSGTYPE_PUBLISH = 3
MSGTYPE_PUBACK = 4
MSGTYPE_PUBRECV = 5
MSGTYPE_PUBREL = 6
MSGTYPE_PUBCOMPLETE = 7
MSGTYPE_SUBSCRIBEREQ = 8
MSGTYPE_SUBSCRIBEACK = 9
MSGTYPE_UNSUBSCRIBE = 10
MSGTYPE_UNSUBACK = 11
MSGTYPE_PINGREQ = 12
MSGTYPE_PINGRESP = 13
MSGTYPE_DISCONNECT = 14


class Connect(Packet):
	__hdr__ = (
		("pnamelen", "H", 0),
		("pname", None, b""),
		("version", "B", 0),
		("conflags", "B", 0),
		("keepalive", "H", 0),
		("clientidlen", "H", 0),
		("clientid", None, b"")
	)

	def _dissect(self, buf):
		pnamelen = unpack_H(buf[:2])[0]
		self.pname = buf[2: 2 + pnamelen]
		off_clientidlen = 2 + pnamelen + 1 + 1 + 2
		clientidlen = unpack_H(buf[off_clientidlen: off_clientidlen + 2])[0]
		off_clientid = off_clientidlen + 2
		self.clientid = buf[off_clientid: off_clientid + clientidlen]
		return 8 + pnamelen + clientidlen


class ConnAck(Packet):
	__hdr__ = (
		("flags", "B", 0),
		("retcode", "B", 0)
	)


class Publish(Packet):
	__hdr__ = (
		("topiclen", "H", 0),
		("topic", None, b""),
		("msgid", "H", 0)
	)

	def _dissect(self, buf):
		topiclen = unpack_H(buf[:2])[0]
		self.topic = buf[2: 2 + topiclen]

		return 2 + topiclen + 2


class PubAck(Packet):
	__hdr__ = (
		("msgid", "H", 0),
	)


class PubRecv(Packet):
	__hdr__ = (
		("msgid", "H", 0),
	)


class PubRel(Packet):
	__hdr__ = (
		("msgid", "H", 0),
	)


class PubComplete(Packet):
	__hdr__ = (
		("msgid", "H", 0),
	)


class SubRequest(Packet):
	__hdr__ = (
		("msgid", "H", 0),
		("topiclen", "H", 0),
		("topic", None, b""),
		("qos", "B", 0)
	)

	def _dissect(self, buf):
		topiclen = unpack_H(buf[2: 4])[0]
		self.topic = buf[4: 4 + topiclen]

		return 5 + topiclen


class SubAck(Packet):
	__hdr__ = (
		("msgid", "H", 0),
		("retcode", "B", 0)
	)


class Unsubscribe(Packet):
	__hdr__ = (
		("msgid", "H", 0),
	)


class UnsubAck(Packet):
	__hdr__ = (
		("msgid", "H", 0),
	)


class PingReq(Packet):
	__hdr__ = (
	)


class PingResp(Packet):
	__hdr__ = (
	)


class Discconnect(Packet):
	__hdr__ = (
	)


class MQTTBase(Packet):
	__hdr__ = (
		("flags", "B", 1),
		("mlen", None, b"\x00")  # 0xF000 = 11110000 00000000 = [one more byte] 1110000 [no more byte] 0000000
	)

	__handler__ = {
		MSGTYPE_CONNECT: Connect,
		MSGTYPE_CONNACK: ConnAck,
		MSGTYPE_PUBLISH: Publish,
		MSGTYPE_PUBACK: PubAck,
		MSGTYPE_PUBRECV: PubRecv,
		MSGTYPE_PUBREL: PubRel,
		MSGTYPE_PUBCOMPLETE: PubComplete,
		MSGTYPE_SUBSCRIBEREQ: SubRequest,
		MSGTYPE_SUBSCRIBEACK: SubAck,
		MSGTYPE_UNSUBSCRIBE: Unsubscribe,
		MSGTYPE_UNSUBACK: UnsubAck,
		MSGTYPE_PINGREQ: PingReq,
		MSGTYPE_PINGRESP: PingResp,
		MSGTYPE_DISCONNECT: Discconnect
	}

	def _dissect(self, buf):
		# Length MUST be decoded, flexible format but more imperformant bc parsing needed
		mlen_len, _ = MQTTBase.decode_length(buf[1:])
		self.mlen = buf[1: 1 + mlen_len]
		hlen = 1 + mlen_len

		return hlen, (buf[0] & 0xF0) >> 4

	@staticmethod
	def decode_length(buf):
		"""return -- mlen length in bytes, mlen value"""
		if buf[0] == 0x00:
			return 1, 0
		buf_idx = 0
		current_bt = buf[buf_idx]
		retval = current_bt & 0x7F

		while current_bt & 0x80 != 0 and buf_idx < len(buf):
			buf_idx += 1
			current_bt = buf[buf_idx]
			retval += (current_bt & 0x7F) << 7 * buf_idx
		return 1 + buf_idx, retval

	@staticmethod
	def encode_length(num):
		"""
		num -- Positive integer like 256
		return -- Encoded number as bytes like b"\x81\xff"
		"""
		bts = []
		while num > 0:
			tbenc = num % 128
			num = int(num / 128)
			hbit = 0x80 if num > 0 else 0
			bts.append(pack_B(hbit | tbenc))

		return b"".join(bts)

	def _get_mlen(self):
		return MQTTBase.decode_length(self.mlen)[1]

	def _set_mlen(self, val):
		self.mlen = MQTTBase.encode_length(val)

	mlen_d = property(_get_mlen, _set_mlen)

	def _get_msgtype(self):
		return (self.flags & 0xF0) >> 4

	def _set_msgtype(self, val):
		self.flags = (val & 0x0F) << 4 | (self.flags & 0x0F)

	msgtype = property(_get_msgtype, _set_msgtype)
