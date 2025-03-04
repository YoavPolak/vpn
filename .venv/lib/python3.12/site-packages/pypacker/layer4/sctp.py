# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""
Stream Control Transmission Protocol.
http://tools.ietf.org/html/rfc3286
http://tools.ietf.org/html/rfc2960
"""
import logging

from pypacker import pypacker, triggerlist, checksum
from pypacker.pypacker import FIELD_FLAG_AUTOUPDATE
# Handler
from pypacker.layer4 import tcp
from pypacker.layer567 import diameter
from pypacker.structcbs import unpack_H, unpack_I

logger = logging.getLogger("pypacker")


# Chunk Types
DATA			= 0
INIT			= 1
INIT_ACK		= 2
SACK			= 3
HEARTBEAT		= 4
HEARTBEAT_ACK		= 5
ABORT			= 6
SHUTDOWN		= 7
SHUTDOWN_ACK		= 8
ERROR			= 9
COOKIE_ECHO		= 10
COOKIE_ACK		= 11
ECNE			= 12
CWR			= 13
SHUTDOWN_COMPLETE	= 14


class Chunk(pypacker.Packet):
	__hdr__ = (
		("type", "B", INIT),
		("flags", "B", 0),
		("len", "H", 0)		# length of header up to end (including data)
	)
	# May have padding
"""
Data Chunk:
type		B
flags		B
len		H
tseq		I
streamid	H
sseq		H
ppid		I
"""


class SCTP(pypacker.Packet):
	__hdr__ = (
		("sport", "H", 0),
		("dport", "H", 0),
		("vtag", "I", 0),
		("sum", "I", 0, FIELD_FLAG_AUTOUPDATE),
		("chunks", None, triggerlist.TriggerList)
	)

	padding = pypacker.get_ondemand_property("padding", lambda: b"")

	__handler__ = {
		123: diameter.Diameter,
	}

	@staticmethod
	def _dissect_chunks(collect_chunks=True):
		collect = [collect_chunks]

		def _dissect_chunks_sub(buf):
			off = 0
			buflen = len(buf)
			padding = b""
			chunks = []
			CHUNKHEADER_DATA_OFF_PPID = 12
			CHUNKHEADER_DATA_LEN = CHUNKHEADER_DATA_OFF_PPID + 4

			while off + 4 < buflen:
				chunktype = buf[off]
				dlen = unpack_H(buf[off + 2: off + 4])[0]
				#logger.debug("Chunk: chunktype=%r, dlen=%r" % (chunktype, dlen))

				if chunktype != 0:
					chunk = Chunk(buf[off: off + dlen])
					chunks.append(chunk)
					off += dlen
				else:
					#logger.debug("Got DATA chunk")
					# Check for padding (this should be a data chunk)
					if not collect_chunks:
						if off + dlen < buflen:
							padding = buf[off + dlen:].tobytes()
					else:
						# Remove data from chunk: use those for handler
						chunk = Chunk(buf[off: off + CHUNKHEADER_DATA_LEN])
						chunks.append(chunk)

					off += CHUNKHEADER_DATA_LEN
					# Assume DATA is the last chunk
					break

				off += dlen

			#logger.debug("Returning chunks (%r)/off,padding: %r/%r,%r" % (collect[0], chunks, off, padding))
			return chunks if collect[0] else (off, padding)

		return _dissect_chunks_sub

	def _dissect(self, buf):
		off_chunks = 12
		chunks_len, padding = SCTP._dissect_chunks(collect_chunks=False)(buf[off_chunks:])
		self._padding = padding
		self.chunks(buf[off_chunks: off_chunks + chunks_len], SCTP._dissect_chunks())
		#logger.debug("sctp base header len=%r, Chunk len=%r, padding len=%r" % (off_chunks, chunks_len, len(padding)))
		hlen = off_chunks + chunks_len
		htype = None

		try:
			# Source or destination port should match
			ports = [unpack_H(buf[0:2])[0], unpack_H(buf[2:4])[0]]
			htype = [x for x in ports if x in self._id_handlerclass_dct[tcp.TCP]][0]
		except:
			#except Exception as ex:
			# No type found
			#logger.warning("Invalid htypt? %r, %r" % (htype, ex))
			pass

		#logger.debug("Full buffer: %s" % buf.tobytes())
		#logger.debug("Padding: %s" % self.padding)
		#logger.debug("Header bytes: %s" % buf[:hlen].tobytes())
		#logger.debug("Body bytes: %r" % buf[hlen: -len(padding)].tobytes())
		return hlen, htype, buf[hlen:] if len(padding) == 0 else buf[hlen: -len(padding)]

	def bin(self, update_auto_fields=True):
		# Padding needs to be placed at the end
		return pypacker.Packet.bin(self, update_auto_fields=update_auto_fields) + self.padding

	def __len__(self):
		return super().__len__() + len(self.padding)

	def _update_fields(self):
		if self.sum_au_active and self._changed():
			# logger.debug("updating checksum")
			self._calc_sum()

	def _calc_sum(self):
		# mark as changed
		self.sum = 0
		s = checksum.crc32_add(0xFFFFFFFF, self._pack_header())
		padlen = len(self.padding)

		if padlen == 0:
			s = checksum.crc32_add(s, self.body_bytes)
		else:
			#logger.debug("checksum with padding")
			s = checksum.crc32_add(s, self.body_bytes[:-padlen])

		self.sum = checksum.crc32_done(s)

	def direction(self, other):
		#logger.debug("checking direction: %s<->%s" % (self, other))
		if self.sport == other.sport and self.dport == other.dport:
			# consider packet to itself: can be DIR_REV
			return pypacker.Packet.DIR_SAME | pypacker.Packet.DIR_REV
		if self.sport == other.dport and self.dport == other.sport:
			return pypacker.Packet.DIR_REV
		return pypacker.Packet.DIR_UNKNOWN

	def reverse_address(self):
		self.sport, self.dport = self.dport, self.sport
