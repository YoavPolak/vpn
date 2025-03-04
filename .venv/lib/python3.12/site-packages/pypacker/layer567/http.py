# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""
Hypertext Transfer Protocol.
"""
import re
import logging

from pypacker import pypacker, triggerlist

logger = logging.getLogger("pypacker")


class HTTPHeader(triggerlist.TriggerList):
	def _pack(self, tuple_entry):
		# logger.debug("packing HTTP-header")
		# no header = no CRNL
		if len(self) == 0:
			# logger.debug("empty buf 2")
			return b""
		#return b"\r\n".join([b": ".join(keyval) for keyval in self]) + b"\r\n\r\n"
		#logger.debug("adding: %r" % (tuple_entry[0] +b": "+ tuple_entry[1] + b"\r\n"))
		# Note: does not preserve deviating separators, eg "x  :   yz"
		return tuple_entry[0] + b": " + tuple_entry[1] + b"\r\n"

# [Method] [Path] HTTP...\r\n
# key: value\r\n
# \r\n
# [body]
PROG_STARTLINE			= re.compile(rb"[\w\./]{3,10} +[\w\./]{1,400} +[\w\./]{1,20}.+")
PROG_STARTLINE_MATCH		= PROG_STARTLINE.match
PROG_SPLIT_HEADBODY		= re.compile(b"\r\n\r\n")
PROG_SPLIT_HEADBODY_SPLIT	= PROG_SPLIT_HEADBODY.split
PROG_SPLIT_HEADER		= re.compile(b"\r\n")
PROG_SPLIT_HEADER_SPLIT		= PROG_SPLIT_HEADER.split
PROG_SPLIT_KEYVAL		= re.compile(b": ")
PROG_SPLIT_KEYVAL_SPLIT		= PROG_SPLIT_KEYVAL.split

PROG_CHUNKSTART_HEADER_d_CRNL	= re.compile(rb"^(\w+)\r\n")

HTTP_PROTO_IPP_REQ	= b"ipp_req"  # Via HTTP request
HTTP_PROTO_IPP_RESP	= b"ipp_resp"  # Via HTTP response


class HTTP(pypacker.Packet):
	__hdr__ = (
		# content: b"startline"
		("startline", None, None),  # Including trailing \r\n
		# content: [("name", "value"), ...]
		("hdr", None, HTTPHeader),  # Including trailing \r\n
		("sep", "2s", b"\r\n")
	)

	"""
	TODO: higher layer are more prone to segmentation -> skip higher layer dissecting? Manual dissecting needed?
	__handler__ = {
		HTTP_PROTO_IPP_REQ: ipp.IPPRequest,
		HTTP_PROTO_IPP_RESP: ipp.IPPResponse
	}
	"""

	def _dissect(self, buf):
		# Requestline: [method] [uri] [version] eg GET / HTTP/1.1
		# Responseline: [version] [status] [reason] eg HTTP/1.1 200 OK
		#logger.debug("Full HTTP: %s", buf)
		# Request/responseline is mendatory to parse header
		if len(buf) == 0 or not PROG_STARTLINE_MATCH(buf):
			self.sep = None
			return 0

		try:
			bts_header, bts_body = PROG_SPLIT_HEADBODY_SPLIT(buf, maxsplit=1)
			#logger.debug("Header: %s\nBody: %s", bts_header, bts_body)
		except ValueError:
			#logger.debug("no startline/header present")
			# Deactivate separator
			self.sep = None
			# Assume this is part of a bigger (splittet) HTTP-message: no header/only body
			return 0

		try:
			startline, bts_header = PROG_SPLIT_HEADER_SPLIT(bts_header, maxsplit=1)
		except ValueError:
			# logger.debug("just startline: %r, hdr length=%d" % (bts_header, len(bts_header) + 4))
			# bts_header was something like "HTTP/1.1 123 status" (\r\n\r\n previously removed)
			self.startline = bts_header + b"\r\n"
			return len(bts_header) + 4  # startline + 2 (CR NL) + 0 (header) + 2 (sep: CR NL) + 0 (body)

		self.startline = startline + b"\r\n"
		# bts_header = hdr1\r\nhdr2 -> hdr1\r\nhdr2\r\n
		self.hdr(memoryview(bts_header + b"\r\n"), self._parse_header)
		# Type extraction, TODO: this is not *that* clean
		# WARNING: requests / responses may not contain "Content-Type"
		"""
		body_id = None
		if b"Content-Type: application/ipp" in bts_body:
			body_id = HTTP_PROTO_IPP_REQ if b"POST" startline else HTTP_PROTO_IPP_RESP
		"""
		# HEADER + "\r\n" + BODY -> newline is part of the header
		return len(buf) - len(bts_body)

	@staticmethod
	def _parse_header(buf):
		#logger.debug("Parsing header: %s", buf)
		header = []
		lines = PROG_SPLIT_HEADER_SPLIT(buf)

		for line in lines:
			#logger.debug("Checking line: %s", line)
			if len(line) == 0:
				break
			try:
				key, val = PROG_SPLIT_KEYVAL_SPLIT(line, 1)
				header.append((key, val))
			except:
				# Not a "key: value" line
				logger.warning("Invalid HTTP line: %s", line)
				header.append(line)

		return header

	def update_content_length(self, newlen=None):
		"""
		newlen -- Use this content length for update if not None, otherwise len(body_bytes)
		return -- New content length
		"""
		HDRNAME_CONTENT_LENGTH = b"Content-Length"
		idx__hdr = self.hdr[lambda h: h[0] == HDRNAME_CONTENT_LENGTH]

		if newlen is None:
			newlen = len(self.body_bytes)

		clenheader_updated = (HDRNAME_CONTENT_LENGTH, ("%d" % newlen).encode())
		#logger.debug("New content length header will be: %r" % str(clenheader_updated))

		if len(idx__hdr) != 0:
			self.hdr[idx__hdr[0][0]] = clenheader_updated
		else:
			self.hdr.append(clenheader_updated)

		return newlen

	def get_unchunked(self):
		"""
		Chunked example:
		4\r\n        (bytes to send)
		Wiki\r\n     (data)
		6\r\n        (bytes to send)
		pedia \r\n   (data)
		E\r\n        (bytes to send)
		in \r\n
		\r\n
		chunks.\r\n  (data)
		0\r\n        (final byte - 0)
		\r\n         (end message
		"""
		body_bts = memoryview(self.body_bytes)
		chunk_start = PROG_CHUNKSTART_HEADER_d_CRNL.search(body_bts)
		off = 0
		bts_unchunked = []

		while chunk_start:
			len_hex_str = chunk_start.group()
			len_of_hex_str = len(len_hex_str)
			chunk_len = int(len_hex_str.strip(), 16)

			if chunk_len == 0:
				#logger.debug("Final chunk reached")
				break

			off_end_chunk = off + len_of_hex_str + chunk_len
			#logger.debug(f"len_hex_str={len_hex_str}, len_of_hex_str={len_of_hex_str}, chunk_len={chunk_len}")

			bts_unchunked.append(body_bts[off + len_of_hex_str: off_end_chunk])
			off = off_end_chunk + 2
			#logger.debug(f"Next chunk? {body_bts[ off: off + 10].tobytes()}")
			chunk_start = PROG_CHUNKSTART_HEADER_d_CRNL.search(body_bts[off:])

		return b"".join(bts_unchunked)

	# TODO: implement setter
	# Note: may need reassemblation before unchunking
	chunked = property(get_unchunked)
