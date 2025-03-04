# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""
Internet Printing Protocol (IPP)
https://www.rfc-editor.org/rfc/rfc2911
https://datatracker.ietf.org/doc/html/rfc2566
https://datatracker.ietf.org/doc/html/rfc2565

WARNING: may need HTTP reassemblation  before dissection
"""

import logging

from pypacker import pypacker, triggerlist
from pypacker.pypacker import FIELD_FLAG_AUTOUPDATE
from pypacker.structcbs import unpack_H


logger = logging.getLogger("pypacker")


"""
>>> Printer attributes
>> operations-supported

0x0000              reserved, not used
0x0001              reserved, not used
0x0002              Print-Job
0x0003              Print-URI
0x0004              Validate-Job
0x0005              Create-Job
0x0006              Send-Document
0x0007              Send-URI
0x0008              Cancel-Job
0x0009              Get-Job-Attributes
0x000A              Get-Jobs
0x000B              Get-Printer-Attributes
0x000C              Hold-Job
0x000D              Release-Job
0x000E              Restart-Job
0x000F              reserved for a future operation
0x0010              Pause-Printer
0x0011              Resume-Printer
0x0012              Purge-Jobs
0x0013-0x3FFF       reserved for future IETF standards track operations (see section 6.4)
0x4000-0x8FFF       reserved for vendor extensions (see section 6.4)


>>> Delimiter Tags
The following table specifies the values for the delimiter tags:

Tag Value (Hex)   Delimiter

0x00              reserved
0x01              operation-attributes-tag
0x02              job-attributes-tag
0x03              end-of-attributes-tag
0x04              printer-attributes-tag
0x05              unsupported-attributes-tag
0x06-0x0E         reserved for future delimiters
0x0F              reserved for future chunking-end-of-attributes-tag


>> the order of these
xxx-attributes-tags and xxx-attribute-sequences in the protocol MUST
be the same as in the model document, but the order of attributes
within each xxx-attribute-sequence MUST be unspecified


Model Document Group           xxx-attributes-sequence
---
Operation Attributes           operations-attributes-sequence
Job Template Attributes        job-attributes-sequence
Job Object Attributes          job-attributes-sequence
Unsupported Attributes         unsupported-attributes-sequence
Requested Attributes           job-attributes-sequence
Get-Job-Attributes)
Requested Attributes           printer-attributes-sequence
Get-Printer-Attributes)
Document Content               in a special position as described above


>>> Value Tags
The following table specifies the integer values for the value-tag:

Tag Value (Hex)  Meaning

0x20             reserved
0x21             integer
0x22             boolean
0x23             enum
0x24-0x2F        reserved for future integer types

0x30             octetString with an  unspecified format
0x31             dateTime
0x32             resolution
0x33             rangeOfInteger
0x34             reserved for collection (in the future)
0x35             textWithLanguage
0x36             nameWithLanguage
0x37-0x3F        reserved for future octetString types

0x40             reserved
0x41             textWithoutLanguage
0x42             nameWithoutLanguage
0x43             reserved
0x44             keyword
0x45             uri
0x46             uriScheme
0x47             charset
0x48             naturalLanguage

0x49             mimeMediaType
0x4A-0x5F        reserved for future character string types
"""

OPERATION_PRINTJOB			= 0x0002
OPERATION_PRINTURI			= 0x0003
OPERATION_VALIDATE_JOB			= 0x0004
OPERATION_CREATE_JOB			= 0x0005
OPERATION_GET_JOBS			= 0x000A
OPERATION_GET_PRINTER_ATTRIBUTES	= 0x000B

TAG_DEL_RESERVED		= 0x00
TAG_DEL_OP_ATTR_TAG		= 0x01
TAG_DEL_JOBATTR_TAG		= 0x02
TAG_DEL_END_OF_ATTR		= 0x03
TAG_DEL_PRINTER_ATTR_TAG	= 0x04
TAG_DEL_UNSUPPORTED_ATTR_TAG	= 0x05
#0x06-0x0E         reserved for future delimiters
#0x0F              reserved for future chunking-end-of-attributes-tag

TAGS_DELIMITER = set([TAG_DEL_RESERVED, TAG_DEL_OP_ATTR_TAG, TAG_DEL_JOBATTR_TAG, TAG_DEL_END_OF_ATTR,
	TAG_DEL_PRINTER_ATTR_TAG, TAG_DEL_UNSUPPORTED_ATTR_TAG])

TAG_TYPE_BOOL			= 0x22
TAG_TYPE_KEYWORD		= 0x44
TAG_TYPE_URI			= 0x45
TAG_TYPE_CHARSET		= 0x47
TAG_TYPE_NAT_LANG		= 0x48
TAG_TYPE_TEXT_LANG		= 0x35
TAG_TYPE_NAME_LANG		= 0x36
TAG_TYPE_TEXT_NO_LANG		= 0x41
TAG_TYPE_NAME_NO_LANG		= 0x42
TAG_TYPE_MEDIA_MIME		= 0x49

"""
HTTP example:
POST / HTTP/1.1
Content-Length: 161
Content-Type: application/ipp
Date: Wed, 1 Jan 2000 21:50:58 GMT
Host: 1.2.3.4.1:631
User-Agent: CUPS/1.2.3 (Linux; x86_64) IPP/2.0
Expect: 100-continue

...
"""


class TypeNameContent(pypacker.Packet):
	__hdr__ = (
		("type", "B", 0),
		("name_len", "H", 0, FIELD_FLAG_AUTOUPDATE),
		("name", None, b""),
		("content_len", "H", 0, FIELD_FLAG_AUTOUPDATE)
	)

	def _dissect(self, buf):
		name_len = unpack_H(buf[1: 3])[0]
		self.name = buf[3: 3 + name_len]
		return 5 + name_len

	def _update_fields(self):
		if self._changed():
			if self.name_len_au_active:
				self.name_len = len(self.name)
			if self.content_len_au_active:
				self.content_len = len(self.body_bytes)


class Attribute(pypacker.Packet):
	__hdr__ = (
		("parameter", None, triggerlist.TriggerList),
	)

	def get_name(self):
		# Avoid exception below
		if len(self.parameter) == 0 or type(self.parameter[0]) != TypeNameContent:
			return None

		# Assume TypeNameContent is used
		try:
			return self.parameter[0].body_bytes
		except:
			return None

"""
Attribute example Structure:

//[operation-attributes-tag:1]
[value-tag:2]
	name: [len:1][content:len]
	value: [len:1][content:len]
[value-tag:2]
	name: [len:1][content:len]
	value: [len:1][content:len]
	// Member of same parent value-tag as long name-len is 0
	value:
		[value-tag:2]
		[name-len:1=0][name:name-len]
		[len:1][content:len]
//[end-of-attributes-tag:1]
"""


def dissect_attributes(only_offsets=False):
	def dissect_attributes_sub(buf):
		"""
		buf -- start direct after operation-attributes-tag
		"""
		#logger.debug("dissect_attributes_sub")
		attributes = []
		tncs = []
		off = 0
		value_tag = buf[off]
		value_tag_new = None

		while off < len(buf):
			# type:1, len:2, value:len
			name_len = unpack_H(buf[off + 1: off + 1 + 2])[0]
			content_len = unpack_H(buf[off + 1 + 2 + name_len: off + 1 + 2 + name_len + 2])[0]
			off_new = off + 1 + 2 + name_len + 2 + content_len
			#logger.debug(f"value_tag={value_tag:#x}, off={off}, name_len={name_len},
			#	 content_len={content_len}, off_new={off_new}")

			value_tag_new = None

			if off_new < len(buf):
				value_tag_new = buf[off_new]
				#logger.debug(f"value_tag_new={value_tag_new:X}")

			if not only_offsets:
				tnc = TypeNameContent(buf[off: off_new])
				tncs.append(tnc)

				if value_tag_new != value_tag:
					# End of Attribute reached, add all tncs
					attribute = Attribute()
					attribute.parameter.extend(tncs)
					attributes.append(attribute)
					tncs = []

			off = off_new

			if value_tag_new is None or value_tag_new in TAGS_DELIMITER:
				break

			value_tag = value_tag_new

		return off if only_offsets else attributes

	return dissect_attributes_sub


class IPPRequest(pypacker.Packet):
	__hdr__ = (
		("version", "H", 0x0200),
		# The operation-attributes-tag MUST be the first tag delimiter, ...
		("operation", "H", OPERATION_GET_PRINTER_ATTRIBUTES),
		("req_id", "I", 1),

		("op_attr_tag", "B", TAG_DEL_OP_ATTR_TAG),
		("op_attr", None, triggerlist.TriggerList),

		# If the client is not supplying any Job Template attributes in the request,
		# the client SHOULD omit Group 2 rather than sending an empty group.
		("template_attr_tag", "B", None),
		("template_attr", None, triggerlist.TriggerList),

		# ... and the end-of-attributes-tag MUST be the last tag delimiter.
		("end_of_attribute_tag", "B", TAG_DEL_END_OF_ATTR),
		# If the operation has a document-content group,
		# the document data in that group MUST follow the end-of-attributes- tag.
		# -> Set document as body bytes
	)

	def _dissect(self, buf):
		#op_attr_len = dissect_attributes(only_offsets=True)(buf[9:])
		self.op_attr(buf[9: -1], dissect_attributes())

		return len(buf)


RESPONSE_STATUS_OK	= 0


class IPPResponse(pypacker.Packet):
	__hdr__ = (
		("version", "H", 0x0200),
		("status", "H", RESPONSE_STATUS_OK),
		("req_id", "I", 1),
		("op_attr_tag", "B", TAG_DEL_OP_ATTR_TAG),
		("op_attr", None, triggerlist.TriggerList),
		("printer_attr_tag", "B", TAG_DEL_PRINTER_ATTR_TAG),
		("printer_attr", None, triggerlist.TriggerList),
		("end_of_attribute_tag", "B", TAG_DEL_END_OF_ATTR),
	)

	def _dissect(self, buf):
		off = 9
		op_attr_len = dissect_attributes(only_offsets=True)(buf[off:])
		#logger.debug(f"Response start 1: {buf[9: 20].tobytes()}, op_attr_len={op_attr_len}")
		self.op_attr(buf[off: off + op_attr_len], dissect_attributes())
		off += op_attr_len + 1
		#logger.debug(f"op_attr_len={op_attr_len}")
		printer_attr_len = dissect_attributes(only_offsets=True)(buf[off:])
		#logger.debug(f"Response start 2: {buf[9 + op_attr_len: 9 + op_attr_len + 20].tobytes()}")
		self.printer_attr(buf[off: off + printer_attr_len], dissect_attributes())

		return len(buf)
