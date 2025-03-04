# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
import logging
import math

from pypacker.structcbs import pack_B

math_ceil = math.ceil
math_log = math.log


logger = logging.getLogger("pypacker")
from_bytes = int.from_bytes

"""
Basic format:
Type | Length | Content
> Type
class | P/C | Tag num | More | Tag num

https://en.wikipedia.org/wiki/X.690#DER_encoding
"""


def encode_length_definitive(num):
	if num < 0x80:
		return pack_B(num)
	else:
		len_len_inbytes = math_ceil(math_log(num + 1, 256))

		if len_len_inbytes > 0x7F:
			logger.warning("Number too big for encoding")

		len_bytesencoded = num.to_bytes(len_len_inbytes, "big")
		return pack_B(0x80 + len_len_inbytes) + len_bytesencoded


def decode_length_definitive(bts):
	"""
	bts -- [len_shortlong:1->127] where bits of len_shortlong = ABBB BBBB [CCCCCCCC].
		Should be 127 bytes (exact length unknown before calling)
	return -- lengts of length, length
	"""
	vlen = bts[0]
	# Defnite form: short or long
	is_lenshort = (vlen & 0x80) == 0
	# Length of length-bytes
	len_len = 1

	if not is_lenshort:
		# The long form consist of 1 initial octet followed by 1 or more subsequent octets,
		# containing the length. In the initial octet, bit 8 is 1, and bits 1-7 (excluding
		# the values 0 and 127) encode the number of octets that follow.
		#logger.debug("Got long format!")
		len_octets = vlen & 0x7F
		lenbts = bts[1: 1 + len_octets]
		#logger.debug("len in bytes: %s" % lenbts)
		vlen = from_bytes(lenbts, byteorder="big", signed=False)
		#logger.debug("length longform, bytes: %r (%d) = %d" % (lenbts, len_octets, vlen))
		len_len += len_octets
	return len_len, vlen


def _get_der_tlv(der_bts):
	"""
	return -- idlen, lenlen, vlen, is_primitive
	"""
	off = 0
	tagstart = off
	is_primitive = (der_bts[off] & 0x20) == 0
	# High tag number form
	# If the tag number is too large for the 5-bit tag field, it has to be encoded in further octets.
	if (der_bts[off] & 0x1F) == 0x1F:
		#logger.warning("Got high tag form")
		# is_hightag = True
		off += 1

		while (der_bts[off] & 0x80) != 0:
			off += 1
	off += 1
	lenstart = off
	lenlen, vlen = decode_length_definitive(der_bts[lenstart: lenstart + 127])
	off += lenlen
	valuestart = off

	return lenstart - tagstart, valuestart - lenstart, vlen, is_primitive


class LinkedTLVList(list):
	def __init__(self, val):
		self._parent_list = None
		super().__init__(val)

	def set_parent(self, parent_list):
		self._parent_list = parent_list

	def get_parent(self):
		return self._parent_list

	def append(self, tlv_list):
		tlv_list.set_parent(self)
		super().append(tlv_list)

	def is_primitive(self):
		# tlv -> (a, b, c), on non-primitive types c will be come a list
		return len(self) == 3 and type(self[2]) is bytes

	def get_value_raw(self):
		if len(self) == 3:
			if self.is_primitive():
				return self[2]
			else:
				return b"".join(v.bin() for v in self[2])
		elif len(self) == 1:
			# Assume list in list
			return self[0].bin()
		else:
			raise Exception("%s" % self)

	def bin(self):
		if len(self) == 3:
			if self.is_primitive():
				return self[0] + self[1] + self[2]
			else:
				type_len = self[0] + self[1]
				value = b"".join(v.bin() for v in self[2])
				return type_len + value
		elif len(self) == 1:
			# Assume list in list
			return self[0].bin()
		else:
			raise Exception("%s" % self)

	def update_len_uptoroot(self):
		self[1] = encode_length_definitive(self.get_value_bin())
		self.get_parent().update_len_uptoroot()

	def __setitem__(self, idx, val):
		if not is_primitive():
			raise Exception("Can't change non-primitive values!")

		# Update lengths if primitive value changed
		update_needed = self.is_primitive() and idx == 2 and len(val) != len(self[2])
		super().__setitem__(idx, val)

		if update_needed:
			#logger.debug("Update of length needed")
			self.update_len_uptoroot()

	"""
	def __getitem__(self, idx):
		val_ret = super().__getitem__(idx)

		return LinkedTLVList(val_ret) if type(val_ret) == list else val_ret
	"""


def decode_der(der_bts, rw_cb=None):
	off = 0
	end = len(der_bts)
	result = LinkedTLVList([])

	while off < end:
		taglen, lenlen, vlen, prim = _get_der_tlv(der_bts[off:])
		der_sub = der_bts[off + taglen + lenlen: off + taglen + lenlen + vlen]

		if not prim:
			der_sub = decode_der(der_sub, rw_cb=rw_cb)

		# Results: [tag_bts, lenlen_bts, value_bts]
		ltlv = LinkedTLVList([
			der_bts[off: off + taglen],
			der_bts[off + taglen: off + taglen + lenlen],
			der_sub]
		)
		#print(ltlv)
		result.append(ltlv)
		off += (taglen + lenlen + vlen)

	rw_cb(result)

	return result

"""
>>> X.509

Certificate  ::=  SEQUENCE  {
	tbsCertificate       TBSCertificate,
	signatureAlgorithm   AlgorithmIdentifier,
	signatureValue       BIT STRING  }
3082 06eb - SEQUENCE with length 0x06eb

TBSCertificate  ::=  SEQUENCE  {
	version         [0]  EXPLICIT Version DEFAULT v1,
	serialNumber         CertificateSerialNumber,
	signature            AlgorithmIdentifier,
	issuer               Name,
	validity             Validity,
	subject              Name,
	subjectPublicKeyInfo SubjectPublicKeyInfo,
	issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
	-- If present, version MUST be v2 or v3
	subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
	-- If present, version MUST be v2 or v3
	extensions      [3]  EXPLICIT Extensions OPTIONAL
	-- If present, version MUST be v3
}
"""

X509_ID_COMMONNAME		= b"U\x04\x03"
X509_ID_COUNTRYNAME		= b"U\x04\x06"
X509_ID_LOCALITYNAME		= b"U\x04\x07"
X509_ID_STATEORPROVINCENAME	= b"U\x04\x08"
X509_ID_ORGANIZATIONNAME	= b"U\x04\n"
X509_ID_ORGANIZATIONUNITNAME	= b"U\x04\x0b"

"""
http://www.oid-info.com/

2.5.4.0 - id-at-objectClass
2.5.4.1 - id-at-aliasedEntryName
2.5.4.2 - id-at-knowldgeinformation
2.5.4.3 - id-at-commonName
2.5.4.4 - id-at-surname
2.5.4.5 - id-at-serialNumber
2.5.4.6 - id-at-countryName
2.5.4.7 - id-at-localityName
2.5.4.8 - id-at-stateOrProvinceName
2.5.4.9 - id-at-streetAddress
2.5.4.10 - id-at-organizationName
2.5.4.11 - id-at-organizationalUnitName
2.5.4.12 - id-at-title
2.5.4.13 - id-at-description
2.5.4.14 - id-at-searchGuide
2.5.4.15 - id-at-businessCategory
2.5.4.16 - id-at-postalAddress
2.5.4.17 - id-at-postalCode
2.5.4.18 - id-at-postOfficeBox
2.5.4.19 - id-at-physicalDeliveryOfficeName
2.5.4.20 - id-at-telephoneNumber
2.5.4.21 - id-at-telexNumber
2.5.4.22 - id-at-teletexTerminalIdentifier
2.5.4.23 - id-at-facsimileTelephoneNumber
2.5.4.24 - id-at-x121Address
2.5.4.25 - id-at-internationalISDNNumber
2.5.4.26 - id-at-registeredAddress
2.5.4.27 - id-at-destinationIndicator
2.5.4.28 - id-at-preferredDeliveryMethod
2.5.4.29 - id-at-presentationAddress
2.5.4.30 - id-at-supportedApplicationContext
2.5.4.31 - id-at-member
2.5.4.32 - id-at-owner
2.5.4.33 - id-at-roleOccupant
2.5.4.34 - id-at-seeAlso
2.5.4.35 - id-at-userPassword
2.5.4.36 - id-at-userCertificate
2.5.4.37 - id-at-cACertificate
2.5.4.38 - id-at-authorityRevocationList
2.5.4.39 - id-at-certificateRevocationList
2.5.4.40 - id-at-crossCertificatePair
2.5.4.41 - id-at-name
2.5.4.42 - id-at-givenName
2.5.4.43 - id-at-initials
2.5.4.44 - id-at-generationQualifier
2.5.4.45 - id-at-uniqueIdentifier
2.5.4.46 - id-at-dnQualifier
2.5.4.47 - id-at-enhancedSearchGuide
2.5.4.48 - id-at-protocolInformation
2.5.4.49 - id-at-distinguishedName
2.5.4.50 - id-at-uniqueMember
2.5.4.51 - id-at-houseIdentifier
2.5.4.52 - id-at-supportedAlgorithms
2.5.4.53 - id-at-deltaRevocationList
2.5.4.58 - Attribute Certificate attribute (id-at-attributeCertificate)
2.5.4.65 - id-at-pseudonym


2.5.29.1 - old Authority Key Identifier
2.5.29.2 - old Primary Key Attributes
2.5.29.3 - Certificate Policies
2.5.29.4 - Primary Key Usage Restriction
2.5.29.9 - Subject Directory Attributes
2.5.29.14 - Subject Key Identifier
2.5.29.15 - Key Usage
2.5.29.16 - Private Key Usage Period
2.5.29.17 - Subject Alternative Name
2.5.29.18 - Issuer Alternative Name
2.5.29.19 - Basic Constraints
2.5.29.20 - CRL Number
2.5.29.21 - Reason code
2.5.29.23 - Hold Instruction Code
2.5.29.24 - Invalidity Date
2.5.29.27 - Delta CRL indicator
2.5.29.28 - Issuing Distribution Point
2.5.29.29 - Certificate Issuer
2.5.29.30 - Name Constraints
2.5.29.31 - CRL Distribution Points
2.5.29.32 - Certificate Policies
2.5.29.33 - Policy Mappings
2.5.29.35 - Authority Key Identifier
2.5.29.36 - Policy Constraints
2.5.29.37 - Extended key usage
2.5.29.46 - FreshestCRL
2.5.29.54 - X.509 version 3 certificate extension Inhibit Any-policy
"""
