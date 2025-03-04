# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""
Simple packet creation and parsing logic.
"""
import logging
import random
import re
from struct import Struct
import inspect
from ipaddress import IPv6Address, v6_int_to_packed

# imported to make usable via import "pypacker.[FIELD_FLAG_AUTOUPDATE | FIELD_FLAG_IS_TYPEFIELD]"
from pypacker.pypacker_meta import MetaPacket, FIELD_FLAG_AUTOUPDATE, FIELD_FLAG_IS_TYPEFIELD
from pypacker.structcbs import pack_mac, unpack_mac, pack_ipv4, unpack_ipv4, unpack_Q, pack_Q
from pypacker.lazydict import LazyDict

logger = logging.getLogger("pypacker")
# logger.setLevel(logging.DEBUG)
logger.setLevel(logging.WARNING)


class NiceFormatter(logging.Formatter):
	FORMATS = {
		logging.DEBUG: "%(module)s -> %(funcName)s -> %(lineno)d: %(message)s",
		logging.INFO: "%(message)s",
		logging.WARNING: "WARNING: %(module)s: %(lineno)d: %(message)s",
		logging.ERROR: "ERROR: %(module)s: %(lineno)d: %(message)s",
		"DEFAULT": "%(message)s"}

	def __init__(self):
		super().__init__(fmt="%(levelno)d: %(msg)s", datefmt=None, style="%")

	def format(self, record):
		format_orig = self._style._fmt

		#print(f"Logging via: {record.levelno}, {logging.DEBUG} {logging.INFO} {logging.WARNING}")
		self._style._fmt = self.FORMATS.get(record.levelno, self.FORMATS["DEFAULT"])
		result = logging.Formatter.format(self, record)

		self._style._fmt = format_orig

		return result

logger_streamhandler = logging.StreamHandler()
logger_formatter = NiceFormatter()
logger_streamhandler.setFormatter(logger_formatter)

logger.addHandler(logger_streamhandler)

PROG_NONVISIBLE_CHARS	= re.compile(b"[^\x21-\x7e]")
HEADER_TYPES_SIMPLE	= {int, bytes}

DIR_SAME		= 1
DIR_REV			= 2
DIR_UNKNOWN		= 4
DIR_NOT_IMPLEMENTED	= 255

ERROR_NONE		= 0
ERROR_DISSECT		= 1  # This layer had an error when parsing/creating an upper layer

VARFILTER_TYPES = {bytes, int}

LAMBDA_TRUE = lambda pkt: True


class NotEnoughBytesException(Exception):
	pass


class DissectException(Exception):
	pass


class Packet(object, metaclass=MetaPacket):
	"""
	Base packet class, with metaclass magic to generate members from self.__hdr__ field.
	This class can be instatiated via:

		Packet(byte_string)
		Packet(key1=val1, key2=val2, ...)

	Every packet got a header and a body. Body-data can be raw byte string OR a packet itself
	(the body handler) which itself stores a packet etc. This continues until a packet only
	contains raw bytes (highest layer). The following schema illustrates the Packet-structure:

	Packet structure
	================

	[Packet:
	headerfield_1
	headerfield_2
	...
	headerfield_N
	[Body -> Packet:
		headerfield_1
		...
		headerfield_N
		[Body: -> Packet:
			headerfields
			...
			[Body: -> b"some_bytes"]
	]]]

	A header definition like __hdr__ = (("name", "12s", b"defaultvalue"),) will define a header field
	having the name "name", format "12s" and default value b"defaultvalue" as bytestring. Fields will
	be added and concatinated in order of definition.

	Body can have these states:
	- Lazy handler not yet dissected (body bytes are internally stored as raw bytes)
		-> Higher layer gets dissected
		-> Higher layer is packet OR raw bytes (if not dissectable)
	- Body is raw bytes


	Minimum features
	================

	- Auto-decoding of headers via given format-patterns (defined via __hdr__)
	- Auto-decoding of body-handlers (IP -> parse IP-data -> add TCP-handler to IP -> parse TCP-data..)
	- Access of higher layers via layer1.higher_layer or "layer1[layerX]" notation
	- There are three types of headers:
	1) Simple constant fields (constant format)
		Format for __hdr__: ("name", "format", value [, FLAGS])

	2) Simple dynamic fields (byte string which changes in length)
		Format for __hdr__: ("name", None, b"bytestring" [, FLAGS])
		Such types MUST get initiated in _dissect() because there is no way in guessing
		the correct format when unpacking values!

	3) TriggerList (List containing Packets, bytes like b"xyz" or tuples like (ID, value))
		Format for __hdr__: ("name", None, TriggerList)
		Such types MUST get initiated in _dissect() because there is no way in guessing
		the correct format when unpacking values!

	The FLAGS value for simple constant and dynamic fields can be used to mark auto-update field
	(see pypacker_meta.py). This will create a variable XXX_au_active one time for a field XXX
	which can be used activate/deactivate the auto-update externally and which can be read in
	the bin()-method internally.
	- Convenient access for standard types (e.g. MAC, IP address) using string-representations
		This is done by appending "_s" to the attributename:
		ip.src_s = "127.0.0.1"
		ip_src_str = ip.src_s

		Implementation info:
		Convenient access should be set via varname_s = pypacker.Packet.get_property_XXX("varname")
		Get/set via is always done using strings (not byte strings).
	- Concatination via "packet = layer1 + layer2 + layerX"
	- Access to next lower/upper layer
	- Header-values with length < 1 Byte should be set by using properties
	- Deactivate/activate non-TriggerList header fields, eg pkt.hdr=None (inactive), pkt.hdr=b"xxx" (active)
	- Checksums (static auto fields in general) are auto-recalculated when calling
		bin(update_auto_fields=True) (default: active)
		The update-behaviour for every single field can be controlled via
		"pkt.VARNAME_au_active = [True|False]
	- Ability to check direction to other Packets via "[is_]direction()"
	- No correction of given raw packet-bytes e.g. checksums when creating a packet from it
		The internal state will only be updated on changes to headers or data later on
	- General rule: less changes to headers/body-data = more performance


	Call-flows
	==========
		pypacker(bytes)
			-> _dissect(): has to be overwritten, get to know/verify the real header-structure
				-> (optional): initiate triggerlists via tlname(bts, cb)
				-> (optional): Set values for dynamic fields via self.xyz = b"test" (see layer567.dns -> Query)
				-> (optional): Activate/deactivate fields
				-> return hlen, id, bts
			-> (optional) on access to simple headers: _unpack() sets all header values of a layer
			-> (optional) on access to TriggerList headers: lazy parsing gets triggered
			-> (optional) on access to body handler: next upper layer gets initiated

		pypacker(keyword1=value, ...)
			-> (optional) set headers

		pypacker()
			-> Only sets standard values for simple headers

	"""

	# Dict for saving "body type ids -> handler classes" globaly:
	# { class_name_current : {id_upper : handler_class_upper} }
	_id_handlerclass_dct = {}
	# Dict for saving "handler class -> body type ids" globaly:
	# { class_name_current : {handler_class_upper : id_upper} }
	_handlerclass_id_dct = {}
	# Constants for Packet-directions
	DIR_SAME		= DIR_SAME
	DIR_REV			= DIR_REV
	DIR_UNKNOWN		= DIR_UNKNOWN
	DIR_NOT_IMPLEMENTED	= DIR_NOT_IMPLEMENTED

	def __init__(self, *args, **kwargs):
		"""
		Packet constructors:

		Packet(bytebuf [, lower_layer_object])
			Note: lower_layer_object only for internal usage
		Packet(keyword1=val1, keyword2=val2, ...)

		bytestring -- Packet bytes to build packet from (use memoryview for best performance
		lower_layer_object -- For internal usage only. Used by _dissect()
			Ideally the current layer is agnostic to the lower layer. But sometimes...
		keywords -- Keyword arguments correspond to header fields to be set
		"""

		if args:
			# args[0]: bytes or memoryview
			mview_all = memoryview(args[0])

			if len(args) == 2:
				# Make lower layer accessible. This won't change the body
				self._lower_layer = args[1]
				# An exception on higher layer will lead to body bytes instead of heandler (see _lazy_init_handler)
				# TODO: Should occur mostly on >layer4 protocols, eg TCP -> splitted packet. Checkout!
				hlen_bodyid_bodybts = self._dissect(mview_all)
			else:
				# This is the lowest layer, handle exception to make it more user friendly
				try:
					hlen_bodyid_bodybts = self._dissect(mview_all)
				except:
					raise DissectException(
						"Could not initiate packet %r, not enough/wrong bytes given?"
						" Got %d bytes: %r, std format needs %d" % (
							self.__class__,
							len(mview_all), mview_all.tobytes(),
							self._header_format_cached.size)
					)

			hlen = hlen_bodyid_bodybts if hlen_bodyid_bodybts.__class__ == int else hlen_bodyid_bodybts[0]
			# Not enough bytes means packet can't be unpacked.
			# Check this here and not in _dissect() as it's always the same for all dissects.
			if len(args[0]) < hlen:
				raise NotEnoughBytesException(
					"Not enough bytes for packet class %s: given=%d < expected=%d" %
					(self.__class__, len(args[0]), hlen))

			self._header_cached = mview_all[:hlen]

			if hlen_bodyid_bodybts.__class__ != int:
				# Assume list
				if len(hlen_bodyid_bodybts) != 3:
					# Assume [hlen, handler_id] (more likely)
					bodybts = mview_all[hlen:]
				else:
					# Assume [hlen, handler_id, bodybts]
					bodybts = hlen_bodyid_bodybts[2]
					#logger.debug("Setting explicit bodybts=len=%r,%r" % (len(bodybts), bodybts.tobytes()))

				# Prepare handler for lazy dissect
				# handler_id may be None and bodybts explicitly given: [hlen, None, bodybts]
				if hlen_bodyid_bodybts[1] is not None:
					try:
						# Likely to succeed
						clz_upper = Packet._id_handlerclass_dct[self.__class__][hlen_bodyid_bodybts[1]]
						#logger.debug("Lazy config of handler:\n%s(%r: %r)\n-> %s(%r: %r)",
						#	self.__class__, len(self._header_cached.tobytes()), self._header_cached.tobytes(),
						#	clz_upper, len(bodybts.tobytes()), bodybts.tobytes())
						self._lazy_handler_data = [clz_upper, bodybts]
						bodybts = None
					except:
						#except Exception as ex:
						#logger.warning("Can't set lazy handler config (invalid handler id?): base=%s, init data: hlen=%r, reason: %r",
						#	self.__class__, hlen_bodyid_bodybts, ex)
						#logger.exception(ex)
						# Set raw bytes as data (eg handler class not found)
						self._lazy_handler_data = None

				# May be None, that's ok
				self._body_bytes = bodybts
			else:
				self._body_bytes = mview_all[hlen:]

			self._reset_changed()
			# Original unpacked value = no changes
			self._unpacked = False
		else:
			if len(kwargs) > 0:
				# Overwrite default parameters
				# Keyword args means: allready unpacked (nothing to unpack)
				# No reset: directly assigned = changed
				self._unpack()

				for k, v in kwargs.items():
					#logger.debug("Setting via keyword arg: %r=%r" % (k, v))
					setattr(self, k, v)
			else:
				self._unpacked = False

	def _dissect(self, buf):
		"""
		Dissect packet bytes. See __init__ -> Call-flows
		buf -- bytestring to be dissected
		return -- header_length [, handler_id]
		"""
		# _dissect(...) was not overwritten: no changes to header, return original header length
		return self._header_format_cached.size

	def __len__(self):
		"""Return total length (= header + all upper layer data) in bytes."""
		if self._lazy_handler_data is not None:
			# Lazy data present: avoid unneeded parsing
			return self.header_len + len(self._lazy_handler_data[1])
		elif self._higher_layer is not None:
			return self.header_len + len(self._higher_layer)
		else:
			# Assume body bytes are set
			return self.header_len + len(self._body_bytes)

	#
	# Public access to header length: keep it uptodate
	#
	def _get_header_len(self):
		# Update format to get the real length
		self._update_cached_header_format_and_tl_states()
		return self._header_format_cached.size

	# Update format if needed and return actual header size
	header_len = property(_get_header_len)

	def _get_dissect_error(self):
		return (self._errors & ERROR_DISSECT) != 0

	dissect_error = property(_get_dissect_error)
	errors = property(lambda obj: obj._errors)

	def is_error_present(self, error):
		"""
		Check if one of pypacker.ERROR_XXX is present
		error -- the error to be check against internal error state
		"""
		return (self._errors & error) != 0

	def _get_bodybytes(self):
		"""
		Return raw data bytes or handler bytes (including all upper layers) if present.
		This is the same as calling bin() but:
		- Excluding this header
		- Without resetting changed-status
		- No triggering of header updates
		"""
		if self._lazy_handler_data is not None:
			# No need to parse: raw bytes for all upper layers
			if type(self._lazy_handler_data[1]) == memoryview:
				self._lazy_handler_data[1] = self._lazy_handler_data[1].tobytes()
			return self._lazy_handler_data[1]
		elif self._higher_layer is not None:
			# Some handler was set
			hndl = self._higher_layer
			return hndl._pack_header() + hndl._get_bodybytes()
		else:
			# Return raw bytes (no handler)
			if type(self._body_bytes) == memoryview:
				self._body_bytes = self._body_bytes.tobytes()

			return self._body_bytes

	def _set_bodybytes(self, value):
		"""
		Set body bytes to value (bytestring). This will reset any handler.

		value -- a bytestring
		"""
		#logger.debug(self.__class__)
		if self._higher_layer is not None:
			# Reset all handler data
			self._set_higherlayer(None)

		self._body_bytes = value
		self._body_value_changed = True
		self._lazy_handler_data = None
		self._notify_changelistener()

	# Get and set bytes for body. Note: this returns bytes even if higher_layer returns None.
	# Setting body_bytes will clear any handler (higher_layer will return None afterwards).
	body_bytes = property(_get_bodybytes, _set_bodybytes)

	def _get_higherlayer(self):
		"""
		Retrieve next upper layer. This is the only direct way to do this.
		return -- handler object or None if not present.
		"""
		#logger.debug(self.__class__)
		if self._lazy_handler_data is not None:
			self._lazy_init_handler()
		return self._higher_layer

	@staticmethod
	def get_id_for_handlerclass(origin_class, handler_class):
		"""
		return -- id associated for the given handler_class used in class origin_class.
			None if nothing was found. Example: origin_class = Ethernet, handler_class = IP,
			id will be ETH_TYPE_IP
		"""
		try:
			# Likely to succeed
			return Packet._handlerclass_id_dct[origin_class][handler_class]
		except:
			pass
		return None

	def _set_higherlayer(self, hndl, notify_changelistener=True):
		"""
		Set body handler for this packet and make it accessible via layername[addedtypeclass]
		like ethernet[ip.IP]. If handler is None any handler will be reset and data will be set to an empty byte string.

		hndl -- The handler to be set: None or a Packet instance. Setting to None
			will clear any handler and set body_bytes to b"".
		notify_changelistener -- Relevant for eg: if this packet is part of a tl -> later changes
		"""
		#logger.debug(self.__class__)
		#logger.debug("Higher layer will be: %r" % hndl.__class__)
		if self._higher_layer is not None:
			# Clear old linked data of upper layer if body handler is already parsed
			# A.B -> A.higher_layer = x -> B.lower_layer = None
			self._higher_layer._lower_layer = None

		if hndl is not None:
			# Set a new body handler
			# Associate ip, arp etc with handler-instance to call "ether.ip", "ip.tcp" etc
			self._body_bytes = None
			hndl._lower_layer = self
		else:
			# Avoid (body_bytes=None, handler=None)
			self._body_bytes = b""

		self._higher_layer = hndl
		self._body_value_changed = True
		self._lazy_handler_data = None

		if notify_changelistener:
			self._notify_changelistener()

	# Deprecated, wording "higher_layer/highest_layer layer is more consistent
	upper_layer = property(_get_higherlayer, _set_higherlayer)
	# Get/set body handler. Note: this will force lazy dissecting when reading
	higher_layer = property(_get_higherlayer, _set_higherlayer)

	def _set_lower_layer(self, hndl):
		if self._lower_layer is not None:
			# Remove upper layer (us) from current lower layer before
			# setting a new lower layer
			self._lower_layer.higher_layer = None

		if hndl is not None:
			hndl.higher_layer = self

	# Get/set body handler
	lower_layer = property(lambda pkt: pkt._lower_layer, _set_lower_layer)

	def _lowest_layer(self):
		current = self

		while current._lower_layer is not None:
			current = current._lower_layer

		return current

	def _get_highest_layer(self):
		current = self

		# unpack all layer, assuming string class will be never found
		while current.higher_layer is not None:
			current = current.higher_layer

		return current

	lowest_layer = property(_lowest_layer)
	highest_layer = property(_get_highest_layer)

	def disconnect_layer(self):
		"""
		Disconnect layer B from ABC and return B. Connects AC with each other.
		This is the same as 'pkt.lower_layer = pkt.higher_layer'
		without returning the middle layer (pkt).

		return -- This layer
		"""
		# Connect lower/upper layer of this layer
		if self.lower_layer is not None and self.higher_layer is not None:
			self.lower_layer.higher_layer = self.higher_layer

		self.lower_layer = None
		self.higher_layer = None

		return self

	def _lazy_init_handler(self):
		"""
		Lazy initialize the handler previously set by _init_handler.
		Make sure this is not called more than once
		"""
		handler_data = self._lazy_handler_data

		# Likely to succeed
		try:
			# Instantiate handler class using lazy data buffer
			handler_obj = handler_data[0](handler_data[1], self)
			# No notify_changelistener:
			# Avoid informing change listener if we are part of a tl (no changes so war)
			self._set_higherlayer(handler_obj, notify_changelistener=False)
			# This was a lazy init: same as direct dissecting -> no body change
			self._body_value_changed = False
		except:
			#except Exception as ex:
			# Error on lazy dissecting: set raw bytes
			self._errors |= ERROR_DISSECT
			self._body_bytes = handler_data[1]
			"""
			logger.warning("Can't initiate handler %r (malformed packet?):"
				" base=%s, reason: %r,"
				" bytes for init: %r, current higher layer: %r",
				handler_data[0], self.__class__, ex,
				self._body_bytes.tobytes() if type(self._body_bytes) is memoryview else self._body_bytes,
				self._higher_layer)
			logger.exception(ex)
			"""
		self._lazy_handler_data = None

	def __getitem__(self, pkt_clzs):
		"""
		Check every layer upwards (inclusive this layer) for the given criteria
		and return the matched layers. Stops searching as soon as a layer doesn't match
		or end of needle/haystack reached. Example:

		a, b, c, d = pkt[
			(A, lambda a: a.src="123"), # Type A and filter must match
			None, # This layer can be anything
			C, # Only type must match
			(None, lambda d: d.__class__ == d), # No type given but filter must match
		]

		All layers have to match starting from A (explicit is better than implicit).
		Comparing starts from first layer otherwise ALL layers have to
		be parsed all the time until a matching layer (to A) appears (starting layer
		is not known a priori).

		pkt_clzs -- Packet classes to search for. Optional lambdas can be used for filtering each layer.
		return -- All matching layers like ret=[a, b, None, None]
			with len(ret) == len(input_list)
		"""
		#logger.debug(self.__class__)
		p_instance = self

		# Multi-value index search
		if type(pkt_clzs) is tuple:
			# Keep unpacking until pkt_clzs is found (no intermediate storing)
			pkt_clzs_len = len(pkt_clzs)
			layers = []
			gotmatch = False

			for pkt_clz in pkt_clzs:
				filter = LAMBDA_TRUE
				gotmatch = True

				# (A, lambda a: a.src="123")
				if type(pkt_clz) is tuple:
					pkt_clz, filter = pkt_clz
				# else: A

				if pkt_clz is not None and pkt_clz != p_instance.__class__:
					# Mismatch in type
					gotmatch = False

				try:
					if not filter(p_instance):
						# Mismatch in filter
						gotmatch = False
				except:
					# This happens if filter is (?, lambda pkt: ...)
					# Eg: checking attributes on wrong packet type
					gotmatch = False

				layers.append(p_instance if gotmatch else None)

				# No match or highest layer reached (no more layers or end of needle reached)
				if not gotmatch or p_instance.higher_layer is None or len(layers) == pkt_clzs_len:
					break
				# End of match sequence in pkt_clzs not reached, go higher
				#logger.debug(p_instance.__class__)
				p_instance = p_instance.higher_layer

			# Return matching layers
			return layers if len(layers) == pkt_clzs_len else layers + [None] * (pkt_clzs_len - len(layers))
		# Single-value index search
		else:
			# Keep unpacking until pkt_clz is found (no intermediate storing)
			while not type(p_instance) is pkt_clzs:
				# This will auto-parse lazy handler data via _get_higherlayer()
				p_instance = p_instance.higher_layer

				if p_instance is None:
					break

			return p_instance

	def __iter__(self):
		"""
		Iterate over every layer starting from this layer.
		To start from the lowest layer use "for l in pkt.lowest_layer".
		"""
		p_instance = self
		# Unpack until highest layer; assume string class never gets found as layer
		while p_instance is not None:
			yield p_instance
			# This will auto-parse lazy handler data via _get_higherlayer()
			p_instance = p_instance.higher_layer

			if p_instance is None:
				break

	def __contains__(self, clz):
		return self[clz] is not None

	def __eq__(self, clz):
		"""
		Compare class of this object to the given class/object
		"""
		# Convert object to its class
		if not type(clz) == MetaPacket:
			clz = clz.__class__
		return self.__class__ == clz

	def dissect_full(self):
		"""
		Recursive read all layer inlcuding header up to highest layer.
		"""
		for name in self._headerfield_names:
			self.__getattribute__(name)

		if self.higher_layer is not None:
			self.higher_layer.dissect_full()

	def __add__(self, packet_or_bytes_to_add):
		"""
		Concatinate a packet with another packet or bytes.
		Note: Beware of side effects as Packets remain connected until removed,
		eg via pkt.higher_layer = None.

		packet_or_bytes_to_add -- The packet or bytes to be added as highest layer
		"""
		if type(packet_or_bytes_to_add) is not bytes:
			self.highest_layer.higher_layer = packet_or_bytes_to_add
		else:
			self.highest_layer.body_bytes += packet_or_bytes_to_add
		return self

	def __iadd__(self, packet_or_bytes_to_add):
		"""
		Concatinate a packet with another packet or bytes.
		Note: Beware of side effects as Packets remain connected

		packet_or_bytes_to_add -- The packet or bytes to be added as highest layer
		"""
		if type(packet_or_bytes_to_add) is not bytes:
			self.highest_layer.higher_layer = packet_or_bytes_to_add
		else:
			self.highest_layer.body_bytes += packet_or_bytes_to_add
		return self

	def split_layers(self):
		"""
		Splits all layers to independent ones starting from this one not connected to each other
		e.g. A.B.C -> [A, B, C]
		return -- [layer1, layer2, ...]
		"""
		layers = [layer for layer in self]

		# Disconnect all layers
		for layer in layers:
			# Avoid overwriting bytes, only reset handler
			if layer._body_bytes is None:
				layer.higher_layer = None
			layer.lower_layer = None
		return layers

	def summarize(self):
		"""
		Print a summary of this layer.
		Optional: Call bin() to update auto-update fields.
		"""
		# Values need to be unpacked to be shown
		#logger.debug(self.__class__)
		self._unpack()

		# Create key=value descriptions
		# Show all header even deactivated ones
		layer_sums_l = []

		for idx, name in enumerate(self._headerfield_names):
			#logger.debug("Getting %s" % name)
			val = getattr(self, name)
			value_alt = ""
			value_translated = ""

			try:
				# Try to get convenient name
				value_alt = " = " + getattr(self, name + "_s")
			except:
				# Not set
				pass

			try:
				# Try to get translated name
				value_translated = getattr(self, name + "_t")

				if value_translated != "":
					value_translated = " = " + value_translated
			except:
				# Not set
				pass

			# Values: int
			if type(val) is int:
				format = self._header_formats[idx]
				layer_sums_l.append("%-12s (%s): 0x%X = %d = %s" % (name, format, val, val,
					bin(val)) + value_alt + value_translated)
			# Inactive
			elif val is None:
				layer_sums_l.append("%-16s: (inactive)" % name)
			else:
				# Values: bytes
				if type(val) is bytes:
					bts_cnt = "(%d)" % len(val)
					layer_sums_l.append("%-9s %6s: %s" % (name, bts_cnt, val) +
						value_alt + value_translated)
				# Values Triggerlist (can contain Packets, tuples, bytes)
				else:
					#logger.debug("%r %r" % (self.__class__, name))
					layer_sums_l.append("%-16s: %s" % (name, val) + value_alt)

		try:
			# Add padding info, not part of _headerfield_names. See Ethernet or SCTP
			if "padding" not in self._headerfield_names:
				#logger.debug("Trying to get padding in %r" % self.__class__)
				value_padding = getattr(self, "padding")
				#logger.debug("padding is: %r" % value_padding)
				if len(value_padding) > 0:
					bts_cnt = "(%d)" % len(value_padding)
					layer_sums_l.append(
						"%-9s %6s: %s (lower layer = more outer padding)" % ("//padding", bts_cnt, value_padding))
		except:
			# No padding
			pass

		if self.higher_layer is None:
			# No upper layer present: describe body bytes
			bts_cnt = "(%d)" % len(self.body_bytes)
			layer_sums_l.append("%-9s %6s: " % ("body_bytes", bts_cnt) + "%s" % self.body_bytes)

		layer_sums = "%s\n\t%s" % (
			self.__module__[9:] + "." + self.__class__.__name__,
			"\n\t".join(layer_sums_l))

		return layer_sums

	def __str__(self):
		#logger.debug(self.__class__)
		# Recalculate fields like checksums, lengths etc
		if self._header_cached is None or self._body_value_changed:
			self.bin()
		# This does lazy init of handler
		upperlayer_str = "\n%s" % self.higher_layer if self.higher_layer is not None else ""
		return self.summarize() + upperlayer_str

	def _unpack(self):
		"""
		Unpack a full layer (set field values) unpacked from cached header bytes.
		This will use the current value of _header_cached to set all field values.
		NOTE:
		- This is only called by the Packet class itself
		- This is called prior to changing ANY header values
		"""
		#logger.debug("%r: unpacked=%r" % (self.__class__, self._unpacked))
		if self._unpacked:
			#logger.debug("Already unpacked")
			return

		# Needed to set here (and not at the end) to avoid recursive calls
		self._unpacked = True
		# Unpack is not triggered by changes to triggerlists -> Format may have changed
		self._update_cached_header_format_and_tl_states()
		#logger.debug("Unpacking %r: %r -> %r" % (self.__class__,
		#	self._header_format_cached.format,
		#	self._header_cached.tobytes() if type(self._header_cached) == memoryview else self._header_cached))
		# This makes header values unshared
		self._header_values = list(self._header_format_cached.unpack(self._header_cached))
		self._header_values_shared = False

	def reverse_address(self):
		"""
		Reverse source <-> destination address of THIS packet. This is at minimum
		defined for: Ethernet, IP, TCP, UDP
		"""
		pass

	def reverse_all_address(self):
		"""
		Reverse source <-> destination address of EVERY packet upwards including this one
		(reverse_address has to be implemented).
		"""
		current_hndl = self

		while current_hndl is not None:
			current_hndl.reverse_address()
			current_hndl = current_hndl.higher_layer

	def direction_all(self, other_packet):
		"""
		Check for direction on ALL layers from this one upwards.
		This continues upwards until no body handler can be found anymore.
		The extending class can overwrite direction() to implement an individual check,

		other_packet -- Packet to be compared with this Packet
		return -- Bitwise AND-concatination of all directions of ALL layers starting from
			this one upwards. Directions are: [DIR_SAME | DIR_REV | DIR_UNKNOWN].
			This can be checked via eg "direction_found & DIR_SAME"
		"""
		dir_ext = self.direction(other_packet)

		try:
			# Check upper layers and combine current result
			# logger.debug("direction? checking next layer")
			dir_upper = self.higher_layer.direction_all(other_packet.higher_layer)

			return dir_ext & dir_upper
		except AttributeError:
			# One of both _higher_layer was None
			# Example: TCP ACK (last step of handshake, no payload) <-> TCP ACK + Telnet
			#logger.debug("AttributeError, direction: %d", dir_ext)
			#logger.debug(e)
			return dir_ext

	def direction(self, other):
		"""
		Check if this layer got a specific direction compared to "other". Can be overwritten.

		return -- [DIR_SAME | DIR_REV | DIR_UNKNOWN | DIR_NOT_IMPLEMENTED]
		"""
		return Packet.DIR_NOT_IMPLEMENTED

	def is_direction(self, packet2, direction):
		"""
		Same as "direction_all()" but using explicit direction to be checked.
		As direction_all can be DIR_SAME and DIR_REV at the same time, this call
		is more clearly.

		packet2 -- packet to be compared to this packet
		direction -- check for this direction (DIR_...)
		return -- True if direction is found in this packet, False otherwise.
		"""
		#logger.debug("direction_all & direction = %d & %d", self.direction_all(packet2), direction)
		return self.direction_all(packet2) & direction == direction

	def _update_higherlayer_id(self):
		"""
		Updates the upperlayer id named by _id_fieldname (FIELD_FLAG_IS_TYPEFIELD was
		set) based on the upperlayer class and simply assigning the associated id to that field.

		Example: current layer = Ethernet, id field = type, body handler class = IP, eth.type
		will be set to ETH_TYPE_IP.

		If updating the type id is more complex than a simple assignmet this method has to
		be overwritten.
		"""
		# Do nothing if one of:
		# - type id field not known
		# - body was not changed (bytes or handler must have been changed)
		# - there is a higher layer (there must be a higher layer, not bytes)
		# - type id field is active
		if self._id_fieldname is None\
			or not self._body_value_changed\
			or self._higher_layer is None\
			or not self.__getattribute__("%s_au_active" % self._id_fieldname):
			return

		# logger.debug("will update handler id, %s / %s / %s / %s",
		#	self._id_fieldname,
		#	self.__getattribute__("%s_au_active" % self._id_fieldname),
		#	self._lazy_handler_data,
		#	self._body_changed)
		# Likely to succeed
		try:
			handler_clz = self._higher_layer.__class__
			# Only set id if the upper layer class can be assoicated to this layer (eg Ethernet -> IP, not Ethernet -> TCP)
			self.__setattr__(self._id_fieldname,
				Packet._handlerclass_id_dct[self.__class__][handler_clz])
		except:
			# No type id found, something like eth + Telnet
			#logger.debug("no type id found for %s, class: %s -> %s" %
			#	(self._higher_layer.__class__, self.__class__, handler_clz))
			pass

	def _update_fields(self):
		"""
		Overwrite this to update header fields.
		Only gets called if this or any other upper layer has changed.
		Callflow on a packet "pkt = layer1 + layer2 + layer3 -> pkt.bin()":
		layer3._update_fields() -> layer2._update_fields() -> layer1._update_fields() ...
		"""
		pass

	def bin(self, update_auto_fields=True):
		"""
		Return this header and body (including all upper layers) as byte string
		and reset changed-status.

		update_auto_fields -- If True auto-update fields like checksums, else leave them be
		"""
		#logger.debug(self.__class__)
		# Update all above already-instantiated layers if *something* has changed
		if update_auto_fields and self._changed():
			#logger.debug("Updating due to changes in %r" % str(self.__class__))
			# Collect layers to be updated:
			# Iterate update for A.B.C like C->B->A: A needs uptodate B and C,
			# B needs uptodate C
			layers = []
			layer_it = self

			while layer_it is not None:
				layers.append(layer_it)
				# Upper layer is not yet dissected but *could* need update.
				# eg: IP:changed + TCP:notchanged/parsed -> TCP needs update
				if layer_it._lazy_handler_data is not None:
					# Next upper layer forces update in layer_it, eg IP->TCP (layer_it)
					if layer_it._header_cached is None and\
						layer_it._lazy_handler_data[0].__class__ in layer_it._update_dependants:
						# Force dissecting
						layer_it = layer_it.higher_layer
					else:
						layer_it = None
				else:
					layer_it = layer_it.higher_layer

			# Start from the top
			layers.reverse()

			for layer in layers:
				layer._update_fields()

		header_tmp = self._pack_header()

		if self._higher_layer is not None:
			# Recursive call
			# This should allow padding like "1 2 3 .... p2 p1"
			bodybytes_tmp = self._higher_layer.bin()
		else:
			bodybytes_tmp = self._get_bodybytes()

		#logger.debug("Body bytes: %r" % bodybytes_tmp)

		# Now every layer got informed about our status, reset this layer
		self._reset_changed()
		return header_tmp + bodybytes_tmp

	def _update_cached_header_format_and_tl_states(self):
		"""
		Update format of this packet header.
		"""
		#logger.debug(self.__class__)
		#logger.debug("Formats: %s" % self._header_formats)
		if self._header_format_cached is None:
			if len(self._tlchanged) > 0:
				# Update values and formats of tl in this packet
				# _header_formats: should be already unshared (on/off, dynamic, tl init)
				# _header_values: will be overwritten by _unpack after init,
				# but that's ok (should be same value)
				for name in self._tlchanged:
					tlobj, idx = self._headername_tlobj[name]
					# tl changed so calling to bin() is needed (instead of just __len__)
					bts = tlobj.bin()
					self._header_values[idx] = bts
					self._header_formats[idx] = "%ds" % len(bts)

				self._tlchanged.clear()

			self._header_format_cached = Struct(">" + "".join(self._header_formats))

	def _pack_header(self):
		"""
		Return header as byte string.
		"""
		#logger.debug(self.__class__)
		if self._header_cached is not None:
			# Return cached data if nothing changed
			if type(self._header_cached) == memoryview:
				self._header_cached = self._header_cached.tobytes()
			#logger.warning("Returning cached header: %s" % self._header_cached)
			return self._header_cached

		# - Format may be None (value set)
		# - Changes to header but not unpacked (only tl was accessed)
		# -> update
		self._update_cached_header_format_and_tl_states()
		#logger.debug("%r: %r -> %r" % (self.__class__, self._header_format_cached.format, self._header_values))
		self._header_cached = self._header_format_cached.pack(*self._header_values)

		return self._header_cached

	# Readonly access to header
	header_bytes = property(_pack_header)

	def _changed(self):
		"""
		Check if this or any upper layer changed in header or body

		return -- True if header or body changed, else False
		"""
		changed = False
		p_instance = self

		while p_instance is not None:
			if p_instance._header_cached is None or p_instance._body_value_changed:
				#logger.debug("Found change in %r" % p_instance.__class__)
				changed = True
				break
			elif p_instance._lazy_handler_data is None:
				# One layer up, stop if next layer is not yet initiated which means: no change
				p_instance = p_instance.higher_layer
			else:
				# Nothing changed upwards: lazy handler data still present/nothing got parsed
				break
		return changed

	def _reset_changed(self):
		"""Set the header/body changed-flag to False. This won't clear caches."""
		self._body_value_changed = False
		# "header_changed==true" = "_header_cached==None"

	_header_value_changed = property(lambda obj: obj._header_cached is None)

	def _add_change_listener(self, listener_cb):
		"""
		Add a new callback to be called on changes to header or body.

		listener_cb -- the change listener to be added as callback-function
		"""
		if self._changelistener is None:
			self._changelistener = {listener_cb}
		else:
			self._changelistener.add(listener_cb)

	def _remove_change_listener(self):
		"""
		Remove all change listener.
		"""
		if self._changelistener is not None:
			self._changelistener.clear()

	def _notify_changelistener(self):
		"""
		Notify listener about changes in header or body using signature callback(self).
		This is primarily meant for triggerlist to react
		on changes in packets like Triggerlist[packet1, packet2, ...].
		"""
		# No listener added so far -> nothing to notify
		if self._changelistener is None:
			return

		for listener_cb in self._changelistener:
			listener_cb(self)

	@classmethod
	def load_handler(cls, clz_add, handler):
		"""
		Load Packet handler classes using a shared dictionary.

		clz_add -- class for which handler has to be added
		handler -- dict of handlers to be set like { id | (id1, id2, ...) : class }, id can be a tuple of values
		"""
		if clz_add not in Packet._id_handlerclass_dct:
			Packet._id_handlerclass_dct[clz_add] = {}
			Packet._handlerclass_id_dct[clz_add] = {}

		for handler_id, packetclass in handler.items():
			# pypacker.Packet.load_handler(IP, { ID : class } )
			if type(handler_id) is not tuple:
				Packet._id_handlerclass_dct[clz_add][handler_id] = packetclass
				Packet._handlerclass_id_dct[clz_add][packetclass] = handler_id
			else:
				# logger.debug("Loading multi-ID handler: clz_add=%s, packetclass=%s, handler_id[0]=%s" %
				#	(clz_add, packetclass, handler_id[0]))
				# pypacker.Packet.load_handler(IP, { (ID1, ID2, ...) : class } )
				for id_x in handler_id:
					Packet._id_handlerclass_dct[clz_add][id_x] = packetclass
				# Ambiguous relation of "handler class -> type ids", take 1st one
				Packet._handlerclass_id_dct[clz_add][packetclass] = handler_id[0]

	def hexdump(self, length=16, only_header=False):
		"""
		length -- amount of bytes per line
		only_header -- if True: just dump header, else header + body (default)

		return -- hexdump output string for this packet (header or header + body).
		"""
		bytepos = 0
		res = []

		if only_header:
			buf = self._pack_header()
		else:
			buf = self.bin()
		buflen = len(buf)

		while bytepos < buflen:
			line = buf[bytepos: bytepos + length]
			hexa = " ".join(["%02x" % x for x in line])
			# line = line.translate(__vis_filter)
			line = re.sub(PROG_NONVISIBLE_CHARS, b".", line)
			res.append("  %04d:      %-*s %s" % (bytepos, length * 3, hexa, line))
			bytepos += length
		return "\n".join(res)

#
# Utility functions
# These could be put into separate modules but this would lead to recursive import problems.
#
# Avoid unneeded references for performance reasons
randint = random.randint


def byte2hex(buf):
	"""Convert a bytestring to a hex-represenation:
	b'1234' -> '\x31\x32\x33\x34'"""
	return "\\x" + "\\x".join(["%02X" % x for x in buf])


# MAC address
def mac_str_to_bytes(mac_str):
	"""Convert mac address AA:BB:CC:DD:EE:FF to byte representation."""
	return b"".join([bytes.fromhex(x) for x in mac_str.split(":")])


def mac_bytes_to_str(mac_bytes):
	"""Convert mac address from byte representation to AA:BB:CC:DD:EE:FF."""
	return "%02X:%02X:%02X:%02X:%02X:%02X" % unpack_mac(mac_bytes)


def get_rnd_mac():
	"""Create random mac address as bytestring"""
	return pack_mac(randint(0, 255), randint(0, 255), randint(0, 255),
		randint(0, 255), randint(0, 255), randint(0, 255))


def get_property_mac(varname):
	"""Create a get/set-property for a MAC address as string-representation."""
	return property(
		lambda obj: mac_bytes_to_str(obj.__getattribute__(varname)),
		lambda obj, val: obj.__setattr__(varname, mac_str_to_bytes(val))
	)


# IPv4 address
def ip4_str_to_bytes(ip_str):
	"""Convert ip address 127.0.0.1 to byte representation."""
	ips = [int(x) for x in ip_str.split(".")]
	return pack_ipv4(ips[0], ips[1], ips[2], ips[3])


def ip4_bytes_to_str(ip_bytes):
	"""Convert ip address from byte representation to 127.0.0.1."""
	return "%d.%d.%d.%d" % unpack_ipv4(ip_bytes)


def get_rnd_ipv4():
	"""Create random ipv4 adress as bytestring"""
	return pack_ipv4(randint(0, 255), randint(0, 255), randint(0, 255), randint(0, 255))


def get_property_ip4(var):
	"""Create a get/set-property for an IP4 address as string-representation."""
	return property(
		lambda obj: ip4_bytes_to_str(obj.__getattribute__(var)),
		lambda obj, val: obj.__setattr__(var, ip4_str_to_bytes(val))
	)


# IPv6 address
def ip6_str_to_bytes(ip6_str):
	"""Convert ip address 127.0.0.1 to byte representation."""
	return v6_int_to_packed(int(IPv6Address(ip6_str)))


def ip6_bytes_to_str(ip6_bytes):
	"""Convert ip address from byte representation to 127.0.0.1."""
	return str(IPv6Address(ip6_bytes))


def get_property_ip6(var):
	"""Create a get/set-property for an IP6 address as string-representation."""
	return property(
		lambda obj: ip6_bytes_to_str(obj.__getattribute__(var)),
		lambda obj, val: obj.__setattr__(var, ip6_str_to_bytes(val))
	)


# DNS names
def dns_name_decode(name, cb_mc_bytes=lambda: b""):
	"""
	DNS domain name decoder (bytes to string)

	name -- example: b"\x03www\x07example\x03com\x00"
	cb_bytes -- callback to get bytes used to find name in case of Message Compression
		cb_bytes_pointer(): bytes
	return -- example: "www.example.com."
	"""
	# ["www", "example", "com"]
	name_decoded = []
	parsed_pointers = set()
	off = 1
	buf = name
	#logger.debug("Decoding DNS: %r" % buf)

	while off < len(buf):
		size = buf[off - 1]
		if size == 0:
			break
		elif (size & 0b11000000) == 0:
			# b"xxx" -> "xxx"
			name_decoded.append(buf[off:off + size].decode())
			off += size + 1
		else:
			# DNS message compression
			off = (((buf[off - 1] & 0b00111111) << 8) | buf[off]) + 1
			buf = cb_mc_bytes()
			#logger.debug("Found compression, off=%d, msg: %r" % (off, buf))

			if off in parsed_pointers:
				# DNS message loop, abort...
				#logger.debug("Msg loop, abort")
				break
			parsed_pointers.add(off)
	#logger.debug("Returning: %r" % (".".join(name_decoded) + "."))
	return ".".join(name_decoded) + "."


def dns_name_encode(name):
	"""
	DNS domain name encoder (string to bytes)

	name -- example: "www.example.com"
	return -- example: b'\x03www\x07example\x03com\x00'
	"""
	name_encoded = [b""]
	# "www" -> b"www"
	labels = [part.encode() for part in name.split(".") if len(part) != 0]

	for label in labels:
		# b"www" -> "\x03www"
		name_encoded.append(chr(len(label)).encode() + label)
	return b"".join(name_encoded) + b"\x00"


def get_property_dnsname(var, cb_mc_bytes=lambda obj: b""):
	"""
	Create a get/set-property for a DNS name.

	cb_bytes -- callback to get bytes used to find name in case of Message Compression
		cb_bytes_pointer(containing_obj) -- bytes
	"""
	return property(
		lambda obj: dns_name_decode(obj.__getattribute__(var),
			cb_mc_bytes=lambda: cb_mc_bytes(obj)),
		lambda obj, val: obj.__setattr__(var, dns_name_encode(val))
	)


def get_property_bytes_num_v1(var, format_target):
	"""
	Creates a get/set-property for "bytes (format Xs) <-> number" where len(bytes) is not 2**x.
	Sometimes numbers aren't encoded as multiple of 2 (see SSL -> Handshake -> 3 bytes = integer???).
	That's bad. How to convert between both representations? Well...
	Note: only use w/ simple static fields

	var -- varname to create a property for
	format_target -- real format of the theader used to create a number.

	Note: only use with static headers
	"""
	format_target_struct = Struct(format_target)
	format_target_unpack = format_target_struct.unpack
	format_target_pack = format_target_struct.pack
	format_varname_s = ("_%s" % var) + "_format"

	def get_formatlen_of_var(obj):
		format_var_s = obj.__getattribute__(format_varname_s)

		if format_var_s is None:
			#logger.warning("Got None format for %s, can't convert for convenience!", var)
			return 0

		return Struct(format_var_s).size

	def get_val_bts_to_int(obj):
		format_var_len = get_formatlen_of_var(obj)
		prefix_bts = (b"\x00" * (format_target_struct.size - format_var_len))
		return format_target_unpack(prefix_bts + obj.__getattribute__(var))[0]

	def set_val_int_to_bts(obj, val):
		format_var_len = get_formatlen_of_var(obj)
		obj.__setattr__(var, format_target_pack(format_target, val)[:-format_var_len])

	return property(
		# bytes -> int
		get_val_bts_to_int,
		# int -> bytes
		set_val_int_to_bts
	)


def bts_to_int(val):
	prefix_bts = b"\x00" * (8 - len(val))
	return unpack_Q(prefix_bts + val)[0]


def int_to_bts(valint, bts_len):
	return pack_Q(valint)[:-bts_len]


def get_property_bytes_num(varname):
	"""
	Creates a get/set-property for "bytes (format Xs) <-> number".
	Comes in handy where len(bytes) is not 2**x.

	Note: only use w/ simple static fields
	Note: max bytes length is 8
	Note: field must be active

	varname -- varname to create a property for
	"""
	varname = [varname]

	def _bts_to_int(obj):
		val_bts = obj.__getattribute__(varname[0])

		if val_bts is None:
			return None

		return bts_to_int(val_bts)

	def _int_to_bts(obj, val_int):
		val_bts_current = obj.__getattribute__(varname[0])

		if val_bts_current is None:
			logger.warning("Field for autoconvert is inactive, activate it first!")
			return
		obj.__setattr__(var, int_to_bts(val_int, len(val_bts_current)))

	return property(
		_bts_to_int,
		_int_to_bts
	)


def get_property_translator(
	varname,
	varname_regex,
	cb_get_description=lambda value, value_name_dct: value_name_dct[value]):
	"""
	Get a descriptor allowing to make a "value -> variable name representation" translation.
	The variable name representation can actually be used to assign values to the field in question.
	Example: ip.py -> contains IP_PROTO_UDP=17 -> ip1.p=ip.IP_PROTO_UDP -> ip.p_t gives "IP_PROTO_UDP"

	varname_regex -- The regex to find variables.
	cb_get_description -- lambda value, value_name_dct: Description
	return -- property allowing get-access to get an descriptive name
	"""
	# Get globals of calling module containing the variables in question
	globals_caller = inspect.stack()[1][0].f_globals

	def collect_cb():
		varname_pattern = re.compile(varname_regex)
		return {value: name for name, value in globals_caller.items() if
			type(value) in VARFILTER_TYPES and varname_pattern.match(name)}

	ldict = LazyDict(collect_cb)

	def descricptor_cb(value):
		if value not in ldict:
			return ""

		return cb_get_description(value, ldict)

	# Only get access
	return property(
		lambda obj: descricptor_cb(obj.__getattribute__(varname))
	)


def get_ondemand_property(varname, initval_cb):
	"""
	Creates a property whose value gets initialized ondemand.
	This is meant as an alternative to an initialization in __init__
	to decrease initial loading time
	"""
	varname_shadowed = "_%s" % varname

	def get_var(self):
		try:
			# Likely to succeed
			return self.__getattribute__(varname_shadowed)
		except:
			val = initval_cb()
			self.__setattr__(varname_shadowed, val)
			return val

	def set_var(self, value):
		return self.__setattr__(varname_shadowed, value)

	return property(get_var, set_var)
