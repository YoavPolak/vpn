# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
import struct
import logging

logger = logging.getLogger("pypacker")

# Allows to activate/decative the auto-update of a header field.
# Note: _update_fields() has to be implemented
FIELD_FLAG_AUTOUPDATE	= 1
# Identifies the header field defining the next higher layer type
# Allows to auto-set the value on concatenation: "pkt = eth0 + ip0" sets type field in eth0
# Auto-sets FIELD_FLAG_AUTOUPDATE
# Note: _update_fields() has to be implemented and _update_higherlayer_id() has to be called in it.
FIELD_FLAG_IS_TYPEFIELD	= 2

HEADERVALUETYPES_SIMPLE = {bytes, int}


def unshare_headername_tlobj(obj):
	if obj._headername_tlobj_shared:
		obj._headername_tlobj = dict(obj._headername_tlobj)
		obj._headername_tlobj_shared = False


def unshare_formats(obj):
	if obj._header_formats_shared:
		obj._header_formats = list(obj._header_formats)
		obj._header_formats_shared = False


def unshare_values(obj):
	if obj._header_values_shared:
		obj._header_values = list(obj._header_values)
		obj._header_values_shared = False


def get_setter(t, header_idx, header_format_original, is_field_type_simple, is_field_static):
	"""
	varname -- name of the variable to set the property for
	is_field_type_simple -- get property for simple static or dynamic type if True, else TriggerList
	is_field_type_simple -- if True: get static type (int, fixed size bytes, ...),
		else dynamic (format "xs") which can change in format (eg DNS names)

	return -- set-property for simple types or triggerlist
	"""
	def setfield_simple(obj, value):
		"""
		value -- bytes, int or None
		"""
		if obj._unpacked == False:
			# obj._unpacked = None means: dissect not yet finished
			obj._unpack()

		if is_field_static:
			unshare_values(obj)
			# Switch active/inactive
			if value is None and obj._header_formats[header_idx] != "0s":
				unshare_formats(obj)
				obj._header_formats[header_idx] = "0s"
				# Will be set later
				value = b""
				obj._header_format_cached = None
			elif value is not None and obj._header_formats[header_idx] == "0s":
				unshare_formats(obj)
				obj._header_formats[header_idx] = header_format_original
				obj._header_format_cached = None
		else:
			# Simple dynamic field: update format.
			format_new = "%ds" % len(value)
			format_old = obj._header_formats[header_idx]

			# Avoid unneeded updates
			if format_new != format_old:
				unshare_formats(obj)
				obj._header_formats[header_idx] = "%ds" % len(value)
				obj._header_format_cached = None

		if obj._unpacked is None:
			return

		# We are not in _dissect anymore, assign value
		unshare_values(obj)
		#logger.debug("Setting %s=%s in %r (_header_format_cached=maybe None)" % (
		#	obj._headerfield_names[header_idx], value, obj.__class__))
		obj._header_values[header_idx] = value
		obj._header_cached = None
		obj._notify_changelistener()

	def setfield_triggerlist(obj, value):
		# Triggerlist assigning is the same as extending
		headername = t._headerfield_names[header_idx]
		# This will trigger init if not already done
		tl = obj.__getattribute__(headername)
		# Content will be replaced
		tl.clear()
		# Wrap
		if type(value) != list:
			value = [value]
		tl.extend(value)

	if is_field_type_simple:
		return setfield_simple

	return setfield_triggerlist


def get_getter(t, header_idx, tl_class=None):
	headername = t._headerfield_names[header_idx]

	def getfield_simple(obj):
		if obj._unpacked == False:
			# obj._unpacked = None means: dissect not yet finished
			obj._unpack()
		#logger.debug("Getting field %r, %r=%r" % (headername, header_idx, obj._header_values[header_idx]))
		return obj._header_values[header_idx]

	def getfield_triggerlist(obj):
		"""
		Callflows:
		dissect -> no changes to simple headers -> bin() -> update format and cached header
		"""
		if obj._unpacked is None:
			obj_l = [obj]

			# obj._unpacked = None means: dissect not yet finished
			def set_buf_cb(buf, cb):
				unshare_headername_tlobj(obj_l[0])
				# length of buf must be the final/correct length
				obj._headername_tlobj[headername] = [buf, cb]
				#logger.debug("Setting tl buf for %r: %r, %r" % (headername, buf.tobytes(), cb))
				unshare_formats(obj_l[0])
				obj._header_formats[header_idx] = "%ds" % len(buf)
				# Standard format was 0s -> new one probably different -> reset old cached format
				obj._header_format_cached = None
				# Header is unchanged/cached at initiation.
				# _pack_header: tl has beeb put into _header_values by unpack
			return set_buf_cb
		else:
			#logger.debug("tl %s is being read" % headername)
			buf_cb__tlobj_idx = obj._headername_tlobj.get(headername)

			# Uninitialized: [memoryview(b"..."), lambda buf: []]
			# or
			# Initilaized: (tl_obj, 123)
			if type(buf_cb__tlobj_idx) == tuple:
				# More likely
				tl = buf_cb__tlobj_idx[0]
			else:
				tlbuf, tlcb = buf_cb__tlobj_idx
				#logger.debug("Init of tl: %r, via: %r" % (headername, tlbuf.tobytes()))
				tl_obj = tl_class(
					obj,
					headername,
					dissect_callback=tlcb,
					buffer=tlbuf,
				)
				#logger.debug("Init of tl %r finished" % headername)
				unshare_headername_tlobj(obj)
				obj._headername_tlobj[headername] = (tl_obj, header_idx)
				# Unchanged so far (_dissect -> tl access)
				tl = tl_obj

			return tl

	if tl_class is None:
		return getfield_simple

	return getfield_triggerlist


def configure_packet_header(t, hdrs):
	"""
	Get header-infos: [("name", "format", value), ...]
	"""
	if hdrs is None:
		return t._header_formats, t._header_values

	# Create a property for every field: property a -> get/set access
	# Using properties will slow down access to header fields but it's needed:
	# This way we get informed about get-access (needed to check for unpack)
	# more efficiently than using __getattribute__ (slow access for header
	# fields vs. slow access for ALL class members).
	for header_idx, hdr in enumerate(hdrs):
		headername = hdr[0]
		headerformat = hdr[1]
		headervalue = hdr[2]
		field_flags = hdr[3] if len(hdr) >= 4 else None

		# Sanity checks
		# Max packet fields: [name, format, value, flags)
		if len(hdr) > 4:
			logger.warning("Amount of field definitions > 4: %r", hdr)

		if headerformat is not None:
			try:
				struct.Struct(headerformat)
			except struct.error:
				raise Exception("Invalid format specified in class %s for header '%s': '%s'" %
					(t.__module__ + "." + t.__name__, headername, headerformat))

			if headervalue is not None:
				try:
					struct.Struct(headerformat).pack(headervalue)
				except struct.error:
					raise Exception("Invalid value specified in class %s for header '%s' with format '%s': '%s'" %
						(t.__module__ + "." + t.__name__, headername, headerformat, headervalue))

		t._headerfield_names.append(headername)
		t._header_formats.append(headerformat)
		t._header_values.append(headervalue)

		is_field_type_simple = False
		is_field_static = True

		if headerformat is not None or (headervalue is None or type(headervalue) in HEADERVALUETYPES_SIMPLE):
			# Simple static or simple dynamic type
			# We got one of:
			# - ("name", None, ...) = Format None = dynamic
			# - ("name", format, ???) = Format given = static
			is_field_type_simple = True

			if headerformat is None:
				# Assume simple dynamic field
				is_field_static = False

		if is_field_type_simple:
			if headervalue is None:
				# Inactive field
				t._header_formats[header_idx] = "0s"
				t._header_values[header_idx] = b""
			elif headerformat is None:
				# Dynamic field, update format
				t._header_formats[header_idx] = "%ds" % len(headervalue)

			# Check for auto-update
			if field_flags is not None:
				if field_flags & FIELD_FLAG_IS_TYPEFIELD != 0:
					setattr(t, "_id_fieldname", headername)

					field_flags |= FIELD_FLAG_AUTOUPDATE

				if field_flags & FIELD_FLAG_AUTOUPDATE != 0:
					# Remember which fields are auto-update ones
					# xxx__au_active must be set: read by _update_higherlayer_id
					# TODO: use sets?
					setattr(t, headername + "_au_active", True)

			# Setting/getting value is done via properties.
			setattr(t, headername, property(
				get_getter(t, header_idx),
				get_setter(t, header_idx, headerformat, is_field_type_simple, is_field_static)
			))
		else:
			# Will be updated in _dissect -> self.tl_name(...)
			t._header_formats[header_idx] = "0s"
			t._header_values[header_idx] = b""

			# Initial value of TiggerLists: [b""]
			t._headername_tlobj[headername] = [memoryview(b""), lambda v: v]

			setattr(t, headername, property(
				get_getter(t, header_idx, tl_class=headervalue),
				get_setter(t, header_idx, None, is_field_type_simple, is_field_static)
			))
			# Format and value needed for correct length in _unpack()
			# Default is empty TriggerList, must be updated in _dissect via
			# self.tl_name(buf, lambda tlbuf: [])


def configure_packet_header_sub(t, hdrs_sub):
	if hdrs_sub is None:
		return

	for name_cbget_cbset in hdrs_sub:
		if len(name_cbget_cbset) < 2:
			logger.warning("subheader length < 2: %d", len(name_cbget_cbset))
			continue
		#logger.debug("setting subheader: %s", name_cbget_cbset[0])

		# (name, cb_get, cb_set)
		if len(name_cbget_cbset) == 3:
			setattr(t, name_cbget_cbset[0], property(name_cbget_cbset[1], name_cbget_cbset[2]))
		# (name, cb_get)
		else:
			setattr(t, name_cbget_cbset[0], property(name_cbget_cbset[1]))


class MetaPacket(type):
	"""
	This Metaclass is a more efficient way of setting attributes than using __init__.
	This is done by reading name, format and default value out of a mendatory __hdr__
	tuple in every subclass. This configuration is set one time when loading the module
	(not at instantiation). Attributes can be normally accessed using "obj.field" notation.
	Callflaw is: __new__ (loading module) -> __init__ (initiate class)

	Header defintition example:
	__hdr__ = (
		("header1", "H", 123), # simple static field
		("header2", "H", None), # simple static field, inactive
		("header3", None, b"xxx"), # simple dynamic field
		("header4", None, None), # simple dynamic field, inactive
		("header5", None, Triggerlist) # TriggerList field
	)

	For values <1 byte a subheader definition eases up setting/getting those values:

	__hdr_sub__ = (
		("header1_sub",
			lambda val: val & 1  # callback to retrieve value
			lambda obj, val: obj.__setattr__(val & 1)  # callback to set value
		),
		...
	)

	CAUTION:
	- List et al are _SHARED_ among all instantiated classes! A copy is needed on
	changes to them without side effects
	- New protocols: header field names must be unique among other variable and method names
	"""
	def __new__(cls, clsname, clsbases, clsdict):
		# Slots (dct["__slots__"] = ...) can't be used because:
		# Setting default values must be done in __init__ which increases delay (init for every instantiation...)
		# Sidenote: Setting default values here creates readonly exception later:
		# __slots__ = ("var", ...) -> t.var = None -> p = Clz() -> p.var = 123 won't work (var is readonly)
		# See: https://stackoverflow.com/questions/820671/python-slots-and-attribute-is-read-only
		t = type.__new__(cls, clsname, clsbases, clsdict)
		t._headerfield_names = []
		t._header_formats = []
		t._header_formats_shared = True
		t._header_values = []
		t._header_values_shared = True
		# TriggerList objects: headername -> tl_object or [b"...", lambda buf: []]
		t._headername_tlobj = {}
		t._headername_tlobj_shared = True
		# Header names of changed tl (for late format update)
		t._tlchanged = set()
		t._tlchanged_shared = True

		# Varname holding the fieldname containing the id associated with body handler
		# eg Ethernet -> "type" or IP -> "p"
		t._id_fieldname = None
		hdrs = getattr(t, "__hdr__", None)
		configure_packet_header(t, hdrs)

		# Get sub-header-infos: [("name", cb_get, cb_set), ...]
		hdrs_sub = getattr(t, "__hdr_sub__", None)
		configure_packet_header_sub(t, hdrs_sub)

		# Get handler classes, assume Packet class has no member "__handler__"
		handler = getattr(t, "__handler__", None)

		if handler is not None and len(handler) > 0:
			if handler.__class__ is not dict:
				print("Invalid format of __handler__: not a dictionary! %r", handler)
			else:
				t.load_handler(t, handler)

		# Set of higher_layer classes which force dissecting (update dependants):
		# IP->TCP => IP changed -> TCP needs checksum update and
		# needs to be dissected for this -> TCP is update dependant of IP
		update_deps = getattr(t, "UPDATE_DEPENDANTS", set())
		t._update_dependants = set([ud.__class__ for ud in update_deps])

		# Cached format
		t._header_format_cached = struct.Struct(">" + "".join(t._header_formats))
		# Cached header, return this if nothing changed, otherwise None
		t._header_cached = t._header_format_cached.pack(*t._header_values)
		# Indicates if header values got already unpacked
		# [True|False] = Status after dissect, None = pre-dissect (not unpacked)
		t._unpacked = None
		# Body as raw byte string (Will be set in __init__, None if handler is present)
		t._body_bytes = b""
		# Track changes to body value like [None | bytes | body-handler] -> [None | bytes | body-handler]
		# Does not track achanges in body-handler itself
		t._body_value_changed = False
		# Next lower layer: a = b + c -> b will be lower layer for c
		t._lower_layer = None
		t._higher_layer = None
		# Objects which get notified on changes on header or body (shared),
		# eg packet_parent -> TriggerList[packet_sub, ...]:
		# Changes to packet_sub need to be known by packet_parent for format updates
		# and TriggerList to clear cache.
		# Needs to be None do identify uninitialized state.
		t._changelistener = None
		# Parent of the packet which is contained in a triggerlist
		# parent_packet.triggerlist[sub] -> sub._triggelistpacket_parent == parent_packet
		t._triggelistpacket_parent = None
		# Lazy handler data: [name, class, bytes]
		t._lazy_handler_data = None
		# Concatination of errors, see pypacker.py -> ERROR_...
		t._errors = 0
		return t
