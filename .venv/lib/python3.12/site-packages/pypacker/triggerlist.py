# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""TriggerList for handling dynamic headers."""
import logging
import types

logger = logging.getLogger("pypacker")

TRIGGERLIST_CONTENT_SIMPLE = {bytes, tuple}


class TriggerList(list):
	"""
	List with trigger-capabilities representing a Packet header.
	This list can contain any type of raw bytes, tuples like (key, value)
	or packets. Calling bin() will reassemble a content like
	[b"somebytes", mypacket, ("tuplekey", "tuplevalue")]
	to this: b"somebytes" + mypacket.bin() + ("tuplekey", "tuplevalue")[1].
	Custom reassemblation for tuples can be done by overwriting "_pack()".
	"""

	def __init__(self, packet, headername, dissect_callback=None, buffer=b""):
		"""
		packet -- packet where this TriggerList gets integrated
		dissect_callback -- callback which dessects byte string b"buffer", returns [a, b, c, ...]
		buffer -- memoryview (standard init) or byte string (packet called pack_header()) for dissecting
		"""
		super().__init__()
		# Set by external Packet
		self._packet = packet
		self._headername = headername
		self._dissect_callback = dissect_callback
		self._cached_bin = buffer
		#logger.debug("Triggerlist %r: buffer type=%r" % (self.__class__, type(buffer)))

	def _lazy_dissect(self):
		if self._packet._unpacked == False:
			# Before changing TriggerList we need to unpack or
			# cached header won't fit on _unpack(...).
			# Ignored if still in dissect (_unpacked == None).
			# This is called before any changes to TriggerList so place it here.
			self._packet._unpack()

		if self._dissect_callback is None:
			# Already dissected, ignore
			return

		try:
			initial_list_content = self._dissect_callback(self._cached_bin)
		except:
			#except Exception as ex:
			# If anything goes wrong: raw bytes will be accessible in any case
			#logger.debug("Failed to dissect in TL")
			#logger.exception(ex)

			if type(self._cached_bin) == memoryview:
				self._cached_bin = self._cached_bin.tobytes()

			initial_list_content = [self._cached_bin]

		self._dissect_callback = None
		# This is re-calling _lazy_dissect(), avoid by calling parent version
		#logger.debug("Initial list content=%r" % str(initial_list_content))
		super(TriggerList, self).extend(initial_list_content)
		# Add listener to packets in list. Nothing has changed, no notify needed.
		self._refresh_listener(initial_list_content, notify_change=False)

	def __getitem__(self, needle):
		self._lazy_dissect()
		if type(needle) != types.FunctionType:
			return super().__getitem__(needle)
		else:
			idx_value = []
			idx = 0

			for idx, value in enumerate(self):
				try:
					if needle(value):
						idx_value.append((idx, value))
				except:
					#except Exception as ex:
					# Don't care. Note: gets inperformant if too many exceptions
					pass
					#logger.exception(ex)
			return idx_value

	def __iadd__(self, v):
		"""Item can be added using '+=', use 'append()' instead."""
		self._lazy_dissect()
		super().__iadd__(v)
		self._refresh_listener([v])
		return self

	def __setitem__(self, needle, value):
		self._lazy_dissect()
		idxs_to_set = []

		if type(needle) != types.FunctionType:
			idxs_to_set.append(needle)
		else:
			idx = 0

			for idx, value_it in enumerate(self):
				try:
					if needle(value_it):
						idxs_to_set.append(idx)
						break
				except:
					# Don't care. Note: gets inperformant if too many exceptions
					pass

		for idx_to_set in idxs_to_set:
			try:
				# Remove listener from old packet which gets overwritten
				self[idx_to_set].remove_change_listener(None, remove_all=True)
			except:
				pass
			super().__setitem__(idx_to_set, value)

		if len(idxs_to_set) > 0:
			self._refresh_listener([value])

	def __delitem__(self, k):
		self._lazy_dissect()
		if type(k) is int:
			itemlist = [self[k]]
		else:
			# Assume slice: [x:y]
			itemlist = self[k]
		super().__delitem__(k)
		self._refresh_listener(itemlist, connect_packet=False)

	def __len__(self):
		self._lazy_dissect()
		return super().__len__()

	def __iter__(self):
		self._lazy_dissect()
		return super().__iter__()

	def append(self, v):
		self._lazy_dissect()
		super().append(v)
		self._refresh_listener([v])

	def extend(self, v):
		self._lazy_dissect()
		super().extend(v)
		self._refresh_listener(v)

	def insert(self, pos, v):
		self._lazy_dissect()
		super().insert(pos, v)
		self._refresh_listener([v])

	def clear(self):
		self._lazy_dissect()
		items = [item for item in self]
		super().clear()
		self._refresh_listener(items, connect_packet=False)

	def _refresh_listener(self, val, connect_packet=True, notify_change=True):
		"""
		Handle modifications of this TriggerList (adding, removing, ...).
		WARNING: packets can only be put in one tl once at a time

		val -- list of bytes, tuples or packets
		connect_packet -- Connect packet to this tl and parent packet, otherwise disconnect
		"""
		for v in val:
			# Ignore non-packets
			if type(v) in TRIGGERLIST_CONTENT_SIMPLE:
				continue

			if connect_packet:
				# Allow packet in TL to access packet containing this TL:
				# packet1( TL[packet2->"access to packet1"] )
				v._triggelistpacket_parent = self._packet
				# TriggerList observes changes on packets:
				# base packet <- TriggerList (observes changes, set changed status
				# in basepacket) <- contained packet (changes)
				# Add change listener to the packet this TL is contained in.
				lwrapper = lambda informer: self._notify_change(informer)
				v._add_change_listener(lwrapper)
			else:
				# Remove any old listener
				v._remove_change_listener()
				# Remove old parent
				v._triggelistpacket_parent = None
		if notify_change:
			#logger.debug("_refresh_listener -> _notify_change (tl add, remove etc)")
			self._notify_change(self)

	def _notify_change(self, informer):
		"""
		Inform the Packet having this TriggerList as field:
		- pkt.tl_name <- tl
		- pkt.tl_name <- tl <- pkt
		Called by: this list on changes or Packets in this list
		"""
		# Format *may* not have changed but we don't know until bin()
		#logger.debug("tl %r : _notify_change by %r (clearing caches)" % (self.__class__, informer.__class__))
		self._packet._header_format_cached = None
		self._packet._header_cached = None

		if self._packet._tlchanged_shared:
			# Unshare to allow later add()
			self._packet._tlchanged = set(self._packet._tlchanged)
			self._packet._tlchanged_shared = False

		self._packet._tlchanged.add(self._headername)
		self._cached_bin = None

	def bin(self):
		"""
		Output the TriggerLists elements as concatenated bytestring.
		Custom implementations for tuple-handling can be set by overwriting _pack().
		"""
		#logger.debug(self.__class__)
		if self._cached_bin is None:
			result_arr = []
			entry_type = None

			for entry in self:
				entry_type = type(entry)

				if entry_type is bytes:
					result_arr.append(entry)
				elif entry_type is tuple:
					result_arr.append(self._pack(entry))
				else:
					# This Must be a packet, otherthise invalid entry!
					result_arr.append(entry.bin())

			self._cached_bin = b"".join(result_arr)
		elif type(self._cached_bin) == memoryview:
			self._cached_bin = self._cached_bin.tobytes()

		return self._cached_bin

	def _pack(self, tuple_entry):
		"""
		This can  be overwritten to convert tuples (key, value) in TriggerLists
		to bytes (see layer567/http.py)
		return -- byte string representation of this tuple entry
			eg (b"Host", b"localhost") -> b"Host: localhost"
		"""
		# Default implementation: return value
		return tuple_entry[1]

	def __repr__(self):
		self._lazy_dissect()
		return super().__repr__()

	def __eq__(self, obj):
		self._lazy_dissect()
		return super().__eq__(obj)

	def __str__(self):
		self._lazy_dissect()
		tl_descr_l = []
		contains_pkt = False

		for val_tl in self:
			if type(val_tl) in TRIGGERLIST_CONTENT_SIMPLE:
				tl_descr_l.append("%s" % str(val_tl))
			else:
				# assume packet
				#pkt_fqn = val_tl.__module__[9:] + "." + val_tl.__class__.__name__
				#tl_descr_l.append(pkt_fqn)
				tl_descr_l.append("%s" % val_tl)
				contains_pkt = True

		if not contains_pkt or len(tl_descr_l) == 0:
			# Oneline output
			return "[" + ", ".join(tl_descr_l) + "]"
		else:
			# Multiline output
			# TODO: deeper output = more ">"
			final_descr = ["(see below)\n" + ">" * 10 + "\n"]

			for idx, val in enumerate(tl_descr_l):
				idx_descr = "[%d]" % idx
				final_descr.append("-> %s:\n%s\n" % (idx_descr, val))
			final_descr.append("<" * 10)
			return "".join(final_descr)
