# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""
Packet read and write routines for pcap format.
See http://wiki.wireshark.org/Development/LibpcapFileFormat
"""
import logging
import types

from pypacker import pypacker
from pypacker.structcbs import pack_H, unpack_H_le, pack_I, unpack_I_le
from pypacker.structcbs import pack_IIII, unpack_IIII, pack_IIII_le, unpack_IIII_le
from pypacker.layer12 import ethernet, linuxcc, ieee80211, radiotap, btle, can

logger = logging.getLogger("pypacker")

"""
PCAP/TCPDump related
"""
# PCAP file header

# File magic numbers
# pcap using microseconds resolution
TCPDUMP_MAGIC_MICRO	        = 0xA1B2C3D4
TCPDUMP_MAGIC_MICRO_SWAPPED	= 0xD4C3B2A1
# pcap using nanoseconds resolution
TCPDUMP_MAGIC_NANO		= 0xA1B23C4D
TCPDUMP_MAGIC_NANO_SWAPPED	= 0x4D3CB2A1

PCAP_VERSION_MAJOR		= 2
PCAP_VERSION_MINOR		= 4

DLT_NULL				= 0
DLT_EN10MB				= 1
DLT_EN3MB				= 2
DLT_AX25				= 3
DLT_PRONET				= 4
DLT_CHAOS				= 5
DLT_IEEE802				= 6
DLT_ARCNET				= 7
DLT_SLIP				= 8
DLT_PPP					= 9
DLT_FDDI				= 10
DLT_PFSYNC				= 18
DLT_IEEE802_11				= 105
DLT_LINUX_SLL				= 113
DLT_PFLOG				= 117
DLT_IEEE802_11_RADIO			= 127
DLT_CAN_SOCKETCAN		        = 227
DLT_LINKTYPE_BLUETOOTH_LE_LL		= 251
LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR	= 256

PCAPTYPE_CLASS = {
	DLT_LINUX_SLL: linuxcc.LinuxCC,
	DLT_EN10MB: ethernet.Ethernet,
	DLT_CAN_SOCKETCAN: can.CAN,
	DLT_IEEE802_11: ieee80211.IEEE80211,
	DLT_IEEE802_11_RADIO: radiotap.Radiotap,
	LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR: btle.BTLEHdr
}


class PcapFileHdr(pypacker.Packet):
	"""pcap file header."""
	# header length = 24
	__hdr__ = (
		("magic", "I", TCPDUMP_MAGIC_NANO),
		("v_major", "H", PCAP_VERSION_MAJOR),
		("v_minor", "H", PCAP_VERSION_MINOR),
		("thiszone", "I", 0),
		("sigfigs", "I", 0),
		("snaplen", "I", 1500),
		("linktype", "I", 1),
	)


class PcapPktHdr(pypacker.Packet):
	"""pcap packet header."""
	# header length: 16
	__hdr__ = (
		("tv_sec", "I", 0),
		# this can be either microseconds or nanoseconds: check magic number
		("tv_usec", "I", 0),
		("caplen", "I", 0),
		("len", "I", 0),
	)


# Pcap magic to config:
# magic : (ts_resolution, unpack_ts, pack_ts)
MAGIC__PCAPFILECONFIG = {
	TCPDUMP_MAGIC_MICRO: (1000, unpack_IIII, pack_IIII),
	TCPDUMP_MAGIC_NANO: (1, unpack_IIII, pack_IIII),
	TCPDUMP_MAGIC_MICRO_SWAPPED: (1000, unpack_IIII_le, pack_IIII_le),
	TCPDUMP_MAGIC_NANO_SWAPPED: (1, unpack_IIII_le, pack_IIII_le)
}

# PCAP callbacks


def pcap_cb_init_write(self, snaplen=1500, linktype=DLT_EN10MB, magic=TCPDUMP_MAGIC_NANO, **initdata):
	# Nanoseconds
	self._timestamp = 0

	# A new pcap file is created
	if self._fh.tell() == 0:
		#logger.debug("Creating new pcap")
		self._resolution_factor, _, self._callback_pack_meta = MAGIC__PCAPFILECONFIG[magic]
		header = PcapFileHdr(magic=magic, snaplen=snaplen, linktype=linktype)

		# BE -> LE
		if magic in [TCPDUMP_MAGIC_MICRO_SWAPPED, TCPDUMP_MAGIC_NANO_SWAPPED]:
			header.v_major = unpack_H_le(pack_H(header.v_major))[0]
			header.v_minor = unpack_H_le(pack_H(header.v_minor))[0]
			header.snaplen = unpack_I_le(pack_I(snaplen))[0]
			header.linktype = unpack_I_le(pack_I(linktype))[0]

		self._fh.write(header.bin())
	# File already present, read config
	else:
		#logger.debug("File already present, reading config and appending to end")
		self._fh.seek(0)
		buf = self._fh.read(24)
		magic = PcapFileHdr(buf).magic

		if magic not in [TCPDUMP_MAGIC_MICRO, TCPDUMP_MAGIC_NANO, TCPDUMP_MAGIC_MICRO_SWAPPED, TCPDUMP_MAGIC_NANO_SWAPPED]:
			raise Exception("Invalid magic: %X" % magic)

		self._resolution_factor, callback_unpack_meta, self._callback_pack_meta = MAGIC__PCAPFILECONFIG[magic]
		# Get last ts in pcap -> read until end
		fhpos = 24
		self._fh.seek(fhpos)
		d = [0, 0, 0, 0]

		while True:
			buf = self._fh.read(16)
			fhpos += 16

			if not buf:
				break

			d = callback_unpack_meta(buf)
			#logger.debug("s=%d, subsec=%d" % (d[0], d[1]))
			fhpos += d[2]
			self._fh.seek(fhpos)

		self._timestamp = d[0] * 1000000000 + (d[1] * self._resolution_factor)
		#logger.debug("Last ts: s=%d, subsec=%d, final=%d" % (d[0], d[1], self._timestamp))


def pcap_cb_write(self, bts, **metadata):
	# Check if "ts" was given when calling write(), otherwise assume 1 us has passed
	# ts = given as ns
	ts = metadata.get("ts", self._timestamp + 1000)
	self._timestamp = ts
	sec = int(ts // 1000000000)
	# ns -> [ns | us]
	subsec = int((ts - (sec * 1000000000)) / self._resolution_factor)

	# logger.debug("packet time sec/subsec: %d/%d", sec, subsec)
	n = len(bts)
	self._fh.write(self._callback_pack_meta(sec, subsec, n, n))
	self._fh.write(bts)


def pcap_cb_init_read(self, **initdata):
	buf = self._fh.read(24)
	# File header is skipped per default (needed for __next__)
	self._fh.seek(24)
	fhdr = PcapFileHdr(buf)

	if fhdr.magic not in [TCPDUMP_MAGIC_MICRO, TCPDUMP_MAGIC_NANO, TCPDUMP_MAGIC_MICRO_SWAPPED,
		TCPDUMP_MAGIC_NANO_SWAPPED]:
		return False

	is_le = False if fhdr.magic in [TCPDUMP_MAGIC_MICRO, TCPDUMP_MAGIC_NANO] else True

	#logger.debug("Pcap magic: %X, le: %s" % (fhdr.magic, is_le))
	# Handle file types
	# Note: we could use PcapPktHdr/PcapLEPktHdr to parse pre-packetdata but calling unpack directly
	# greatly improves performance
	self._resolution_factor, self._callback_unpack_meta, _ = MAGIC__PCAPFILECONFIG[fhdr.magic]
	linktype = fhdr.linktype if not is_le else unpack_I_le(pack_I(fhdr.linktype))[0]
	self._lowest_layer_new = PCAPTYPE_CLASS.get(linktype, None)
	return True


def pcap_cb_read(self):
	buf = self._fh.read(16)

	if not buf:
		raise StopIteration

	d = self._callback_unpack_meta(buf)
	buf = self._fh.read(d[2])

	# return as ns: sec->ns + [us*1000 | ns]
	return d[0] * 1000000000 + (d[1] * self._resolution_factor), buf


def pcap_cb_btstopkt(self, meta, bts):
	return self._lowest_layer_new(bts)


FILETYPE_PCAP	= 0
# TODO: add pcapng support:
# - Interface name can be stored. Handy if capturing on >1 interfaces
#FILETYPE_PCAPNG	= 1

# type_id : [
#	cb_init_write(obj, **initdata),
#	cb_write(self, bytes, **metadata),
#	cb_init_read(obj, **initdata),
#	cb_read(self): metadata, bytes
#	cb_btstopkt(self, metadata, bytes): pkt
# ]
FILEHANDLER = {
	FILETYPE_PCAP: [
		pcap_cb_init_write, pcap_cb_write, pcap_cb_init_read, pcap_cb_read, pcap_cb_btstopkt
	],
}


class FileHandler(object):
	def __init__(self, filename, accessmode):
		self._fh = open(filename, accessmode)
		self._closed = False

	def __enter__(self):
		return self

	def __exit__(self, objtype, value, traceback):
		self.close()

	def flush(self):
		self._fh.flush()

	def close(self):
		self._closed = True
		self._fh.close()


class Writer(FileHandler):
	"""
	Simple pcap writer supporting pcap format.
	"""
	def __init__(self, filename, filetype=FILETYPE_PCAP, append=False, **initdata):
		if append:
			super().__init__(filename, "a+b")
		else:
			super().__init__(filename, "wb")

		callbacks = FILEHANDLER[filetype]
		callbacks[0](self, **initdata)
		self.write = types.MethodType(callbacks[1], self)


class Reader(FileHandler):
	"""
	Simple pcap file reader supporting pcap format.
	"""
	def __init__(self, filename, filetype=FILETYPE_PCAP, **initdata):
		super().__init__(filename, "rb")

		callbacks = FILEHANDLER[filetype]
		ismatch = False

		for pcaptype, callbacks in FILEHANDLER.items():
			self._fh.seek(0)
			# init callback
			ismatch = callbacks[2](self, **initdata)

			if ismatch:
				#logger.debug("found handler for file: %x", pcaptype)
				# Read callback
				self.__next__ = types.MethodType(callbacks[3], self)
				# Bytes-to-packet callback
				self._btstopkt = types.MethodType(callbacks[4], self)
				break
		if not ismatch:
			raise Exception("No matching handler found")

	def read_packet(self, pktfilter=lambda pkt: True):
		"""
		pktfilter -- filter as lambda function to match packets to be retrieved,
			return True to accept a specific packet.
		return -- (metadata, packet) if packet can be created from bytes
			else (metadata, bytes). For pcap/tcpdump metadata is a nanoseconds timestamp
		"""
		while True:
			# until StopIteration
			meta, bts = self.__next__()

			try:
				pkt = self._btstopkt(meta, bts)
			except Exception as ex:
				logger.warning("could not create packets from bytes: %r", ex)
				return meta, bts

			if pktfilter(pkt):
				return meta, pkt

	def read_packet_iter(self, pktfilter=lambda pkt: True):
		"""
		pktfilter -- filter as lambda function to match packets to be retrieved,
			return True to accept a specific packet.
		return -- iterator yielding (metadata, packet)
		"""
		if self._closed:
			return

		while True:
			try:
				yield self.read_packet(pktfilter=pktfilter)
			except:
				return

	def __iter__(self):
		"""
		return -- (metadata, bytes)
		"""
		if self._closed:
			return

		while True:
			try:
				yield self.__next__()
			except StopIteration:
				break

	def read(self):
		"""
		Get all packets as list.
		limit -- Maximum amount of
		return -- [(ts, bts), ...]
		"""
		return [(ts, bts) for ts, bts in self]


def merge_pcaps(pcap_filenames_in, pcap_filename_out, filter_accept=lambda bts: True, linktype=DLT_EN10MB):
	"""
	Merge multiple pcap files.
	pcap_filenames_in -- List of pcap filenames to be merged
	pcap_filename_out -- The final merged pcap file
	filter -- A callback "lambda bts: [True|False]" for filtering packets. True = merge packet to output file.
	linktype -- Linktype for pcap_filename_out
	"""
	fp_out = Writer(filename=pcap_filename_out, linktype=linktype)

	for pcap_filename_in in pcap_filenames_in:
		fp_in = Reader(filename=pcap_filename_in)
		cnt = 1
		try:
			for _, bts in fp_in:
				if filter_accept(bts):
					fp_out.write(bts)
				cnt += 1
		except Exception as ex:
			logger.warning("Terminated reading %s at packet %d" % (pcap_filename_in, cnt))
			logger.exception(ex)
		fp_in.close()
	fp_out.close()
