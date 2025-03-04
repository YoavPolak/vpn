# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""
Border Gateway Protocol.
"""
import logging

from pypacker import pypacker, triggerlist
from pypacker.structcbs import unpack_H

logger = logging.getLogger("pypacker")

# Border Gateway Protocol 4 - RFC 4271
# Communities Attribute - RFC 1997
# Capabilities - RFC 3392
# Route Refresh - RFC 2918
# Route Reflection - RFC 4456
# Confederations - RFC 3065
# Cease Subcodes - RFC 4486
# NOPEER Community - RFC 3765
# Multiprotocol Extensions - 2858

# Message Types
OPEN				= 1
UPDATE				= 2
NOTIFICATION			= 3
KEEPALIVE			= 4
ROUTE_REFRESH			= 5

# Attribute Types
ORIGIN				= 1
AS_PATH				= 2
NEXT_HOP			= 3
MULTI_EXIT_DISC			= 4
LOCAL_PREF			= 5
ATOMIC_AGGREGATE		= 6
AGGREGATOR			= 7
COMMUNITIES			= 8
ORIGINATOR_ID			= 9
CLUSTER_LIST			= 10
MP_REACH_NLRI			= 14
MP_UNREACH_NLRI			= 15

# Origin Types
ORIGIN_IGP			= 0
ORIGIN_EGP			= 1
INCOMPLETE			= 2

# AS Path Types
AS_SET				= 1
AS_SEQUENCE			= 2
AS_CONFED_SEQUENCE		= 3
AS_CONFED_SET			= 4

# Reserved Communities Types
NO_EXPORT			= 0xFFFFFF01
NO_ADVERTISE			= 0xFFFFFF02
NO_EXPORT_SUBCONFED		= 0xFFFFFF03
NO_PEER				= 0xFFFFFF04

# Common AFI types
AFI_IPV4			= 1
AFI_IPV6			= 2

# Multiprotocol SAFI types
SAFI_UNICAST			= 1
SAFI_MULTICAST			= 2
SAFI_UNICAST_MULTICAST		= 3

# OPEN Message Optional Parameters
AUTHENTICATION			= 1
CAPABILITY			= 2

# Capability Types
CAP_MULTIPROTOCOL		= 1
CAP_ROUTE_REFRESH		= 2

# NOTIFICATION Error Codes
MESSAGE_HEADER_ERROR		= 1
OPEN_MESSAGE_ERROR		= 2
UPDATE_MESSAGE_ERROR		= 3
HOLD_TIMER_EXPIRED		= 4
FSM_ERROR			= 5
CEASE				= 6

# Message Header Error Subcodes
CONNECTION_NOT_SYNCHRONIZED	= 1
BAD_MESSAGE_LENGTH		= 2
BAD_MESSAGE_TYPE		= 3

# OPEN Message Error Subcodes
UNSUPPORTED_VERSION_NUMBER	= 1
BAD_PEER_AS			= 2
BAD_BGP_IDENTIFIER		= 3
UNSUPPORTED_OPTIONAL_PARAMETER	= 4
AUTHENTICATION_FAILURE		= 5
UNACCEPTABLE_HOLD_TIME		= 6
UNSUPPORTED_CAPABILITY		= 7

# UPDATE Message Error Subcodes
MALFORMED_ATTRIBUTE_LIST	= 1
UNRECOGNIZED_ATTRIBUTE		= 2
MISSING_ATTRIBUTE		= 3
ATTRIBUTE_FLAGS_ERROR		= 4
ATTRIBUTE_LENGTH_ERROR		= 5
INVALID_ORIGIN_ATTRIBUTE	= 6
AS_ROUTING_LOOP			= 7
INVALID_NEXT_HOP_ATTRIBUTE	= 8
OPTIONAL_ATTRIBUTE_ERROR	= 9
INVALID_NETWORK_FIELD		= 10
MALFORMED_AS_PATH		= 11

# Cease Error Subcodes
MAX_NUMBER_OF_PREFIXES_REACHED	= 1
ADMINISTRATIVE_SHUTDOWN		= 2
PEER_DECONFIGURED		= 3
ADMINISTRATIVE_RESET		= 4
CONNECTION_REJECTED		= 5
OTHER_CONFIGURATION_CHANGE	= 6
CONNECTION_COLLISION_RESOLUTION	= 7
OUT_OF_RESOURCES		= 8


class BGP(pypacker.Packet):
	__hdr__ = (
		("marker", "16s", b"\xff" * 16),
		("len", "H", 0),
		("type", "B", OPEN)
	)

	def _dissect(self, buf):
		#logger.debug("BGP bytes: %d/%r" % (len(buf), buf))
		htype = buf[18]
		return 19, htype

	class Open(pypacker.Packet):
		__hdr__ = (
			("v", "B", 4),
			("asn", "H", 0),
			("holdtime", "H", 0),
			("identifier", "I", 0),
			("param_len", "B", 0),
			("params", None, triggerlist.TriggerList)
		)

		@staticmethod
		def _dissect_params(buf):
			buflen = len(buf)
			off = 0
			params = []

			while off < buflen:
				plen = buf[off + 2]
				param = BGP.Open.Parameter(buf[off:off + plen])
				params.append(param)
				off += plen
			return params

		def _dissect(self, buf):
			#logger.debug("Parsing Parameter")
			pcount = buf[9]

			if pcount != 0:
				OFF_PARAMS = 10
				self.params(buf[OFF_PARAMS:], BGP.Open._dissect_params)
			return len(buf)

		class Parameter(pypacker.Packet):
			__hdr__ = (
				("type", "B", 0),
				("len", "B", 0)
			)

	class Update(pypacker.Packet):
		__hdr__ = (
			("withdrawnlen", "H", 0),
			("pathlen", "H", 0),
			("wroutes", None, triggerlist.TriggerList),
			("pathattrs", None, triggerlist.TriggerList),
			("anncroutes", None, triggerlist.TriggerList),
		)

		@staticmethod
		def _dissect_wroutes(buf):
			off = 0
			buflen = len(buf)
			wroutes = []

			while off < buflen:
				#logger.debug("bytes for wroutes...")
				rlen = 3 + 0
				route = Route(buf[off: off + rlen])
				wroutes.append(route)
				off += rlen
			return wroutes

		@staticmethod
		def _dissect_pathattrs(buf):
			off = 0
			buflen = len(buf)
			pathattrs = []

			while off < buflen:
				alen = 3 + buf[off + 2]
				attr = BGP.Update.Attribute(buf[off: off + alen])
				pathattrs.append(attr)
				off += alen
			return pathattrs

		@staticmethod
		def _dissect_anncroutes(buf):
			off = 0
			buflen = len(buf)
			anncroutes = []

			while off + 3 <= buflen:
				rlen = 3 + 0
				route = Route(buf[off: off + rlen])
				anncroutes.append(route)
				off += rlen

			return anncroutes

		def _dissect(self, buf):
			off = 4
			off_end = off + unpack_H(buf[:2])[0]
			self.wroutes(buf[off: off_end], BGP.Update._dissect_wroutes)

			off = off_end
			off_end = off + unpack_H(buf[2:4])[0]
			self.pathattrs(buf[off: off_end], BGP.Update._dissect_pathattrs)

			off = off_end
			off_end = len(buf)
			self.anncroutes(buf[off: off_end], BGP.Update._dissect_anncroutes)
			return off_end

		class Attribute(pypacker.Packet):
			__hdr__ = (
				("flags", "B", 0),
				("type", "B", 0),
				("len", "B", 0)
			)

			def __get_o(self):
				return (self.flags >> 7) & 0x1

			def __set_o(self, o):
				self.flags = (self.flags & ~0x80) | ((o & 0x1) << 7)
			optional = property(__get_o, __set_o)

			def __get_t(self):
				return (self.flags >> 6) & 0x1

			def __set_t(self, t):
				self.flags = (self.flags & ~0x40) | ((t & 0x1) << 6)
			transitive = property(__get_t, __set_t)

			def __get_p(self):
				return (self.flags >> 5) & 0x1

			def __set_p(self, p):
				self.flags = (self.flags & ~0x20) | ((p & 0x1) << 5)
			partial = property(__get_p, __set_p)

			def __get_e(self):
				return (self.flags >> 4) & 0x1

			extended_length = property(__get_e)

			def _dissect(self, buf):
				typeid = None

				if len(buf) > 3:
					typeid = buf[2]
				return 3, typeid

			class Origin(pypacker.Packet):
				__hdr__ = (
					("type", "B", ORIGIN_IGP),
				)

			class ASPath(pypacker.Packet):
				__hdr__ = (
					("segments", None, triggerlist.TriggerList),
				)

				@staticmethod
				def _dissect_aspaths(buf):
					off = 0
					buflen = len(buf)
					segments = []

					while off < buflen:
						seglen = buf[off + 2]
						seg = BGP.Attribute.ASPath.ASPathSegment(buf[off + 1:seglen])
						segments.append(seg)
						off += seglen
					return segments

				def _dissect(self, buf):
					self.segments(buf[1:], BGP.Attribute.ASPath._dissect_aspaths)
					return len(buf)

				class ASPathSegment(pypacker.Packet):
					__hdr__ = (
						("type", "B", 0),
						("len", "B", 0)
					)

			class NextHop(pypacker.Packet):
				__hdr__ = (
					("ip", "I", 0),
				)

			class MultiExitDisc(pypacker.Packet):
				__hdr__ = (
					("value", "I", 0),
				)

			class LocalPref(pypacker.Packet):
				__hdr__ = (
					("value", "I", 0),
				)

			class AtomicAggregate(pypacker.Packet):
				pass

			class Aggregator(pypacker.Packet):
				__hdr__ = (
					("asn", "H", 0),
					("ip", "I", 0)
				)

			class OriginatorID(pypacker.Packet):
				__hdr__ = (
					("value", "I", 0),
				)

			class ClusterList(pypacker.Packet):
				pass

			class MPReachNLRI(pypacker.Packet):
				__hdr__ = (
					("afi", "H", AFI_IPV4),
					("safi", "B", SAFI_UNICAST),
				)

			class MPUnreachNLRI(pypacker.Packet):
				__hdr__ = (
					("afi", "H", AFI_IPV4),
					("safi", "B", SAFI_UNICAST),
				)

			class Communitie(pypacker.Packet):
				pass

			__handler__ = {
				ORIGIN: Origin,
				AS_PATH: ASPath,
				NEXT_HOP: NextHop,
				MULTI_EXIT_DISC: MultiExitDisc,
				LOCAL_PREF: LocalPref,
				ATOMIC_AGGREGATE: AtomicAggregate,
				AGGREGATOR: Aggregator,
				COMMUNITIES: Communitie,
				ORIGINATOR_ID: OriginatorID,
				CLUSTER_LIST: ClusterList,
				MP_REACH_NLRI: MPReachNLRI,
				MP_UNREACH_NLRI: MPUnreachNLRI
			}

	class Notification(pypacker.Packet):
		__hdr__ = (
			("code", "B", 0),
			("subcode", "B", 0),
		)

	class Keepalive(pypacker.Packet):
		pass

	class RouteRefresh(pypacker.Packet):
		__hdr__ = (
			("afi", "H", AFI_IPV4),
			("rsvd", "B", 0),
			("safi", "B", SAFI_UNICAST)
		)

	__handler__ = {
		OPEN: Open,
		UPDATE: Update,
		NOTIFICATION: Notification,
		KEEPALIVE: Keepalive,
		ROUTE_REFRESH: RouteRefresh
	}


class Route(pypacker.Packet):
	__hdr__ = (
		("len", "B", 0),
	)
