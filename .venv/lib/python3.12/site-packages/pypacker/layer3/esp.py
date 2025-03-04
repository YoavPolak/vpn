# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""Encapsulated Security Protocol."""

from pypacker import pypacker


class ESP(pypacker.Packet):
	__hdr__ = (
		("spi", "I", 0),
		("seq", "I", 0)
	)
