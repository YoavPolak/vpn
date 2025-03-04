# Copyright 2013, Michael Stahn
# Use of this source code is governed by a GPLv2-style license that can be
# found in the LICENSE file.
"""
Utility functions, primarily written for Linux based OS.
"""
import subprocess
import re
import os
import logging
import math
import ipaddress
import collections

from pypacker import pypacker as pypacker


logger = logging.getLogger("pypacker")

try:
	import netifaces
except ImportError:
	logger.warning("Couldn't load netifaces, some utils won't work")

log = math.log
mac_bytes_to_str = pypacker.mac_bytes_to_str


def switch_wlan_channel(iface, channel, shutdown_prior=False):
	"""
	Switch wlan channel to channel.
	Requirements: ifconfig, iwconfig

	iface -- interface name
	channel -- channel numer to be set as number
	shutdown_prior -- shut down interface prior to setting channel
	"""
	if shutdown_prior:
		cmd_call = ["ifconfig", iface, "down"]
		subprocess.check_call(cmd_call)

	cmd_call = ["iwconfig", iface, "channel", "%d" % channel]
	subprocess.check_call(cmd_call)

	if shutdown_prior:
		cmd_call = ["ifconfig", iface, "up"]
		subprocess.check_call(cmd_call)


WLAN_MODE_MANAGED	= 0
WLAN_MODE_MONITOR	= 1
WLAN_MODE_UNKNOWN	= 2

_MODE_STR_INT_TRANSLATE = {
	b"managed": WLAN_MODE_MANAGED,
	b"monitor": WLAN_MODE_MONITOR,
	b"": WLAN_MODE_UNKNOWN
}

PATTERN_MODE	= re.compile(br"Mode:(\w+) ")


def get_wlan_mode(iface):
	"""
	return -- [MODE_MANAGED | MODE_MONITOR | MODE_UNKNOWN]
	"""
	cmd_call = ["iwconfig", iface]
	output = subprocess.check_output(cmd_call)
	match = PATTERN_MODE.search(output)

	found_str = match.group(1).lower()
	return _MODE_STR_INT_TRANSLATE.get(found_str, WLAN_MODE_UNKNOWN)


def is_interface_up(iface):
	"""
	return -- [True | False]
	"""
	cmd_call = ["ifconfig"]
	pattern_up = re.compile(b"^" + bytes(iface, "UTF-8") + b": flags=", re.MULTILINE)
	output = subprocess.check_output(cmd_call)
	return pattern_up.search(output) is not None


def set_interface_mode(iface, monitor_active=None, mtu=None, state_active=None):
	"""
	Configure an interface, primarily for wifi monitor mode
	Requirements: ifconfig, iwconfig

	monitor_active -- activate/deactivate monitor mode (only for wlan interfaces)
	state_active -- set interface state
	"""
	initial_state_up = is_interface_up(iface)

	if monitor_active is not None:
		cmd_call = ["ifconfig", iface, "down"]
		subprocess.check_call(cmd_call)
		mode = "monitor" if monitor_active else "managed"
		cmd_call = ["iwconfig", iface, "mode", mode]
		subprocess.check_call(cmd_call)

	if type(mtu) is int:
		cmd_call = ["ifconfig", iface, "mtu", "%d" % mtu]
		subprocess.check_call(cmd_call)

	# try:
	#	cmd_call = ["iwconfig", iface, "retry", "0"]
	#	subprocess.check_call(cmd_call)
	#	# we don't need retry but this can improve performance
	# except:
	#	# not implemented: don't care
	#	pass

	if state_active or initial_state_up:
		cmd_call = ["ifconfig", iface, "up"]
		subprocess.check_call(cmd_call)


def is_interface_present(iface_name):
	try:
		netifaces.ifaddresses(iface_name)
		return True
	except ValueError:
		# Raised if interface is not present
		return False


def set_interface_state(iface_name, state_active=True):
	state_str = "up" if state_active else "down"
	output = subprocess.getoutput("ip link set dev %s %s" % (iface_name, state_str))
	logger.info(output)


PROG_CHANNEL = re.compile(br"Channel ([\d]+) :")


def get_available_wlan_channels(iface):
	"""
	Requirements: iwlist

	return -- channels as integer list
	"""
	cmd_call = ["iwlist", iface, "channel"]
	output = subprocess.check_output(cmd_call)
	# logger.debug("iwlist output: %r", output)

	return [int(ch) for ch in PROG_CHANNEL.findall(output)]


def set_ethernet_address(iface, ethernet_addr):
	"""
	iface -- interface name
	ethernet_addr -- Ethernet address like "AA:BB:CC:DD:EE:FF"
	"""
	initial_state_up = is_interface_up(iface)
	cmd_call = ["ifconfig", iface, "down"]
	subprocess.check_call(cmd_call)
	cmd_call = ["ifconfig", iface, "hw", "ether", ethernet_addr]
	subprocess.check_call(cmd_call)

	if initial_state_up:
		cmd_call = ["ifconfig", iface, "up"]
		subprocess.check_call(cmd_call)

MAC_VENDOR = {}
PROG_MACVENDOR = re.compile(r"([\w\-]{8,8})   \(hex\)\t\t(.+)")
PROG_MACVENDOR_STRIPPED = re.compile(r"(.{6,6}) (.+)")

current_dir = os.path.dirname(os.path.realpath(__file__)) + "/"

FILE_OUI = current_dir + "oui.txt"
FILE_OUI_STRIPPED = current_dir + "oui_stripped.txt"


def _convert():
	"""
	Convert oui file
	return -- True on success, False otherwise
	"""
	# logger.debug("loading oui file %s", FILE_OUI)

	try:
		with open(FILE_OUI, "r") as fh_read:
			for line in fh_read:
				hex_vendor = PROG_MACVENDOR.findall(line)

				if len(hex_vendor) > 0:
					# print(hex_vendor)
					MAC_VENDOR[hex_vendor[0][0].replace("-", "")] = hex_vendor[0][1]
	except:
		# logger.debug("no oui file present -> nothing to convert")
		return False

	try:
		with open(FILE_OUI_STRIPPED, "w") as fh_write:
			for mac, descr in MAC_VENDOR.items():
				fh_write.write("%s %s\n" % (mac, descr))
	except Exception as ex:
		logger.warning("could not create stripped oui file %r", ex)
		return False
	return True


def _load_mac_vendor():
	"""
	Load oui.txt containing mac->vendor mappings into MAC_VENDOR dictionary.
	See http://standards.ieee.org/develop/regauth/oui/oui.txt
	"""
	if not os.path.isfile(FILE_OUI_STRIPPED):
		success = False

		if os.path.isfile(FILE_OUI):
			success = _convert()

		if not success:
			return

	# logger.debug("loading stripped oui file %s", FILE_OUI_STRIPPED)

	try:
		with open(FILE_OUI_STRIPPED, "r") as fh_read:
			for line in fh_read:
				hex_vendor = PROG_MACVENDOR_STRIPPED.findall(line)

				if len(hex_vendor) > 0:
					# print(hex_vendor)
					MAC_VENDOR[hex_vendor[0][0]] = hex_vendor[0][1]
		# logger.debug("got %d vendor entries", len(MAC_VENDOR))
	except Exception as ex:
		logger.warning("could not load stripped oui file %r", ex)


def get_vendor_for_mac(mac):
	"""
	mac -- First three bytes of mac address at minimum eg "AA:BB:CC...", "AABBCC..." or
		byte representation b"\xaa\xbb\xcc\xdd\xee\xff"
	return -- found vendor string or empty string
	"""
	if len(MAC_VENDOR) == 1:
		return ""

	if len(MAC_VENDOR) == 0:
		_load_mac_vendor()
		# avoid loading next time
		if len(MAC_VENDOR) == 0:
			MAC_VENDOR["test"] = "test"

	if type(mac) == bytes:
		# b"\xaa\xbb\xcc\xdd\xee\xff" -> AA:BB:CC:DD:EE:FF -> AABBCC"
		mac = pypacker.mac_bytes_to_str(mac)[0:8].replace(":", "")
	else:
		# AA:BB:CC -> AABBCC
		mac = str.upper(mac.replace(":", "")[0:6])

	#logger.debug("searching mac %s", mac)
	return MAC_VENDOR.get(mac, "")


def is_special_mac(mac_str):
	"""
	Check if this is a special MAC adress (not a client address). Every MAC not found
	in the official OUI database is assumed to be non-client.

	mac_str -- Uppercase mac string like "AA:BB:CC[:DD:EE:FF]", first 3 MAC-bytes are enough
	"""
	return len(get_vendor_for_mac(mac_str)) == 0


ENTROPY_GRANULARITY_QUADRUPLE	= 0


def calculate_entropy(elements, granularity_bytes=0, blocksize_bytes=64, log_base=2):
	"""
	Calcualte entropy of elements

	elements -- list of elements (each of same length) or a string
	granularity_bytes -- amount of bytes from which entropy has to be calculated
	blocksize_bytes -- if elements is a string: size of the block which is splittet in granularity_bytes
		long strings to calculate the entropy
	return -- entropy or None on error
	"""
	if len(elements) == 0:
		return None

	if type(elements) != list:
		# Only strings allowed
		if type(elements) not in [str, bytes] or granularity_bytes > blocksize_bytes:
			return None
		# Get entropy of a string using a blocksize of blocksize_bytes and granularity of granularity_bytes
		# Example with blocksize_bytes=4, granularity_bytes=1:
		# "12345678" -> "1234", "5678" -> E("1", "2", "3", "4"), E("5", "6", "7", "8")
		# Change default parameter
		if granularity_bytes == 0:
			granularity_bytes = 1
		entropies = []

		for off1 in range(0, len(elements), blocksize_bytes):
			block = elements[off1: off1 + blocksize_bytes]
			#print(block)
			tokens = [block[off2: off2 + granularity_bytes] for off2 in range(0, len(block), granularity_bytes)]
			#print(tokens)
			entropy_block = calculate_entropy(tokens)
			#print(entropy_block)
			entropies.append(entropy_block)
			#time.sleep(60)
		return entropies
	elif granularity_bytes != 0:
		# Get Entropy of subsets of bytes of elements: ["1234", "5678"] -> [E("1", "5", ...), ...]
		element_len = len(elements[0])
		entropies = []

		for off in range(0, element_len, granularity_bytes):
			elements_part = []

			for element in elements:
				elements_part.append(element[off: off + granularity_bytes])
			entropy_part = calculate_entropy(elements_part)
			entropies.append(entropy_part)
		return entropies

	symbol_count = collections.defaultdict(lambda: 0)

	for element in elements:
		# Faster than using exceptions
		symbol_count[element] += 1

	#print(symbol_count)
	entropy = 0
	symbols_total = sum(val for _, val in symbol_count.items())

	for _, count in symbol_count.items():
		p = count / symbols_total
		entropy += log(p, log_base) * p

	return abs(entropy)


def get_mac_for_iface(iface_name):
	"""
	return -- MAC address of the interface iface_name
	Assume MAC address is always retrievable
	"""
	try:
		return netifaces.ifaddresses(iface_name)[netifaces.AF_LINK][0]["addr"]
	except:
		return None


def get_ip_addressinfo(iface_name, version=4, idx=0):
	"""
	iface_name -- Name of the interface to get the information from
	version -- 4 for IPv4, 6 for IPv6
	idx -- Index to the n'th element in the address-info list (useful if multiple IP addresses are assigned)
	return -- Adressinfo (IP address, mask, broadcast address) for the given interface name
		like ("1.2.3.4", "255.255.255.0", "192.168.0.255") or None on error
	"""
	version_id = netifaces.AF_INET if version == 4 else netifaces.AF_INET6

	try:
		addressinfo = netifaces.ifaddresses(iface_name)[version_id][idx]
		# Honor no broadcast for IPv6
		return addressinfo["addr"], addressinfo["netmask"], addressinfo.get("broadcast", None)
	except:
		return None


def nwmask_to_cidr(nmask):
	"""
	TODO: Detect if IPv4 or IPv6
	nmask -- An IPv4 network mask like "255.255.255.0"
	return -- The amount of network bits in CIDR format like 24
	"""
	return ipaddress.IPv4Network("1.2.3.4/%s" % nmask, strict=False).prefixlen


def get_gwip_for_iface(iface_name, version=4):
	"""
	iface_name -- Name of the interface to get the information from
	version -- 4 for IPv4, 6 for IPv6
	return -- IP address of the default gateway like "1.2.3.4" for interface iface_name or None
	"""
	version_id = netifaces.AF_INET if version == 4 else netifaces.AF_INET6
	gws_ip = netifaces.gateways().get(version_id, None)

	if gws_ip is None:
		return None
	gw_result = None

	for gw_info in gws_ip:
		if iface_name in gw_info:
			gw_result = gw_info[0]
			break
	return gw_result


def get_arp_cache_entry(ipaddr):
	"""
	return -- MAC address for IP addess like "1.2.3.4"
	"""
	mac = None
	pattern_mac = re.compile("([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})")

	with open("/proc/net/arp", "r") as fd:
		for line in fd:
			if line.startswith(ipaddr + " "):
				mac = pattern_mac.search(line).group(0)
				break
	return mac


def add_arp_entry(ip_address, mac_address, interface_name):
	"""
	Add an arp entry using linux "arp" command.
	"""
	cmd_call = ["arp", "-s", ip_address, "-i", interface_name, mac_address]
	subprocess.check_call(cmd_call)


def flush_arp_cache():
	"""
	Remove all arp entries from cache using linux "ip" command.
	"""
	cmd_call = ["ip", "-s", "neigh", "flush", "all"]
	subprocess.check_call(cmd_call)
