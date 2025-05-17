""" IP packet manipulation utilities.

This module contains functions to manipulate IP packets, such as extracting and 
modifying source and destination addresses for both IPv4 and IPv6.

The IP header structure is defined as per RFC 791 (section 3.1):
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 0  |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 4  |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8  |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 12 |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 16 |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 20 |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

from pypacker.layer3.ip import IP  # Import IPv4 packet manipulation class
from pypacker.layer3.ip6 import IP6  # Import IPv6 packet manipulation class


def packet_version(packet: bytes) -> int:
    """
    Extracts the IP version from the packet.

    Args:
        packet: The raw IP packet as bytes.

    Returns:
        int: The version of the IP protocol (4 for IPv4, 6 for IPv6).
    """
    return packet[0] >> 4  # The first 4 bits of the first byte represent the version


def parse_packet(data: bytes) -> IP:
    """
    Parses the raw packet and returns an IP object, either IPv4 or IPv6.

    Args:
        data: The raw IP packet as bytes.

    Returns:
        IP or IP6: An IP object representing either an IPv4 or IPv6 packet.

    Raises:
        Exception: If the IP version is unsupported.
    """
    packet_ver = packet_version(data)
    if packet_ver == 4:
        packet = IP(data)  # Parse as IPv4
    elif packet_ver == 6:
        packet = IP6(data)  # Parse as IPv6
    else:
        raise Exception(f'Unsupported IP packet version: {packet_ver}')
    return packet


def src_addr(packet: bytes) -> str:
    """
    Extracts the source IP address from the IP packet.

    Args:
        packet: The raw IP packet as bytes.

    Returns:
        str: The source IP address as a string.
    """
    return parse_packet(packet).src_s  # Get the source address from the parsed packet


def set_src_addr_ipv6(packet: bytearray, src_addr: str) -> None:
    """
    Sets the source IP address for an IPv6 packet.

    Args:
        packet: The raw IP packet as a bytearray.
        src_addr: The source IP address to set (IPv6 format).
    """
    ip = IP6(packet)  # Parse the packet as IPv6
    ip.src_s = src_addr  # Set the source IP address
    # TODO: find out how to avoid data copying
    for i, b in enumerate(ip.bin()):
        packet[i] = b  # Update the original bytearray with the new source address


def set_src_addr(packet: bytearray, src_addr: str) -> None:
    """
    Sets the source IP address for an IPv4 packet.

    Args:
        packet: The raw IP packet as a bytearray.
        src_addr: The source IP address to set (IPv4 format).
    """
    ip = IP(packet)  # Parse the packet as IPv4
    ip.src_s = src_addr  # Set the source IP address
    # TODO: find out how to avoid data copying
    for i, b in enumerate(ip.bin()):
        packet[i] = b  # Update the original bytearray with the new source address


def dst_addr(packet: bytes) -> str:
    """
    Extracts the destination IP address from the IP packet.

    Args:
        packet: The raw IP packet as bytes.

    Returns:
        str: The destination IP address as a string.
    """
    return parse_packet(packet).dst_s  # Get the destination address from the parsed packet


def set_dst_addr(packet: bytearray, dst_addr: str) -> None:
    """
    Sets the destination IP address for an IPv4 packet.

    Args:
        packet: The raw IP packet as a bytearray.
        dst_addr: The destination IP address to set (IPv4 format).
    """
    ip = IP(packet)  # Parse the packet as IPv4
    ip.dst_s = dst_addr  # Set the destination IP address
    # TODO: find out how to avoid data copying
    for i, b in enumerate(ip.bin()):
        packet[i] = b  # Update the original bytearray with the new destination address


def set_dst_addr_ipv6(packet: bytearray, dst_addr: str) -> None:
    """
    Sets the destination IP address for an IPv6 packet.

    Args:
        packet: The raw IP packet as a bytearray.
        dst_addr: The destination IP address to set (IPv6 format).
    """
    ip = IP6(packet)  # Parse the packet as IPv6
    ip.dst_s = dst_addr  # Set the destination IP address
    # TODO: find out how to avoid data copying
    for i, b in enumerate(ip.bin()):
        packet[i] = b  # Update the original bytearray with the new destination address
