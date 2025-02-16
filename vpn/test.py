from pypacker.layer3 import ip


""" IP packet manipulation utilities.

https://tools.ietf.org/html/rfc791#section-3.1

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

from pypacker.layer3.ip import IP
from pypacker.layer3.ip6 import IP6


def packet_version(packet: bytes) -> int:
    return packet[0] >> 4

def parse_packet(data: bytes) -> IP:
    packet_ver = packet_version(data)
    if packet_ver == 4:
        packet = IP(data)
    elif packet_ver == 6:
        packet = IP6(data)
    else:
        raise Exception('Unsupported IP packet version: {packet_ver}')
    return packet
   
def src_addr(packet: bytes) -> str:
   """Extracts src_addr field from IP packet."""
   #return '.'.join([str(n) for n in packet[12:16]])
   return parse_packet(packet).src_s

def set_src_addr(packet: bytearray, src_addr: str) -> None:
   ip = IP(packet)
   ip.src_s = src_addr
   # TODO: find out how to avoid data copying
   for i, b in enumerate(ip.bin()):
      packet[i] = b

def dst_addr(packet: bytes) -> str:
   """Extracts dst_addr field from IP packet."""
   return '.'.join([str(n) for n in packet[16:20]])

def set_dst_addr(packet: bytearray, dst_addr: str) -> None:
   ip = IP(packet)
   ip.dst_s = dst_addr
   # TODO: find out how to avoid data copying
   for i, b in enumerate(ip.bin()):
      packet[i] = b


ipv4_packet = b'\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\xb1\xe6\xc0\xa8\x00\x68\xc0\xa8\x00\x01'
ipv6_packet = b'\x60\x00\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x00\x00\x00' \
              b'\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01' \
              b'\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'

# print(packet_version(packet_data))

#ipv4 tests

# print(packet_version(packet_data))
# print(parse_packet(packet_data))
print(src_addr(ipv6_packet))
bytearray_obj = bytearray(ipv6_packet)
set_src_addr(bytearray_obj, '11::2001:db8:0:1')
bytes_obj = bytes(bytearray_obj)
print(src_addr(bytes_obj))




# ip_packet = ip.IP(packet_data)
# print(dst_addr(packet_data))
# print(parse_packet(ipv6_packet).src_s)  # Access source IP address
# print(ip_packet.dst_s)  # Access destination IP address