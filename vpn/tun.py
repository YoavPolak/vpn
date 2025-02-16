import os
from fcntl import ioctl
import struct
import subprocess
import time


# Some constants from Linux kernel header if_tun.h
UNIX_TUNSETIFF = 0x400454ca
UNIX_IFF_TUN = 0x0001
UNIX_IFF_NO_PI = 0x1000


class Device:
    def __init__(self, name, addr: str) -> None:
        self.name = name
        self.addr = addr

        self._ftun = None

    def up(self) -> None:
        self._ftun = create_vnet_device(self.name)
        set_addr(self.name, self.addr)

    def read(self, n: int=1500) -> bytes:
        """
        Args:
            n: bytes to read.
        """
        return os.read(self._ftun, n)

    def write(self, data: bytes) -> None:
        os.write(self._ftun, data)


def create_vnet_device(name: str) -> int:
    """Creates TUN (virtual network) device.

    Returns:
        file descriptor used to read/write to device.
    """
    make_if_req = struct.pack('16sH', name.encode('ascii'),
                              UNIX_IFF_TUN | UNIX_IFF_NO_PI)
    fid = os.open('/dev/net/tun', os.O_RDWR)
    ioctl(fid, UNIX_TUNSETIFF, make_if_req)
    return fid


def set_addr(dev_name: str, addr: str) -> None:
    """Associate address with TUN device using subprocess."""
    # Bring up the network interface (dev_name)
    subprocess.check_call(f'ifconfig {dev_name} up', shell=True)
    print(f'{dev_name} brought up successfully.')

    # Assign IP to the interface with /24 subnet
    subprocess.check_call(f'ifconfig {dev_name} {addr} netmask 255.255.255.0 up', shell=True) #maybe change it to peer to peer
    print(f'{dev_name} configured with IP {addr}/24 and brought up successfully.')


# def setup_point_to_point(tun_device: str, local_ip: str, remote_ip: str):
#     """Set up a point-to-point connection by assigning IP addresses."""
#     subprocess.check_call(f'ifconfig {dev_name} up', shell=True)
#     subprocess.check_call(f'ifconfig {tun_device} {local_ip} pointopoint {remote_ip} up', shell=True)
# # Device 1: local IP 192.168.100.1, remote IP 192.168.100.2
# ifconfig tun0 192.168.100.1 pointopoint 192.168.100.2 up

# # Device 2: local IP 192.168.100.2, remote IP 192.168.100.1
# ifconfig tun0 192.168.100.2 pointopoint 192.168.100.1 up



def test_tun_device():
    tun_name = "tun0"
    tun_ip = "192.168.100.1"  # Ensure this IP is not already assigned

    print(f"Creating and bringing up TUN device: {tun_name}")
    device = Device(tun_name, tun_ip)
    device.up()

    # Wait for the device to be fully up and IP address to be assigned
    time.sleep(2)

    print(f"Setting IP address for {tun_name}: {tun_ip}")
    set_addr(tun_name, tun_ip)  # Set the address (this should not conflict now)

    # Wait to allow the data to be processed
    time.sleep(1)

    while True:
        # Read data from the device
        print(f"Reading data from {tun_name}")
        read_data = device.read(1500)

        # Show the raw read data for debugging
        print(f"Raw Read data: {IP(read_data)}")

    # Clean up: Closing the TUN device (optional)
    print("Test completed.")

# Run the test
# if __name__ == "__main__":
#     test_tun_device()

