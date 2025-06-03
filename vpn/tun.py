import os
import struct
import subprocess
import time
import logging
from typing import Optional

# Constants from Linux kernel header if_tun.h
UNIX_TUNSETIFF = 0x400454ca
UNIX_IFF_TUN = 0x0001
UNIX_IFF_NO_PI = 0x1000

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')


class Device:
    def __init__(self, name: str, addr: str) -> None:
        self.name = name
        self.addr = addr
        self._ftun: Optional[int] = None

    def up(self) -> None:
        """Create TUN device and assign IP using modern 'ip' commands."""
        self._ftun = create_vnet_device(self.name)
        set_addr(self.name, self.addr)

    def read(self, n: int = 1500) -> bytes:
        if self._ftun is None:
            raise RuntimeError("Device not opened")
        return os.read(self._ftun, n)

    def write(self, data: bytes) -> None:
        if self._ftun is None:
            raise RuntimeError("Device not opened")
        os.write(self._ftun, data)

    def fileno(self) -> int:
        if self._ftun is None:
            raise RuntimeError("Device not opened")
        return self._ftun

    def close(self) -> None:
        if self._ftun is not None:
            try:
                os.close(self._ftun)
                logging.info(f"TUN device {self.name} closed.")
                self._ftun = None
            except OSError as e:
                logging.error(f"Failed to close TUN device: {e}")


def create_vnet_device(name: str) -> int:
    """
    Create a TUN device and return the file descriptor.
    """
    ifreq = struct.pack('16sH', name.encode('ascii'), UNIX_IFF_TUN | UNIX_IFF_NO_PI)
    fd = os.open('/dev/net/tun', os.O_RDWR)
    fcntl_ioctl(fd, UNIX_TUNSETIFF, ifreq)
    logging.info(f"Created TUN device: {name}")
    return fd


def fcntl_ioctl(fd: int, request: int, arg) -> None:
    """Wrapper for fcntl.ioctl to avoid import in global scope."""
    import fcntl
    fcntl.ioctl(fd, request, arg)


def netmask_to_prefix(netmask: str) -> int:
    """Convert netmask like '255.255.255.0' to prefix length, e.g., 24."""
    return sum(bin(int(x)).count('1') for x in netmask.split('.'))


def set_addr(dev_name: str, addr: str, netmask: str = "255.255.255.0") -> None:
    """
    Assign IP address and bring interface up using 'ip' command.
    """
    prefix_len = netmask_to_prefix(netmask)
    cidr_addr = f"{addr}/{prefix_len}"

    try:
        # Delete existing IP (if any) to avoid errors
        subprocess.run(["ip", "addr", "flush", "dev", dev_name], check=True)

        # Assign IP address
        subprocess.run(["ip", "addr", "add", cidr_addr, "dev", dev_name], check=True)

        # Bring the interface up
        subprocess.run(["ip", "link", "set", dev_name, "up"], check=True)

        logging.info(f"{dev_name} assigned IP {cidr_addr} and brought up successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to set IP address on {dev_name}: {e}")


def add_split_default_routes(dev_name: str, gateway: str = "10.0.0.1") -> None:
    """
    Add split default routes so most traffic goes via VPN.
    """
    try:
        # Flush existing routes for those subnets to avoid duplicates
        subprocess.run(["ip", "route", "del", "0.0.0.0/1"], check=False)
        subprocess.run(["ip", "route", "del", "128.0.0.0/1"], check=False)

        subprocess.run(
            ["ip", "route", "add", "0.0.0.0/1", "via", gateway, "dev", dev_name],
            check=True,
        )
        subprocess.run(
            ["ip", "route", "add", "128.0.0.0/1", "via", gateway, "dev", dev_name],
            check=True,
        )
        logging.info("Split default routes added successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error adding split default routes: {e}")


def test_tun_device() -> None:
    tun_name = "tun0"
    tun_ip = "192.168.100.1"  # Make sure this IP is free on your network

    logging.info(f"Creating and bringing up TUN device: {tun_name}")
    device = Device(tun_name, tun_ip)
    device.up()

    # Wait a bit for system to configure device
    time.sleep(2)

    # Optionally add split default routes (uncomment if needed)
    # add_split_default_routes(tun_name, gateway="192.168.100.2")

    logging.info("Starting to read packets (Ctrl+C to stop)...")
    try:
        while True:
            packet = device.read(1500)
            logging.debug(f"Read packet: {packet.hex()}")
            # Here you can add packet processing code

    except KeyboardInterrupt:
        logging.info("Interrupted by user, closing device...")

    device.close()
    logging.info("Test completed.")


# Uncomment to run test when this script is executed directly:
# if __name__ == "__main__":
#     test_tun_device()
