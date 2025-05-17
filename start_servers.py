import threading
from servers.vpn_server import vpn_server
from servers.handshake_server import handshake_server

import urllib3
import os
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    os.system("bash ./tools/setup_server_nat.sh")
    udp_thread = threading.Thread(target=vpn_server.main, name="UDPServerThread")
    tcp_thread = threading.Thread(target=handshake_server.main, name="SecureTCPServerThread")

    udp_thread.start()
    tcp_thread.start()

    udp_thread.join()
    tcp_thread.join()
    print("shut down")
if __name__ == "__main__":
    main()