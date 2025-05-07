import threading
from . import udp_server, secure_tcp_server
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    udp_thread = threading.Thread(target=udp_server.main, name="UDPServerThread")
    tcp_thread = threading.Thread(target=secure_tcp_server.main, name="SecureTCPServerThread")

    udp_thread.start()
    tcp_thread.start()

    udp_thread.join()
    tcp_thread.join()
    print("shut down")
if __name__ == "__main__":
    main()

#TODO change name for things, add comments and gui shit messages