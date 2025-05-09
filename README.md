
# Setup Commands

This document contains the setup commands for various components of the system, including the **Central Server**, **VPN Server**, **VPN Client**, and instructions for **Testing VPN Connectivity**.

---

## **Central Server**

To start the **Central Server**, navigate to the server directory and run the `uvicorn` command to launch the server with automatic reloading:

```bash
cd ./servers/central_server
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
uvicorn central_server:app --host 0.0.0.0 --port 8443 --ssl-keyfile=key.pem --ssl-certfile=cert.pem
```

- **Explanation**: The `cd ./servers/central_server` command navigates to the directory where the server code is located. The `uvicorn` command starts the FastAPI application with `--reload` to automatically reload the server when you make changes to the code.

---

## **VPN Server**

To start the **VPN Servers**, run the following command with `sudo` privileges:

```bash
sudo $(which python3) -m start_servers
```

- **Explanation**: The `sudo $(which python3) -m start_servers` command runs the `start_servers` module from the `project root` folder. The `sudo` ensures the command is executed with elevated privileges, which may be required to manage networking and VPN operations.

---

## **VPN Client**

To start the **VPN Client**, execute the following command:

```bash
sudo $(which python3) -m client.app.main
```

- **Explanation**: Similar to the VPN servers, this command launches the `main` module from the `client/app` folder, which will configure and initiate the VPN client. Again, `sudo` is required for the necessary permissions.

---

## **Test VPN Connectivity**

To test the VPN connection, use the following command to ping a remote server via the `tun1` interface:

```bash
ping -I tun1 google.com
```

- **Explanation**: The `ping -I tun1 google.com` command sends a ping request through the `tun1` interface (typically used for VPN connections) to `google.com`. This helps verify that the VPN connection is active and that you can access external websites through the VPN.

---

## Conclusion

These commands will help you set up and test the central server, VPN server, VPN client, and VPN connectivity. Be sure to follow each step carefully and ensure you have the necessary permissions to run commands with `sudo`.


---
```bash
sudo ip route add default dev tun1` Need to do it after the tun is built
```

# Project documentation

projoect-root/
├── README.md
├── requirements.txt
├── client/
│   ├── app/
│   │   ├── gui.py
│   │   └── main.py
│   └── core/
│       ├── handshake_client.py
│       └── vpn_client.py
├── database/
│   ├── session_data.db
│   └── session_db.py
├── servers/
│   ├── central_server/
│   │   ├── central_server.py
│   │   ├── cert.pem
│   │   ├── key.pem
│   │   └── users.db
│   ├── handshake_server/
│   │   └── handshake_server.py
│   └── vpn_server/
│       └── vpn_server.py
├── start_servers.py
|
├── tools/
│   ├── setup_client_nat.sh
│   └── setup_server_nat.sh
├── utils/
│   ├── encryption_methods.py
│   └── valid_ip.py
└── vpn/
    ├── __init__.py
    ├── ip.py
    ├── logs.py
    ├── net.py
    ├── protocol/
    │   ├── hmac_utils.py
    │   └── vpn_protocol.py
    └── tun.py

```
┌──────────────────────┐                        ┌──────────────────────┐
│      VPN Client      │                        │      VPN Server      │
│                      │                        │                      │
│  ┌───────────────┐   │  TCP: Handshake        |   ┌───────────────┐  │
│  │ RSA + AES Key │◄──────────────────────────────►│ RSA + AES Key │  │
│  └───────────────┘   │                        |   └───────────────┘  │
│         ▲            │                        |          ▲           │
│         │ AES Key    │                        |          │ AES Key   │
│         ▼            │                        |          ▼           │
│  ┌───────────────┐   │   UDP: Encrypted VPN   |   ┌───────────────┐  |
│  │   UDP Socket  │◄──────────────────────────────►│   UDP Socket  │  |
│  └───────────────┘   │       Data Packets     |   └───────────────┘  |
│         ▲            │                        |          ▲           │
│         │            │                        |          │           │
│  ┌───────────────┐   │                        │   ┌───────────────┐  |
│  │   TUN Device  │◄──────────────────────────────►│   TUN Device  │  |
│  └───────────────┘   │                        │   └───────────────┘  |
└──────────────────────┘                        └──────────────────────┘
```