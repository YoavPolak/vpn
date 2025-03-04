```markdown
# Setup Commands

This document contains the setup commands for various components of the system, including the **Central Server**, **VPN Server**, **VPN Client**, and instructions for **Testing VPN Connectivity**.

---

## **Central Server**

To start the **Central Server**, navigate to the server directory and run the `uvicorn` command to launch the server with automatic reloading:

```bash
cd ./central_server
uvicorn central_server:app --reload
```

- **Explanation**: The `cd ./central_server` command navigates to the directory where the server code is located. The `uvicorn` command starts the FastAPI application with `--reload` to automatically reload the server when you make changes to the code.

---

## **VPN Server**

To start the **VPN Server**, run the following command with `sudo` privileges:

```bash
sudo python3 -m tests.test_server
```

- **Explanation**: The `sudo python3 -m tests.test_server` command runs the `test_server` module from the `tests` folder. The `sudo` ensures the command is executed with elevated privileges, which may be required to manage networking and VPN operations.

---

## **VPN Client**

To start the **VPN Client**, execute the following command:

```bash
sudo python3 -m tests.test_client
```

- **Explanation**: Similar to the VPN server, this command launches the `test_client` module from the `tests` folder, which will configure and initiate the VPN client. Again, `sudo` is required for the necessary permissions.

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
```