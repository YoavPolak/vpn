- **AES-256** is used to encrypt the **application data** (payload) inside the **VPN packet**. This keeps the data secure while it's in transit.
- The **UDP packet** just acts as a transport layer and doesn't encrypt its contents. It simply carries the already encrypted **VPN packet** (which includes the encrypted payload).
- So, **there’s only one AES key** used for encrypting the payload inside the VPN packet, not for the UDP headers.

The **UDP layer** doesn’t handle encryption—it just transmits the encrypted VPN packet.

1. RSA || Diffie Hellman key exchange probably DH
2. verify session key
3. aes key exchange
4. tunneling