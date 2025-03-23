- **AES-256** is used to encrypt the **application data** (payload) inside the **VPN packet**. This keeps the data secure while it's in transit.
- The **UDP packet** just acts as a transport layer and doesn't encrypt its contents. It simply carries the already encrypted **VPN packet** (which includes the encrypted payload).
- So, **there’s only one AES key** used for encrypting the payload inside the VPN packet, not for the UDP headers.

The **UDP layer** doesn’t handle encryption—it just transmits the encrypted VPN packet.

1. RSA || Diffie Hellman key exchange probably DH
2. verify session key
3. aes key exchange
4. tunneling

sudo ip route add default dev tun1

When you're experiencing slow performance with your VPN server (such as when curling YouTube), there are several areas you can optimize to improve performance. Here are some key suggestions:

### 1. **Reduce Encryption Overhead**:
   - **AES Key Exchange**: If your server is using RSA encryption to exchange AES keys during the handshake, ensure that this process is efficient. RSA operations (encryption/decryption) are computationally expensive, and the handshake process may be a bottleneck.
     - Use a more efficient key exchange mechanism (e.g., Elliptic Curve Diffie-Hellman (ECDH)) for better performance.
     - Consider reducing the key size for RSA (e.g., 2048-bit or 3072-bit) depending on your security needs.

   - **Optimize AES Encryption**: If you're using AES encryption for each packet, make sure you're using an efficient AES mode like GCM (which is authenticated and efficient). AES-CBC, for instance, has additional overhead, especially when it comes to handling padding and IVs (Initialization Vectors).

     - Ensure you're using hardware acceleration (if available) for AES operations.

### 2. **Network Protocol Optimization**:
   - **UDP Size**: The `recvfrom(1549)` in your code seems like it may be limiting the packet size. This could cause fragmentation, and fragmentation introduces overhead in the network and additional CPU cycles to reassemble the packets. Ensure you're using an optimal packet size (usually 1500 bytes or below for UDP, but depends on your specific network MTU).
   - **Protocol Handling**: The amount of processing you're doing on each packet (e.g., encryption, decryption, verifying tokens, etc.) adds up. Minimizing the amount of processing required per packet can help improve performance. 

### 3. **Optimize the Handshake and Authentication**:
   - **Token Verification**: The token verification process (`verify_auth_token`) involves sending an HTTP request to an external server. This can introduce significant latency, especially if the server is far away or the network is slow. You may consider:
     - **Caching token expiration times**: To avoid sending requests for every connection, cache token expiration times in your database or memory.
     - **Parallelize Authentication**: If you're handling multiple clients, try to ensure that the token verification and RSA decryption do not block other threads.
   
### 4. **Reduce Latency in Handling Data**:
   - **Efficient NAT Handling**: The NAT operations (`_nat.in_`, `_nat.out`) could be adding some latency. Check if these operations can be optimized for faster lookups or avoid unnecessary re-processing of the same packets.
   - **Direct Tunnel Device Access**: Ensure the tunnel device (`tun_device`) is accessed in a way that minimizes blocking operations or redundant data copies. Using `select()` or `poll()` to handle non-blocking I/O might help.

### 5. **Asynchronous Packet Handling**:
   - **Concurrency Improvements**: You're using threads to handle each packet, which can lead to overhead from context switching and memory usage. Consider using an **asynchronous model** or a thread pool (with a fixed number of worker threads). This can reduce the overhead caused by creating a new thread for each packet.
     - Look into using libraries like `asyncio` for non-blocking I/O, or employ a thread pool to limit the number of threads.

### 6. **Optimize Data Transfer**:
   - **Compression**: If the data you're transferring is compressible (such as text), adding compression (like gzip) before encrypting and transmitting can reduce the amount of data to send over the network, potentially improving performance.

   - **Buffering and Packetization**: If you're transmitting many small packets, consider buffering and combining them into larger packets before sending them. This reduces overhead related to multiple UDP datagrams.

### 7. **Reduce Logging/Debugging Overhead**:
   - If you're running with verbose logging (e.g., `logging.debug`), it may slow down packet processing, especially if there's a large number of packets. You might want to disable or reduce the verbosity of logging in production to minimize the overhead.

### 8. **Measure and Profile**:
   - **Profiling**: Use a profiler to identify which part of the code is slowest (e.g., `cProfile`, `line_profiler`). This can help pinpoint specific bottlenecks (e.g., encryption, token verification, packet handling).
   - **Network Latency**: Ensure that the server itself isn't overloaded and that the network connection between the client and the server is stable and fast. This includes checking bandwidth, latency, and packet loss.

---

### Key Steps to Take:
1. **Use efficient encryption (AES-GCM instead of CBC)** and make sure you're using hardware acceleration.
2. **Optimize the token verification** process (cache tokens, avoid HTTP requests for every packet).
3. **Use asynchronous processing** or thread pooling to handle packets more efficiently.
4. **Reduce logging** and debug statements in production.
5. **Profile** your application to identify performance bottlenecks.

If you're looking for specific improvements in encryption and packet handling, I can help you further refine certain areas like AES encryption/decryption, NAT handling, or async processing. Let me know!