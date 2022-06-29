# TCP 3-Way Handshake

**Three-Way Handshake** or a TCP 3-way handshake is a process which is used in a TCP/IP network to make a connection between the server and client. It is a three-step process that requires both the client and server to exchange synchronization and acknowledgment packets before the real data communication process starts.

TCP Handshake takes place on layer 4 - **Transport Layer**

Three-way handshake process is designed in such a way that both ends help you to initiate, negotiate, and separate TCP socket connections at the same time. It allows you to transfer multiple TCP socket connections in both directions at the same time.

# **TCP message types**

| Message | Description |
| --- | --- |
| SYN | Used to initiate and establish a connection. It also helps you to synchronize sequence numbers between devices. |
| ACK | Helps to confirm to the other side that it has received the SYN. |
| SYN-ACK | SYN message from local device and ACK of the earlier packet. |
| FIN | Used to terminate a connection. |

# **TCP Three-Way Handshake Process**

TCP traffic begins with a three-way handshake. In this TCP handshake process, a client needs to initiate the conversation by requesting a communication session with the Server:

![092119_0753_TCP3WayHand1](https://user-images.githubusercontent.com/68123282/176364522-019b7424-d3d6-4309-a75d-493d94ff5af6.jpeg)

3 way Handshake Diagram

- **Step 1:** In the first step, ****the client establishes a connection with a server. It sends a segment with SYN and informs the server about the client should start communication, and with what should be its sequence number.
- **Step 2:** In this step **s**erver responds to the client request with SYN-ACK signal set. ACK helps you to signify the response of segment that is received and SYN signifies what sequence number it should able to start with the segments.
- **Step 3:** In this final step, the client acknowledges the response of the Server, and they both create a stable connection will begin the actual data transfer process.

# **Real-world Example**

[092119_0753_TCP3WayHand2.webp](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/b057ad46-7e84-43f0-9934-9bcfd1b95949/092119_0753_TCP3WayHand2.webp)

Here is a simple example of the three-way handshake process that is consists of three steps:

- Host X begins the connection by sending the TCP SYN packet to its host destination. The packets contain a random sequence number (For example, 4321) that indicates the beginning of the sequence numbers for data that the Host X should transmit.
- After that, the Server will receive the packet, and it responds with its sequence number. It’s response also includes the acknowledgment number, that is Host X’s sequence number incremented with 1 (Here, it is 4322).
- Host X responds to the Server by sending the acknowledgment number that is mostly server’s sequence number that is incremented by 1.

After the data transmission process is over, TCP automatically terminates the connection between two separate endpoints.
