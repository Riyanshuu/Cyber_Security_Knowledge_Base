## The OSI Model

The **Open System Interconnection** Model also known as ISO-OSI reference model. Developed by International Organization of Standardization (ISO). Describes flow of information from one computer to another. Consist of seven layers.

- OSI is a logical model just to define a communication between two devices. This model enables devices from different vendors to communicate with each other.
- This model contains seven layers in which each layer has its own specific functions.
- When data comes down to the layer, each layer adds some information to PDU (Protocols Data Unit). This process is called encapsulation.

## ****Layers of OSI Model****

1. Physical Layer - data cables , cat6 , etc.
2. Data Link Layer - switching , MAC addresses
3. Network Layer - IP addresses , routing
4. Transport Layer - TCP/UDP
5. Session Layer - session management
6. Presentation Layer - WMV , JPEG , MOV
7. Application Layer - HTTP , SMTP

**Application Layer** - Prepares data to be sent over the network. This is the layer where a user interacts with the application.

**Presentation Layer** - It takes many types of data from the application layer and presents it into a network acceptable format (file extension checking). Other functions are encryption and decryption, compression and decompression, etc.

**Session Layer** - A connection for a time period to perform a particular task whenever a client initiates a connection with a server, a program at server end called session manager creates a session id for that connection and allocates hardware resources.

**Transport Layer** - Maintain end-to-end connectivity between two applications. This layer ensures guaranteed data delivery between two processes. This layer uses the concept of logical ports to uniquely identify an application layer. There are two types of protocols being used at this layer:

1. TCP (Transmission Control Protocol) ; secure
2. UDP (User Datagram Protocol) ; unsecure

Ad Info: Total number of ports - 65535

- Well-known ports - 0 to 1023
- Registered ports - 1024 to 49151
- Dynamic ports - 49152 to 65535 (Registered ports & Dynamic ports are unfixed ports.)

**Network Layer** - Maintain end-to-end connectivity between two end systems. This layer defines all the functions used to get data from one port of network to another port of network. For example: IP IPX.

**Data Link Layer** - Maintain system-to-system connectivity within a network. This layer defines how to present data into media. Mainly classified into two:

1. LLC (Logical Link Control) or CRC (Cyclic Redundancy Check)
2. MAC (Media Access Control) ; 48 bits

- 24 bits > OUI (Organization Unique Identifier)
- 24 bits > company

**Physical Layer** - Actual data transfer is prefined at this layer. It transmits raw bit streams over the physical medium. This layer converts bits into signals.

# OSI Layer Attacks
| Layers | Attacks |
| --- | --- |
| Application Layer | Exploit |
| Presentation Layer  | Phishing |
| Session Layer | Hijacking |
| Transport Layer  | Reconnaissance |
| Network Layer  | Man-in-the-Middle Attack |
| Data Link Layer | Spoofing |
| Physical Layer  | Sniffing |

![OSI Layers, Functions, Protocols, Attacks, and Mitigations_page-0001](https://user-images.githubusercontent.com/68123282/176388155-c32a0719-b04e-4eeb-b036-9d621a9043b2.jpg)
