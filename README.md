# TCP-Three-Way-Handshake-Implementation-Client-Side-
The client was implemented using raw sockets in C++, providing low-level control over packet creation and transmission. Unlike standard socket programming, raw sockets bypass the operating system’s transport layer handling, enabling manual specification of TCP header fields such as sequence numbers, flags, and checksums.

About the code:

This client.cpp program implements a TCP client that performs a 3-way handshake
 with a server using raw sockets, manually constructing IP and TCP headers. 
 This low-level approach demonstrates how TCP connections are established at the network protocol level.

 Prereqisites:

- Operating System: macOS or Linux (raw sockets require a Unix-like system)
- Compiler: g++ or clang++
- Root privileges (required to send raw packets)

COMPILATION:
bash
g++ client.cpp -o client -std=c++11

EXECUTION:

1. Run the Server
In one terminal window, start the server to listen for incoming SYN packets:
bash:
  sudo make run-server
 2. Run the Client
In another terminal window, initiate the TCP handshake from the client side
bash:
 sudo make run-client


