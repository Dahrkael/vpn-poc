# VPN Proof of Concept
This project shows the basics of how to create VPN software from scratch for Linux in C using just the standard APIs and the iptables utility. Code is simple and easy to follow on purpose, with comments here and there hinting whats going on.

The same program can act as server or client, creating the appropiate TUN devices and forwarding the traffic through them. While the current architecture is a standard Client-Server one, the code doesn't do a lot of assumptions (both are just Peers) so it can be modified to become a full p2p node to create mesh networks.
To add some spiciness the protocol supports Peers changing their source address via *reconnect* messages by sharing their id and a secret.

Currently the code does not compress nor encrypt the traffic, although functions and logic are in place for that they are just placeholders (as they are out of scope).


## Code organization
* **common.h:** like the name implies it contains all the system headers used across the whole project, helper functions and widely used custom types.
* **socket.c:** contains a wrapper for the Berkeley socket API.
* **tunnel.c:** contains functions to abstract the usage of TUN devices.
* **peer.c:** contains an abstraction for the VPN endpoints and functions to manage it.
* **protocol.c:** branched off peer.c it contains the functions specific to the custom network protocol used between peers.
* **peer.h:** since peer.c and protocol.c use types and functions from eachother I had to  move the common stuff to this header.
* **main.c:** entrypoint of the program, just parses the arguments and setups the peers.
* **compile.c:** the only compilation unit the compiler needs to get a working executable.

There are also shell scripts to help with compilation and setting up the forwarding rules.

## Configuration and usage
The VPN program requires elevated privileges as it makes use of multiple restricted devices and APIs. Modifying the routes and firewall rules also requires elevated privileges.
### Compilation
Make sure **GCC** is installed (no other dependencies!) and execute the *compile.sh* script in the repository. This will generate a **vpn-poc** executable ready to use.
To enable or disable debug logs modify the *DEBUG* define in *compile.c*.
### Usage
Usage of the program can be seen by executing it with no parameters or looking at the show_help() method in main.c.

By using the **-s (--server)** parameter with an optional bind address, the program will start in Server mode and listen for incoming connections.

By using the **-c (--connect)** parameter with a server address, the program will start in Client mode and try to establish a connection with the specified server.

Tunnel address, network mask and mtu can be specified using -a, -m and -l. The TUN  device name can be specified using -i (--interface). The MTU of both peers need to be the same or data will be lost. 

**--persist** option is not fully implemented so please ignore it.

Using the **--debug** option two Peer instances (one Client and one Server) will be created in the same process, each one with its own TUN device (vpns and vpnc), both connected through localhost. This allows for quick debugging of the internal workings but it is hard to set proper rules for this setup to use as a general VPN. 

This way the program will:

• Capture all outgoing packets on the client side 

• Do all the client processing as normal (encryption, compression, etc)

• Send the data through a loopback socket to the server side

• Do all the server processing as normal (decryption, uncompression, etc) 

• Dump the packets into the gateway interface

### Testing
By default the interfaces names are "vpns" for the server and "vpnc" for the client.

While the program is running make sure the routes are properly setup to go through the vpn interface. 

Using the traceroute utility it should show that indeed packets flow through the program tunnel’s IP addresses. Perform standard internet connectivity tests, like pinging multiple addresses or accessing websites. This approach makes sure everything works under perfect conditions. 

To test real WAN conditions the **netem** module available since Linux 2.6 can be used to emulate things like delays, packet loss or reordering. To test the server and client on separate computers the approach is the same, just running the program with the apropiate flags on each computer and perform the same test steps. Wireshark can be used to monitor all interfaces and make sure data is flowing. Also it’s I/O Graphs can be used to measure the throughput achieved by the program in terms of bandwidth and packet rate.