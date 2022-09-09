# VPN Proof of Concept
For full information please refer to the documentation PDF

## Code organization
* **common.h:** like the name implies it contains all the system headers used across the whole project, helper functions and widely used custom types.
* **socket.c:** contains a wrapper for the Berkeley socket API.
* **tunnel.c:** constains functions to abstract the usage of TUN devices.
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

By using the -s (--server) parameter with an optional bind address, the program will start in Server mode and listen for incoming connections.

By using the -c (--connect) parameter with a server address, the program will start in Client mode and try to establish a connection with the specified server.

Tunnel address, network mask and mtu can be specified using -a, -m and -l. The TUN  device name can be specified using -i (--interface). The MTU of both peers need to be the same or data will be lost. 

--persist option is not fully implemented so please ignore it.

Using the --debug option two Peer instances (one Client and one Server) will be created in the same process, each one with its own TUN device (ddgs and ddgc), both connected through localhost. This allows for quick debugging of the internal workings but it is hard to set proper rules for this setup to use as a general VPN.

