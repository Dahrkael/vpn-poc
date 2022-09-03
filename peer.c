#include "common.h"

// peer represents one endpoint of a VPN connection (both client or server)
// combines a network connection to another peer and a local tunnel device

typedef enum {
    PS_Disconnected,
    PS_Handshaking,
    PS_Connected
} PeerState;

struct remote_peer_t;
typedef struct remote_peer_t RemotePeer;

struct remote_peer_t {
    uint8_t id;
    PeerState state;
    uint32_t buffer_size;
    uint8_t* recv_buffer;
    uint8_t* send_buffer;
    RemotePeer* next;
};

typedef struct {
    VPNMode mode;
    Tunnel tunnel;
    Socket socket;
    RemotePeer* remote_peers;
} Peer;


Peer* peer_create()
{
    Peer* peer = (Peer*)malloc(sizeof(Peer));
    if (!peer)
        return NULL;

    memset(peer, 0, sizeof(Peer));
    socket_clear(&peer->socket);
    return peer;
}

void peer_destroy(Peer* peer)
{
    if (!peer)
        return;

    // shut down socket
    socket_close(&peer->socket);
    // shut down tunnel
    tunnel_down(&peer->tunnel);
    tunnel_close(&peer->tunnel);

    // delete remote peer list
    RemotePeer* remote_peer = peer->remote_peers;
    while(remote_peer)
    {
        // delete buffers
        if (remote_peer->recv_buffer)
            free(remote_peer->recv_buffer);
        if (remote_peer->send_buffer)
            free(remote_peer->send_buffer);

        remote_peer = remote_peer->next;
    }

    // delete the peer
    free(peer);
    peer = NULL;
}

bool peer_initialize2(Peer* peer, const VPNMode mode, const struct sockaddr_storage* address, const char* interface)
{
    if (!peer)
        return false;

    peer->mode = mode;

     // create an apropiate socket
    if (!socket_open(&peer->socket, address->ss_family == AF_INET6, true))
        return false;

    // mark sent packets as 'DDG' for later use in routing
    if (!socket_set_mark(&peer->socket, 0x00000DD6))
        return false;

    // create the requested tunnel
    if (!tunnel_open(&peer->tunnel, interface ))
        return false;

    return true;
}

bool peer_initialize(Peer* peer, const StartupOptions* options)
{
    if (!peer || !options || options->mode == VPNMode_None)
        return false;

    
    if (!peer_initialize2(peer, options->mode, &options->address, options->interface))
        return false;

    
    // bind allows incoming packets from unknown addresses
    if (peer->mode == VPNMode_Server)
    {
        if (!socket_bind(&peer->socket, &options->address))
            return false;
    }
    // connect only allows incoming/outgoing packets from/to the specified address
    if (peer->mode == VPNMode_Client)
    {
        if (!socket_connect(&peer->socket, &options->address))
            return false;
    }

    // set default or specified local and remote addresses
    struct sockaddr_storage address;
    memcpy(&address, &options->tunnel_address, sizeof(options->tunnel_address));
    if (address.ss_family == AF_UNSPEC)
    {
        const char* default_tunnel_address = "10.9.8.0";
        address.ss_family = AF_INET;
        ((struct sockaddr_in*)&address)->sin_addr.s_addr = inet_addr(default_tunnel_address);
    }

    if (!tunnel_set_addresses(&peer->tunnel, &address))
        return false;

    // set default or specified network mask
    struct sockaddr_storage netmask;
    memcpy(&netmask, &options->tunnel_netmask, sizeof(options->tunnel_netmask));
    if (netmask.ss_family == AF_UNSPEC)
    {
        const char* default_tunnel_netmask = "255.255.255.0";
        netmask.ss_family = AF_INET;
        ((struct sockaddr_in*)&netmask)->sin_addr.s_addr = inet_addr(default_tunnel_netmask);
    }

    if (!tunnel_set_network_mask(&peer->tunnel, &netmask))
        return false;

    return true;
}
