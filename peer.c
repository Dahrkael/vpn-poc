#include "common.h"

// peer represents one endpoint of a VPN connection (both client or server)
// combines a network connection to another peer and a local tunnel device

// remote peer keeps the local state associated with other non-local peers

#define DEFAULT_BUFFER_SIZE 1400

typedef enum {
    PS_Disconnected = 0,
    PS_Handshaking,
    PS_Connected
} PeerState;

struct remote_peer_t;
typedef struct remote_peer_t RemotePeer;

struct remote_peer_t {
    uint8_t id;
    PeerState state;
    struct sockaddr_storage address;
    uint32_t buffer_size;
    uint8_t* recv_buffer;
    uint8_t* send_buffer;

    // linked list members
    RemotePeer* prev;
    RemotePeer* next;
};

typedef struct {
    VPNMode mode;
    Tunnel tunnel;
    Socket socket;

    uint8_t* recv_buffer;
    uint8_t* send_buffer;
    RemotePeer* remote_peers;
} Peer;

RemotePeer* remotepeer_create(const uint32_t buffer_size)
{
    RemotePeer* peer = (RemotePeer*)malloc(sizeof(RemotePeer));
    if (!peer)
        return NULL;

    memset(peer, 0, sizeof(RemotePeer));

    peer->buffer_size = buffer_size;
    peer->recv_buffer = (uint8_t*)malloc(buffer_size);
    peer->send_buffer = (uint8_t*)malloc(buffer_size);
    if (!peer->recv_buffer || !peer->send_buffer)
    {
        free(peer->recv_buffer);
        free(peer->send_buffer);
        free(peer);
        peer = NULL;
    }

    return peer;
}

void remotepeer_destroy(RemotePeer* peer)
{
    if (!peer)
        return;

    // delete buffers
    if (peer->recv_buffer)
        free(peer->recv_buffer);
     if (peer->send_buffer)
        free(peer->send_buffer);

    // remove the peer from the list
    if (peer->prev)
        peer->prev->next = peer->next;

    // delete the peer
    free(peer);
    peer = NULL;
}

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
        RemotePeer* next = remote_peer->next;
        remotepeer_destroy(remote_peer);
        remote_peer = next;
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

    tunnel_set_mtu(&peer->tunnel, DEFAULT_BUFFER_SIZE);

    return true;
}

bool peer_initialize(Peer* peer, const StartupOptions* options)
{
    if (!peer || !options || options->mode == VPNMode_None)
        return false;

    
    if (!peer_initialize2(peer, options->mode, &options->address, options->interface))
        return false;

    if (peer->mode == VPNMode_Server)
    {
        if (!socket_bind(&peer->socket, &options->address))
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

bool peer_connect(Peer* peer, const struct sockaddr_storage* address)
{
    if (!peer || !address)
        return false;

    if (peer->mode != VPNMode_Client)
    {
        printf_debug("%s: trying to connect from a non-client peer\n", __func__);
        return false;
    }

    if (peer->remote_peers)
    {
        printf("%s: peer already has a remote peer assigned\n", __func__);
        return false;
    }

    // connect the socket here in case the address changes
    if (!socket_connect(&peer->socket, address))
        return false;

    // create a remote peer representing the server
    RemotePeer* remote_peer = remotepeer_create(DEFAULT_BUFFER_SIZE);
    assert(remote_peer);

    remote_peer->state = PS_Handshaking;
    remote_peer->address = *address;

    // first and only remote peer in the client list
    peer->remote_peers = remote_peer;
    return true;
}

bool peer_service_client(Peer* peer)
{
    uint8_t recv_buffer[DEFAULT_BUFFER_SIZE];
    uint8_t send_buffer[DEFAULT_BUFFER_SIZE];
    do {
        // read incoming data from the socket
        struct sockaddr_storage remote;
        uint32_t read = DEFAULT_BUFFER_SIZE;
        SocketResult ret = socket_receive(&peer->socket, recv_buffer, &read, &remote);
        if (ret == SR_Error)
            return false;
        if (ret == SR_Pending)
            break; // no more data to read
        if (ret == SR_Success)
        {
            printf_debug("socket received %u bytes\n", read);
            if (!tunnel_write(&peer->tunnel, recv_buffer, read))
                return false;
        }
    } while(true);

    do {
        // read outgoing data from the tunnel
        uint32_t read = DEFAULT_BUFFER_SIZE;
        if (!tunnel_read(&peer->tunnel, send_buffer, &read))
            break; // no more data to read
        // send tunnel data through the socket
        if (read > 0)
        {
            printf_debug("tunnel received %u bytes\n", read);
            uint32_t sent = read;
            if (!socket_send(&peer->socket, send_buffer, &sent, &peer->remote_peers->address))
                return false;
            assert(read == sent);
        }
    } while(true);
    
    
    return true;
}

bool peer_service_server(Peer* peer)
{
    return true;
}

bool peer_service(Peer* peer)
{
    if (!peer)
        return false;

    if (peer->mode == VPNMode_Client)
        return peer_service_client(peer);

    if (peer->mode  == VPNMode_Server)
        return peer_service_server(peer);
    
    return false;
}