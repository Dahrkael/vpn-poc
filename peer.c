#include "peer.h"

RemotePeer* remotepeer_create()
{
    RemotePeer* peer = (RemotePeer*)malloc(sizeof(RemotePeer));
    if (!peer)
        return NULL;

    memset(peer, 0, sizeof(RemotePeer));
    return peer;
}

void remotepeer_destroy(RemotePeer* peer)
{
    if (!peer)
        return;

    // remove the peer from the list
    if (peer->prev)
        peer->prev->next = peer->next;

    // delete the peer
    free(peer);
    peer = NULL;
}

Peer* peer_create(const uint32_t buffer_size)
{
    Peer* peer = (Peer*)malloc(sizeof(Peer));
    if (!peer)
        return NULL;

    memset(peer, 0, sizeof(Peer));
    socket_clear(&peer->socket);

    // include the header size to compose messages directly in the buffers
    peer->buffer_size = buffer_size > 0 ? buffer_size : DEFAULT_BUFFER_SIZE;
    peer->buffer_size += sizeof(MsgHeader);

    peer->recv_buffer = (uint8_t*)malloc(peer->buffer_size);
    peer->send_buffer = (uint8_t*)malloc(peer->buffer_size);
    if (!peer->recv_buffer || !peer->send_buffer)
    {
        free(peer->recv_buffer);
        free(peer->send_buffer);
        free(peer);
        peer = NULL;
    }

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

    // delete buffers
    if (peer->recv_buffer)
        free(peer->recv_buffer);
     if (peer->send_buffer)
        free(peer->send_buffer);

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

RemotePeer* peer_find_remote(Peer* peer, struct sockaddr_storage* address)
{
    // this should be a hashmap lookup or a binary search
    RemotePeer* remote = peer->remote_peers;
    while(remote)
    {
        bool same = !memcmp(&remote->address, address, sizeof(struct sockaddr_storage));
        if (same)
            return remote;
    }

    return NULL;
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

    // set the tunnel mtu to just enough for the payload with no headers
    tunnel_set_mtu(&peer->tunnel, protocol_max_payload(peer));

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
    RemotePeer* remote_peer = remotepeer_create();
    assert(remote_peer);

    remote_peer->state = PS_Handshaking;
    remote_peer->address = *address;

    // first and only remote peer in the client list
    peer->remote_peers = remote_peer;
    return true;
}

bool peer_enable(Peer* peer, const bool enabled)
{
    if (!peer || !tunnel_is_valid(&peer->tunnel))
        return false;

    return enabled ? tunnel_up(&peer->tunnel) : tunnel_down(&peer->tunnel);
}

bool peer_service(Peer* peer)
{
    if (!peer)
        return false;

    do {
        // read messages from known and unknown peers
        RemotePeer* remote = NULL;
        struct sockaddr_storage new_remote;
        SocketResult ret = protocol_receive(peer, &remote, &new_remote);

        if (ret == SR_Error)
            return false;

        if (ret == SR_Pending)
            break; // no more data to read

        if (ret == SR_Success)
        {
            // clients cannot receive messages from unknown sources
            assert(remote || peer->mode == VPNMode_Server);

            // this means unpacking the message failed
            if (peer->recv_length == 0)
                continue;

            MsgType type = protocol_get_type(peer->recv_buffer, peer->recv_length);
            if (peer->recv_length < protocol_get_message_size(type))
                continue; // non-fatal, just ignore the message

            bool ok = true;
            if (!remote)
            {
                switch(type)
                {
                case MT_ClientHandshake:
                    ok = protocol_handshake_client(peer, &new_remote);
                    break;
                case MT_ClientReconnect:
                    ok = protocol_reconnect_client(peer, &new_remote);
                    break;
                default:
                    printf("%s: invalid message received from unknown peer\n", __func__);
                    continue; // non-fatal, continue reading
                }
            }
            else
            {
                switch(type)
                {
                case MT_ServerHandshake:
                    ok = protocol_handshake_server(peer, remote);
                    break;
                case MT_ServerReconnect:
                    ok = protocol_reconnect_server(peer, remote);
                    break;
                case MT_Data:
                    protocol_data_receive(peer, remote); // non-fatal
                    break;
                case MT_Ping:
                case MT_Pong:
                    ok = protocol_ping(peer, remote);
                    break;
                default:
                    printf("%s: invalid message received from known peer\n", __func__);
                    continue; // non-fatal, continue reading
                }
            }
            

            if (!ok) return false;
        }
    } while(true);

    do {
        // read outgoing data from the tunnel
        uint32_t read = protocol_max_payload(peer);
        // leave room for the header
        uint8_t* buffer = peer->send_buffer + sizeof(MsgHeader);
        if (!tunnel_read(&peer->tunnel, buffer, &read))
            break; // no more data to read

        // send tunnel data through the socket
         if (!protocol_data_send(peer, peer->remote_peers))
            return false;    
    } while(true);
    
    return true;
}
