#include "peer.h"

MsgType protocol_get_type(const uint8_t* buffer, const uint32_t length)
{
    if (length < sizeof(MsgHeader))
        return MT_Invalid;

    MsgType type = ((MsgHeader*)buffer)->type;
    if (type < MT_Invalid || type > MT_Data)
        return MT_Invalid;

    return type;
}

uint32_t protocol_max_payload(Peer* peer)
{
    assert(peer);
    return peer->buffer_size - sizeof(MsgHeader);
}

// placeholder
bool protocol_compress(Peer* peer, uint8_t* buffer, uint32_t* length)
{
    (void) peer; (void) buffer; (void) length;
    return true;
}

// placeholder
bool protocol_uncompress(Peer* peer, uint8_t* buffer, uint32_t* length)
{
    (void) peer; (void) buffer; (void) length;
    return true;
}

// placeholder
bool protocol_encrypt(RemotePeer* remote, uint8_t* buffer, uint32_t* length)
{
    (void) remote; (void) buffer; (void) length;
    //if (remote->cipher)
        //remote->cipher->encrypt(remote->key, buffer, length);
    return true; 
}

// placeholder
bool protocol_decrypt(RemotePeer* remote, uint8_t* buffer, uint32_t* length)
{
    (void) remote; (void) buffer; (void) length;
    //if (remote->cipher)
        //remote->cipher->decrypt(remote->key, buffer, length);
    return true; 
}

bool protocol_handshake_client(Peer* peer, RemotePeer* remote)
{
    // TODO
    return true;
}

bool protocol_handshake_server(Peer* peer, RemotePeer* remote)
{
    // TODO
    return true;
}

// message originating on both client and server
bool protocol_reconnect_request(Peer* peer, RemotePeer* remote)
{
    MsgReconnect message;
    message.header.type = MT_Reconnect;
    message.id = remote->id;
    message.secret = remote->secret;
    memcpy(peer->send_buffer, &message, sizeof(MsgReconnect));

    uint32_t sent = sizeof(MsgReconnect);
    if (!socket_send(&peer->socket, peer->send_buffer, &sent, &remote->address))
        return false;

    return sent == sizeof(MsgReconnect);
}

// client message received on the server
bool protocol_reconnect_client(Peer* peer, struct sockaddr_storage* remote, const uint32_t length)
{
    if (length < sizeof(MsgReconnect))
        return false;

    MsgReconnect* message = (MsgReconnect*)peer->recv_buffer;

    // find a matching peer entry to update its address
    bool found = false;
    RemotePeer* remote_peer = peer->remote_peers;
    while(remote_peer)
    {
        if ((remote_peer->id == message->id) && (remote_peer->secret == message->secret))
        {
            remote_peer->address = *remote;
            remote_peer->secret = rand();
            found = true;
            break;
        }
        remote_peer = peer->remote_peers->next;
    }

    // if updated send an acknowledgement
    if (found)
        return protocol_reconnect_request(peer, remote_peer);

    return true; // non-fatal server side
}

// server message received on the client
bool protocol_reconnect_server(Peer* peer, RemotePeer* remote, const uint32_t length)
{
    if (length < sizeof(MsgReconnect))
        return false;

    MsgReconnect* message = (MsgReconnect*)peer->recv_buffer;
    // set the id if not set yet
    if (remote->id == 0)
        remote->id = message->id;

    // update the secret always
    if (remote->id == message->id)
        remote->secret = message->secret;

    return true;
}

bool protocol_data_send(Peer* peer, RemotePeer* remote, const uint32_t length)
{
    if (length == 0)
        return true;

    // add the header at the beginning of the buffer
    MsgHeader* header = (MsgHeader*)peer->send_buffer;
    memset(header, 0, sizeof(MsgHeader));
    header->type = MT_Data;

    uint32_t sent = length;
    if (!socket_send(&peer->socket, peer->send_buffer, &sent, &remote->address))
        return false;

    assert(length == sent); // TODO manage this

    // clear buffer after sending for privacy
    // memset(peer->send_buffer, 0, peer->buffer_size;

    return true;
}

bool protocol_data_receive(Peer* peer, RemotePeer* remote, const uint32_t length)
{
    if (length == 0)
        return false;

    // skip the header at the beginning of the buffer
    const uint8_t* data = peer->send_buffer + sizeof(MsgHeader);
    const uint32_t data_length = length - sizeof(MsgHeader);

    // TODO server NAT

    if (!tunnel_write(&peer->tunnel, data, data_length))
        return false;
    
    return true;
}