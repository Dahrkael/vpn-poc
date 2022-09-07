#include "peer.h"

#define PROTOCOL_ID 0xBEEFCAFE
#define PROTOCOL_VERSION 0x1

MsgType protocol_read_type(const uint8_t* buffer, const uint32_t length)
{
    if (length < sizeof(MsgHeader))
        return MT_Invalid;

    MsgType type = ((MsgHeader*)buffer)->type;
    if (type < MT_Invalid || type > MT_Data)
        return MT_Invalid;

    return type;
}

const char* protocol_get_type_text(MsgType type)
{
    switch(type)
    {
        case MT_Ping: return "Ping";
        case MT_Pong: return "Pong";
        case MT_ClientHandshake: return "Client Handshake";
        case MT_ServerHandshake: return "Server Handshake";
        case MT_ClientReconnect: return "Client Reconnect";
        case MT_ServerReconnect: return "Server Reconnect";
        case MT_Data: return "Data";
        case MT_Disconnect: return "Disconnect";
        case MT_Invalid: return "Invalid";
    }
    return "<Invalid>";
}

uint32_t protocol_get_message_size(const MsgType type)
{
    switch(type)
    {
        case MT_Invalid: 
            return 0;
        case MT_Ping:
        case MT_Pong:
            return sizeof(MsgPing);
        case MT_ClientReconnect:
        case MT_ServerReconnect:
            return sizeof(MsgReconnect);
        case MT_ClientHandshake: 
        case MT_ServerHandshake:
            return sizeof(MsgHandshake);
        case MT_Data: 
            return sizeof(MsgHeader) + 1; // variable size
        case MT_Disconnect:
            return sizeof(MsgDisconnect);
    }
    return 0;
}

uint32_t protocol_max_payload(Peer* peer)
{
    assert(peer);
    return peer->buffer_size - sizeof(MsgHeader);
}

uint32_t protocol_compute_checksum(const uint8_t* buffer, const uint32_t length)
{
    uint32_t a = 1;
    uint32_t b = 0;
    const uint32_t modulo = 65521;

    for(uint32_t i = 0; i < length; i++)
    {
        a = (a + buffer[i]) % modulo;
        b = (b + a) % modulo;
    }
    return (b << 16) | a;
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

bool protocol_send(Peer* peer, RemotePeer* remote, const MsgType type)
{
    // set header data at the beginning of the buffer
    MsgHeader* header = (MsgHeader*)peer->send_buffer;
    memset(header, 0, sizeof(MsgHeader));
    header->type = type;
    // compute the checksum of the buffer *after* the checksum field
    header->checksum = protocol_compute_checksum(peer->send_buffer + sizeof(uint32_t), peer->send_length - sizeof(uint32_t));

    // first compress to get better ratio
    bool ok = protocol_compress(peer, peer->send_buffer, &peer->send_length);
    assert(ok); // compress cannot fail

    // then encrypt
    ok = protocol_encrypt(remote, peer->send_buffer, &peer->send_length);
    assert(ok); // encrypt cannot fail

    uint32_t sent = peer->send_length;
    if (!socket_send(&peer->socket, peer->send_buffer, &sent, &remote->address))
        return false;

    assert(sent == peer->send_length); // TODO manage this

    // clear buffer after sending for privacy
    memset(peer->send_buffer, 0, peer->buffer_size);
    peer->send_length = 0;

    remote->last_send_time = get_current_timestamp();

    return true;
}

// if the remote peer is unknown 'remote' is null and new_remote contains the address
SocketResult protocol_receive(Peer* peer, RemotePeer** remote, struct sockaddr_storage* new_remote)
{
    // read incoming message from the socket
    struct sockaddr_storage address;
    peer->recv_length = peer->buffer_size;
    SocketResult ret = socket_receive(&peer->socket, peer->recv_buffer, &peer->recv_length, &address);

    if (ret == SR_Success)
    {
        // if not found will be NULL
        *remote = peer_find_remote(peer, &address);
        *new_remote = address;

        // first decrypt
        bool decrypted = protocol_decrypt(*remote, peer->recv_buffer, &peer->recv_length);
        // then uncompress if decrypted
        bool uncompressed = decrypted && protocol_uncompress(peer, peer->recv_buffer, &peer->recv_length);

        // check the integrity
        bool valid = false;
        if (uncompressed)
        {
            uint32_t computed = protocol_compute_checksum(peer->recv_buffer + sizeof(uint32_t), peer->recv_length - sizeof(uint32_t));
            uint32_t incoming = ((MsgHeader*)peer->recv_buffer)->checksum;
            valid = (computed == incoming);
        }

        if (!decrypted || !uncompressed || !valid)
        {
            char address_text[256];
            address_to_string(&address, address_text,sizeof(address_text));
            if (!valid)
                printf("%s: checksum failed in message from %s\n", __func__, address_text);
            else
                printf("%s: failed to %s message from %s\n", __func__, decrypted ? "uncompress" : "decrypt", address_text);

            peer->recv_length = 0; // length zero because theres no available data
        }
    }   

    return ret;
}

// message originating on both client and server
bool protocol_reconnect_request(Peer* peer, RemotePeer* remote)
{
    MsgReconnect* message = (MsgReconnect*)peer->send_buffer;
    message->id = remote->id;
    message->secret = remote->secret;

    peer->send_length = sizeof(MsgReconnect);
    MsgType type = (peer->mode == VPNMode_Server ? MT_ServerReconnect : MT_ClientReconnect);
    return protocol_send(peer, remote, type);
}

// client message received on the server
bool protocol_reconnect_client(Peer* peer, struct sockaddr_storage* remote)
{
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
bool protocol_reconnect_server(Peer* peer, RemotePeer* remote)
{
    MsgReconnect* message = (MsgReconnect*)peer->recv_buffer;
    // set the id if not set yet
    if (remote->id == 0)
        remote->id = message->id;

    // update the secret always
    if (remote->id == message->id)
        remote->secret = message->secret;

    return true;
}

// message originating on both client and server
bool protocol_handshake_request(Peer* peer, RemotePeer* remote)
{
    printf_debug("%s: %s id %08X version %u\n", __func__, 
        peer->mode == VPNMode_Server ? "SERVER" : "CLIENT", PROTOCOL_ID, PROTOCOL_VERSION);

    MsgHandshake* message = (MsgHandshake*)peer->send_buffer;
    message->protocol = PROTOCOL_ID;
    message->version = PROTOCOL_VERSION;
    // pure placeholder for illustration purposes
    message->preferred_cipher = 1;
    message->cipher_count = 2;
    message->ciphers[0] = 0xAE5128; // these would be FNV-1a hashes
    message->ciphers[1] = 0xAE5256;

    peer->send_length = sizeof(MsgHandshake);
    MsgType type = (peer->mode == VPNMode_Server ? MT_ServerHandshake : MT_ClientHandshake);
    return protocol_send(peer, remote, type);
}

// client message received on the server
bool protocol_handshake_client(Peer* peer, struct sockaddr_storage* remote)
{
    char remote_text[256];
    address_to_string(remote, remote_text, sizeof(remote_text));
    printf_debug("%s: new connection from %s\n", __func__, remote_text);

    MsgHandshake* message = (MsgHandshake*)peer->recv_buffer;

    // protocol and version have to match
    if (message->protocol != PROTOCOL_ID)
        return true;
    if (message->version != PROTOCOL_VERSION)
        return true;

     // create a remote peer representing the new client
    RemotePeer* new_peer = remotepeer_create();
    assert(new_peer);

    new_peer->id = /*TODO*/99;
    new_peer->secret = rand();

    new_peer->state = PS_Connected;
    new_peer->address = *remote;
    new_peer->last_recv_time = get_current_timestamp();
    //new_peer->cipher = ;
    //new_peer->key = ;

    // place it at the end of the list
    if (!peer->remote_peers)
    {
        peer->remote_peers = new_peer;
    }
    else
    {
        RemotePeer* last = peer->remote_peers;
        while(last && last->next)
            last = last->next;
        last->next = new_peer;
    }

    printf_debug("%s: peer accepted from %s\n", __func__, remote_text);

    // send handshake answer
    if (!protocol_handshake_request(peer, new_peer))
        return false;

    // send reconnect info
    if (!protocol_reconnect_request(peer, new_peer))
        return false;

    return true;
}

// server message received on the client
bool protocol_handshake_server(Peer* peer, RemotePeer* remote)
{
     MsgHandshake* message = (MsgHandshake*)peer->recv_buffer;

    // protocol and version have to match
    if (message->protocol != PROTOCOL_ID)
        return false;
    if (message->version != PROTOCOL_VERSION)
        return false;

    printf_debug("%s: handshake successful\n", __func__);

    // now it can start forwawrding packets
    remote->state = PS_Connected;
    return true;
}

bool protocol_ping_request(Peer* peer, RemotePeer* remote)
{
#if DEBUG
    char remote_text[256];
    address_to_string(&remote->address, remote_text, sizeof(remote_text));
    printf_debug("%s: keep-alive to %s after %lums\n", __func__, remote_text, 
        get_current_timestamp() - remote->last_recv_time);
#endif

    MsgPing* message = (MsgPing*)peer->send_buffer;
    message->send_time = get_current_timestamp();
    message->recv_time = 0;

    peer->send_length = sizeof(MsgPing);
    return protocol_send(peer, remote, MT_Ping);
}

bool protocol_ping(Peer* peer, RemotePeer* remote)
{
    MsgPing* request = (MsgPing*)peer->recv_buffer;

    if (request->header.type == MT_Pong)
    {
        remote->rtt = get_current_timestamp() - request->send_time;
        return true;
    }

    assert(request->header.type == MT_Ping);

#if DEBUG
    char remote_text[256];
    address_to_string(&remote->address, remote_text, sizeof(remote_text));
    printf_debug("%s: keep-alive from %s\n", __func__, remote_text);
#endif
    
    // could just memcpy the request
    MsgPing* response = (MsgPing*)peer->send_buffer;
    response->send_time = request->send_time;
    response->recv_time = get_current_timestamp();

    peer->send_length = sizeof(MsgPing);
    return protocol_send(peer, remote, MT_Pong);
}

// message originating on both client and server
bool protocol_disconnect_request(Peer* peer, RemotePeer* remote)
{
    // mark as disconnected and remove it in peer_check_connections()
    remote->state = PS_Disconnected;

    MsgDisconnect* message = (MsgDisconnect*)peer->send_buffer;
    message->reason = 1; // placeholder

    peer->send_length = sizeof(MsgDisconnect);
    return protocol_send(peer, remote, MT_Disconnect);
}

//  message received on both client and server
bool protocol_disconnect(Peer* peer, RemotePeer* remote)
{
    MsgDisconnect* message = (MsgDisconnect*)peer->recv_buffer;

    char remote_text[256];
    address_to_string(&remote->address, remote_text, sizeof(remote_text));
    printf("disconnection (reason %u) from %s\n", message->reason, remote_text);

    // mark as disconnected and remove it in peer_check_connections()
    remote->state = PS_Disconnected;

    return true;
}

bool protocol_data_send(Peer* peer, RemotePeer* remote)
{
    if (peer->send_length == 0)
        return true;

    // TODO server NAT

    return protocol_send(peer, remote, MT_Data);
}

bool protocol_data_receive(Peer* peer, RemotePeer* remote)
{
    // skip the header at the beginning of the buffer
    const uint8_t* data = peer->recv_buffer + sizeof(MsgHeader);
    const uint32_t data_length = peer->recv_length - sizeof(MsgHeader);

    // TODO server NAT

    if (!tunnel_write(&peer->tunnel, data, data_length))
        return false;
    
    return true;
}
