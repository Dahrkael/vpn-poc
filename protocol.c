#include "peer.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

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

bool protocol_get_destination(const uint8_t* buffer, const uint32_t length, struct sockaddr_storage* destination)
{
    struct iphdr* header4 = (struct iphdr*)buffer;
    if (length < sizeof(struct iphdr) && length < (uint32_t)(header4->ihl << 2))
        return false;

    if (header4->version == 6)
    {
        struct ip6_hdr* header6 = (struct ip6_hdr*)buffer;
        struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)destination;
        ipv6->sin6_addr = header6->ip6_dst;
        destination->ss_family = AF_INET6;
    }
    else if (header4->version == 4)
    {
        struct sockaddr_in* ipv4 = (struct sockaddr_in*)destination;
        ipv4->sin_addr.s_addr = header4->daddr;
        destination->ss_family = AF_INET;
    }
    else
    {
        assert("invalid ip version");
        return false;
    }

    return true;
}

void protocol_compute_ip_checksum(struct iphdr* ip_header)
{
    ip_header->check = 0;

    uint16_t* addr = (uint16_t*)ip_header;
    uint32_t count = ip_header->ihl << 2;
    register uint64_t sum = 0;
    while (count > 1) 
    {
        sum += *addr++;
        count -= 2;
    }
    
    // padding
    if (count > 0)
        sum += ((*addr) & htons(0xFF00));
    
    // folding
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    
    sum = ~sum;
    ip_header->check = (uint16_t)sum;
}

void protocol_compute_tcp_checksum(struct iphdr* ip_header, uint16_t* payload)
{
    register uint64_t sum = 0;
    uint16_t tcp_length = ntohs(ip_header->tot_len) - (ip_header->ihl << 2);
    struct tcphdr* tcp_header = (struct tcphdr*)payload;
    
    // tcp pseudoheader
    // source ip
    sum += (ip_header->saddr >> 16) & 0xFFFF;
    sum += (ip_header->saddr) & 0xFFFF;
    //destination ip
    sum += (ip_header->daddr >> 16) & 0xFFFF;
    sum += (ip_header->daddr) & 0xFFFF;
    // protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    // length
    sum += htons(tcp_length);
 
    tcp_header->check = 0;
    while (tcp_length > 1) 
    {
        sum += * payload++;
        tcp_length -= 2;
    }

    // padding
    if (tcp_length > 0) 
        sum += ((*payload) & htons(0xFF00));

    // folding
    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    sum = ~sum;
    tcp_header->check = (uint16_t)sum;
}

void protocol_compute_udp_checksum(struct iphdr* ip_header, uint16_t* payload)
{
    (void)ip_header;
    struct udphdr *udp_header = (struct udphdr*)payload;
    udp_header->check = 0; // udp checksum is optional
}
void protocol_recompute_packet_checksums(const uint8_t* buffer, const uint32_t length)
{
    (void)length;
    struct iphdr* header = (struct iphdr*)buffer;
    // recompute the ip header
    protocol_compute_ip_checksum(header);
    
    uint16_t* payload = (uint16_t*)(buffer + (header->ihl << 2));
    switch(header->protocol)
    {
    case IPPROTO_TCP:
        protocol_compute_tcp_checksum(header, payload);
        break;
    case IPPROTO_UDP:
        protocol_compute_udp_checksum(header, payload);
        break;
    default:
        break;
    }
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

bool protocol_replace_address(uint8_t* buffer, const uint32_t length, const struct sockaddr_storage* address, const bool origin)
{
    assert(buffer);
    assert(address);

    uint8_t address_version = 0;
    switch(address->ss_family)
    {
        case AF_INET: address_version = 4; break;
        case AF_INET6: address_version = 6; break;
        default: return false; // discard non-IP packets
    }

    // discard the packet if its not big enough
    if (address_version == 4 && length < sizeof(struct iphdr))
        return false;
    else if (address_version == 6 && length < sizeof(struct ip6_hdr))
        return false;
    
    struct iphdr* header4 = (struct iphdr*)buffer;
    struct ip6_hdr* header6 = (struct ip6_hdr*)buffer;

    if (address_version != header4->version)
    {
        printf_debug("%s: address is IPv%u but packet is IPv%u\n", __func__, address_version, header4->version);
        return false;
    }

    struct sockaddr_in* address4 = (struct sockaddr_in*)address;
    struct sockaddr_in6* address6 = (struct sockaddr_in6*)address;
    
    if (origin) // outgoing -> change source
    {
        if (address_version == 6)
            header6->ip6_src = address6->sin6_addr;
        else
            header4->saddr = address4->sin_addr.s_addr;
    }
    else // incoming -> change destination
    {
        if (address_version == 6 )
            header6->ip6_dst = address6->sin6_addr;
        else
            header4->daddr = address4->sin_addr.s_addr;
    }

    protocol_recompute_packet_checksums(buffer, length);
    
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
    if (!socket_send(&peer->socket, peer->send_buffer, &sent, &remote->real_address))
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
        *remote = peer_find_remote(peer, &address, true);
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
            remote_peer->real_address = *remote;
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
    printf("%s: new connection from %s\n", __func__, remote_text);

    MsgHandshake* message = (MsgHandshake*)peer->recv_buffer;

    // protocol and version have to match
    if (message->protocol != PROTOCOL_ID)
        return true;
    if (message->version != PROTOCOL_VERSION)
        return true;

    // TODO temporal failsafe
    if (peer->next_id >= peer->total_ids)
    {
        printf("%s: client IDs exhausted! restart the server to accept more\n", __func__);
        return true;
    }

     // create a remote peer representing the new client
    RemotePeer* new_peer = remotepeer_create();
    assert(new_peer);

    new_peer->id = peer->next_id++;
    new_peer->secret = rand();

    new_peer->state = PS_Connected;
    new_peer->real_address = *remote;
    new_peer->last_recv_time = get_current_timestamp();
    //new_peer->cipher = ;
    //new_peer->key = ;

    // create a fake vpn address based on the id (TODO ipV4 only)
    new_peer->vpn_address = peer->tunnel_address_block;
    struct sockaddr_in* ipv4 = (struct sockaddr_in*)&new_peer->vpn_address;
    uint8_t* last_octet = ((uint8_t*)&ipv4->sin_addr.s_addr) + 3;
    *last_octet = new_peer->id;

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

    char vpn_text[256];
    address_to_string(&new_peer->vpn_address, vpn_text, sizeof(vpn_text));
    printf("%s: peer %u (%s) accepted from %s\n", __func__, new_peer->id, vpn_text, remote_text);

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
    address_to_string(&remote->real_address, remote_text, sizeof(remote_text));
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
    address_to_string(&remote->real_address, remote_text, sizeof(remote_text));
    printf("disconnection (reason %u) from %s\n", message->reason, remote_text);

    // mark as disconnected and remove it in peer_check_connections()
    remote->state = PS_Disconnected;

    return true;
}

bool protocol_data_send(Peer* peer, RemotePeer* remote)
{
    if (peer->send_length == 0)
        return true;

    return protocol_send(peer, remote, MT_Data);
}

bool protocol_data_receive(Peer* peer, RemotePeer* remote)
{
    // skip the header at the beginning of the buffer
    uint8_t* data = peer->recv_buffer + sizeof(MsgHeader);
    const uint32_t data_length = peer->recv_length - sizeof(MsgHeader);

    // NAT
    if (peer->mode == VPNMode_Server)
    {
        // replace the tunnel remote address with the fake vpn address
        // so it can figure out where to send the responses later
        struct sockaddr_storage* source = &remote->vpn_address;
        if (!protocol_replace_address(data, data_length, source, true))
            return false;
    }
    else
    {
        if (!protocol_replace_address(data, data_length, &peer->tunnel_local_address, false))
           return false;
    }
        

    if (!tunnel_write(&peer->tunnel, data, data_length))
        return false;
    
    return true;
}
