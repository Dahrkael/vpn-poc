#pragma once

#include "common.h"

// peer represents one endpoint of a VPN connection (both client or server)
// combines a network connection to another peer and a local tunnel device

// remote peer keeps the local state associated with other non-local peers

#define DEFAULT_BUFFER_SIZE 1400
#define DEFAULT_KEEPALIVE_TIMEOUT (2 * 1000)
#define DEFAULT_CONNECTION_TIMEOUT (10 * 1000)
#define DEFAULT_RELIABLE_RETRY (1 * 1000)

/* remote peer data */

typedef enum {
    PS_Disconnected = 0,
    PS_Handshaking,
    PS_Reconnecting,
    PS_Connected
} PeerState;

struct remote_peer_t;
typedef struct remote_peer_t RemotePeer;

struct remote_peer_t {
    uint8_t id;
    PeerState state;
    uint64_t secret; // for reconnection
    struct sockaddr_storage address;
    uint32_t rtt;
    uint64_t last_recv_time;
    uint64_t last_send_time;
    uint64_t last_ping_time;

    // encryption stuff (placeholder)
    void* cipher;
    uint8_t* key;

    // linked list members
    RemotePeer* prev;
    RemotePeer* next;
};

/* peer data */

typedef struct {
    VPNMode mode;
    Tunnel tunnel;
    Socket socket;

    uint32_t buffer_size;
    uint8_t* recv_buffer;
    uint32_t recv_length;
    uint8_t* send_buffer;
    uint32_t send_length;
    RemotePeer* remote_peers;

    struct sockaddr_storage tunnel_local_address; // cache
    struct sockaddr_storage tunnel_remote_address; // cache
} Peer;

RemotePeer* remotepeer_create();
RemotePeer* peer_find_remote(Peer* peer, struct sockaddr_storage* address);

/* protocol data */

typedef enum {
    MT_Invalid = 0,
    MT_Ping,
    MT_Pong,
    MT_ClientHandshake,
    MT_ServerHandshake,
    MT_ClientReconnect,
    MT_ServerReconnect,
    MT_Disconnect,
    MT_Data
} MsgType;

typedef struct {
    uint32_t checksum;
    MsgType type;
} MsgHeader;

// ping acts like a keep-alive
typedef struct {
    MsgHeader header;
    uint64_t send_time;
    uint64_t recv_time;
} MsgPing;

typedef struct {
    MsgHeader header;
    uint32_t protocol;
    uint8_t version;
    uint8_t preferred_cipher;
    uint8_t cipher_count;
    uint32_t ciphers[8];
} MsgHandshake;

typedef struct {
    MsgHeader header;
    uint8_t id;
    uint64_t secret;
} MsgReconnect;

typedef struct {
    MsgHeader header;
    uint8_t reason;
} MsgDisconnect;