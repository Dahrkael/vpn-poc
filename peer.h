#pragma once

#include "common.h"

// peer represents one endpoint of a VPN connection (both client or server)
// combines a network connection to another peer and a local tunnel device

// remote peer keeps the local state associated with other non-local peers

#define DEFAULT_BUFFER_SIZE 1400

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
    uint8_t* send_buffer;
    RemotePeer* remote_peers;
} Peer;

/* protocol data */

typedef enum {
    MT_Invalid = 0,
    MT_ClientHandshake = 1,
    MT_ServerHandshake,
    MT_Reconnect,
    MT_Data = 5
} MsgType;

typedef struct {
    MsgType type;
    uint32_t checksum; // TODO crc32
} MsgHeader;

typedef struct {
    MsgHeader header;
    uint8_t preferred_cipher;
    uint8_t cipher_count;
    uint32_t ciphers[8];
} MsgHandshake;

typedef struct {
    MsgHeader header;
    uint8_t id;
    uint64_t secret;
} MsgReconnect;