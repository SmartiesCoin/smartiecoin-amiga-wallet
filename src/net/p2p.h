/*
 * Smartiecoin Amiga Wallet - P2P protocol
 * Implements the Bitcoin/Dash/Smartiecoin wire protocol
 */
#ifndef SMT_P2P_H
#define SMT_P2P_H

#include "../types.h"
#include "../chainparams.h"

/* ---- P2P Message Header (24 bytes) ---- */
#define SMT_MSG_HDR_SIZE   24
#define SMT_MSG_CMD_SIZE   12

typedef struct {
    uint8_t magic[4];
    char    command[SMT_MSG_CMD_SIZE];
    uint32_t payload_size;
    uint8_t  checksum[4];
} smt_msg_header_t;

/* ---- Service flags ---- */
#define SMT_NODE_NETWORK        (1ULL << 0)
#define SMT_NODE_BLOOM          (1ULL << 2)
#define SMT_NODE_COMPACT_FILTERS (1ULL << 6)

/* ---- Inventory types ---- */
#define SMT_INV_TX              1
#define SMT_INV_BLOCK           2
#define SMT_INV_FILTERED_BLOCK  3

typedef struct {
    uint32_t  type;
    hash256_t hash;
} smt_inv_t;

/* ---- Network address ---- */
typedef struct {
    uint64_t services;
    uint8_t  ip[16];    /* IPv6-mapped IPv4: ::ffff:a.b.c.d */
    uint16_t port;
} smt_net_addr_t;

/* ---- Version message ---- */
typedef struct {
    int32_t   version;
    uint64_t  services;
    int64_t   timestamp;
    smt_net_addr_t addr_recv;
    smt_net_addr_t addr_from;
    uint64_t  nonce;
    char      user_agent[256];
    int32_t   start_height;
    uint8_t   relay;         /* BIP37: 0 = don't relay until filter set */

    /* Dash/Smartiecoin extension */
    uint8_t   mnauth_challenge[32]; /* MNAUTH challenge (we ignore this) */
    uint8_t   fMasternode;
} smt_msg_version_t;

/* ---- Block header (80 bytes on wire) ---- */
typedef struct {
    int32_t   version;
    hash256_t prev_hash;
    hash256_t merkle_root;
    uint32_t  timestamp;
    uint32_t  bits;       /* compact difficulty target */
    uint32_t  nonce;
} smt_block_header_t;

/* ---- Merkle block (BIP37) ---- */
#define SMT_MAX_MERKLE_HASHES 256
#define SMT_MAX_MERKLE_FLAGS  64

typedef struct {
    smt_block_header_t header;
    uint32_t  num_tx;
    int       num_hashes;
    hash256_t hashes[SMT_MAX_MERKLE_HASHES];
    int       num_flag_bytes;
    uint8_t   flags[SMT_MAX_MERKLE_FLAGS];
} smt_msg_merkleblock_t;

/* ---- P2P Connection ---- */
#define SMT_P2P_BUF_SIZE 65536
#define SMT_MAX_PEERS     4

typedef struct {
    int       sock;          /* socket fd */
    uint8_t   recv_buf[SMT_P2P_BUF_SIZE];
    size_t    recv_len;
    smt_bool  connected;
    smt_bool  version_sent;
    smt_bool  version_received;
    smt_bool  verack_received;
    smt_bool  filter_loaded;
    int32_t   peer_version;
    int32_t   peer_height;
    uint64_t  peer_services;
    char      peer_agent[256];
    char      peer_ip[64];
    uint16_t  peer_port;
    int64_t   last_ping_time;
    uint64_t  ping_nonce;
} smt_peer_t;

typedef struct {
    smt_peer_t         peers[SMT_MAX_PEERS];
    int                num_peers;
    smt_chain_params_t params;
    int32_t            best_height;
} smt_p2p_manager_t;

/* ---- Message building ---- */

/* Build message header */
void smt_msg_build_header(smt_msg_header_t *hdr, const uint8_t magic[4],
                          const char *command, const uint8_t *payload,
                          uint32_t payload_size);

/* Serialize a complete message (header + payload) into buffer */
int smt_msg_serialize(uint8_t *buf, size_t buf_size,
                      const uint8_t magic[4], const char *command,
                      const uint8_t *payload, uint32_t payload_size);

/* Parse message header from buffer */
int smt_msg_parse_header(const uint8_t *buf, size_t buf_len,
                         smt_msg_header_t *hdr);

/* ---- Build specific messages ---- */

int smt_msg_build_version(uint8_t *buf, size_t buf_size,
                          const smt_chain_params_t *params,
                          int32_t best_height,
                          const char *peer_ip, uint16_t peer_port);

int smt_msg_build_verack(uint8_t *buf, size_t buf_size,
                         const uint8_t magic[4]);

int smt_msg_build_ping(uint8_t *buf, size_t buf_size,
                       const uint8_t magic[4], uint64_t nonce);

int smt_msg_build_pong(uint8_t *buf, size_t buf_size,
                       const uint8_t magic[4], uint64_t nonce);

int smt_msg_build_getheaders(uint8_t *buf, size_t buf_size,
                             const uint8_t magic[4],
                             int32_t version,
                             const hash256_t *locator_hashes,
                             int num_locator,
                             const hash256_t stop_hash);

int smt_msg_build_getdata(uint8_t *buf, size_t buf_size,
                          const uint8_t magic[4],
                          const smt_inv_t *items, int num_items);

int smt_msg_build_filterload(uint8_t *buf, size_t buf_size,
                             const uint8_t magic[4],
                             const uint8_t *filter, size_t filter_size,
                             uint32_t num_hash_funcs,
                             uint32_t tweak,
                             uint8_t flags);

int smt_msg_build_tx(uint8_t *buf, size_t buf_size,
                     const uint8_t magic[4],
                     const uint8_t *tx_data, size_t tx_len);

/* ---- Parse specific messages ---- */

int smt_msg_parse_version(const uint8_t *payload, size_t len,
                          smt_msg_version_t *ver);

int smt_msg_parse_headers(const uint8_t *payload, size_t len,
                          smt_block_header_t *headers, int max_headers,
                          int *num_parsed);

int smt_msg_parse_inv(const uint8_t *payload, size_t len,
                      smt_inv_t *items, int max_items, int *num_parsed);

int smt_msg_parse_merkleblock(const uint8_t *payload, size_t len,
                              smt_msg_merkleblock_t *mb);

int smt_msg_parse_ping(const uint8_t *payload, size_t len, uint64_t *nonce);

/* ---- P2P Manager ---- */

void smt_p2p_init(smt_p2p_manager_t *mgr, const smt_chain_params_t *params);
int  smt_p2p_connect(smt_p2p_manager_t *mgr, const char *ip, uint16_t port);
void smt_p2p_disconnect(smt_p2p_manager_t *mgr, int peer_idx);
int  smt_p2p_send(smt_peer_t *peer, const uint8_t *data, size_t len);
int  smt_p2p_recv(smt_peer_t *peer);
int  smt_p2p_process(smt_p2p_manager_t *mgr, int peer_idx);

/* Callback types for received messages */
typedef void (*smt_on_headers_fn)(smt_block_header_t *headers, int count, void *ctx);
typedef void (*smt_on_merkleblock_fn)(const smt_msg_merkleblock_t *mb, void *ctx);
typedef void (*smt_on_tx_fn)(const uint8_t *tx_data, size_t tx_len, void *ctx);
typedef void (*smt_on_inv_fn)(const smt_inv_t *items, int count, void *ctx);

typedef struct {
    smt_on_headers_fn     on_headers;
    smt_on_merkleblock_fn on_merkleblock;
    smt_on_tx_fn          on_tx;
    smt_on_inv_fn         on_inv;
    void                  *ctx;
} smt_p2p_callbacks_t;

void smt_p2p_set_callbacks(smt_p2p_manager_t *mgr, const smt_p2p_callbacks_t *cb);

#endif /* SMT_P2P_H */
