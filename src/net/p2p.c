/*
 * Smartiecoin Amiga Wallet - P2P protocol implementation
 */
#include "p2p.h"
#include "serialize.h"
#include "../crypto/sha256.h"
#include "../platform/amiga_net.h"

#ifdef AMIGA
#include <proto/exec.h>
#include <proto/dos.h>
#include <dos/dos.h>
#include <dos/datetime.h>
#else
#include <string.h>
#include <time.h>
#endif

static smt_p2p_callbacks_t g_callbacks;

/* ---- IPv4 to IPv6-mapped ---- */
static void ipv4_to_mapped(uint8_t ip[16], uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    smt_memzero(ip, 16);
    ip[10] = 0xFF;
    ip[11] = 0xFF;
    ip[12] = a;
    ip[13] = b;
    ip[14] = c;
    ip[15] = d;
}

/* Parse dotted IPv4 string */
static int parse_ipv4(const char *str, uint8_t *a, uint8_t *b, uint8_t *c, uint8_t *d) {
    uint32_t parts[4] = {0, 0, 0, 0};
    int pi = 0;
    const char *p = str;

    while (*p && pi < 4) {
        if (*p >= '0' && *p <= '9') {
            parts[pi] = parts[pi] * 10 + (*p - '0');
        } else if (*p == '.') {
            pi++;
        } else {
            return -1;
        }
        p++;
    }
    if (pi != 3) return -1;
    *a = (uint8_t)parts[0]; *b = (uint8_t)parts[1];
    *c = (uint8_t)parts[2]; *d = (uint8_t)parts[3];
    return 0;
}

/* Get current time as int64 */
static int64_t get_timestamp(void) {
#ifdef AMIGA
    /* Use Amiga DateStamp - approximate, seconds since 1978 + offset to Unix epoch */
    struct DateStamp ds;
    DateStamp(&ds);
    return (int64_t)ds.ds_Days * 86400 + (int64_t)ds.ds_Minute * 60 +
           (int64_t)ds.ds_Tick / 50 + 252460800LL; /* Amiga epoch to Unix epoch */
#else
    return (int64_t)time(NULL);
#endif
}

/* ---- Message building ---- */

void smt_msg_build_header(smt_msg_header_t *hdr, const uint8_t magic[4],
                          const char *command, const uint8_t *payload,
                          uint32_t payload_size) {
    hash256_t hash;
    int i;

    smt_memcpy(hdr->magic, magic, 4);
    smt_memzero(hdr->command, SMT_MSG_CMD_SIZE);
    for (i = 0; command[i] && i < SMT_MSG_CMD_SIZE; i++)
        hdr->command[i] = command[i];
    hdr->payload_size = payload_size;

    if (payload && payload_size > 0) {
        smt_sha256d(payload, payload_size, hash);
    } else {
        /* SHA256d of empty data */
        smt_sha256d((const uint8_t *)"", 0, hash);
    }
    smt_memcpy(hdr->checksum, hash, 4);
}

int smt_msg_serialize(uint8_t *buf, size_t buf_size,
                      const uint8_t magic[4], const char *command,
                      const uint8_t *payload, uint32_t payload_size) {
    size_t pos = 0;
    smt_msg_header_t hdr;
    int i;

    if (SMT_MSG_HDR_SIZE + payload_size > buf_size)
        return -1;

    smt_msg_build_header(&hdr, magic, command, payload, payload_size);

    /* Write header */
    smt_write_bytes(buf, &pos, buf_size, hdr.magic, 4);
    smt_write_bytes(buf, &pos, buf_size, (const uint8_t *)hdr.command, SMT_MSG_CMD_SIZE);
    smt_write_u32le(buf, &pos, buf_size, hdr.payload_size);
    smt_write_bytes(buf, &pos, buf_size, hdr.checksum, 4);

    /* Write payload */
    if (payload_size > 0)
        smt_write_bytes(buf, &pos, buf_size, payload, payload_size);

    return (int)pos;
}

int smt_msg_parse_header(const uint8_t *buf, size_t buf_len,
                         smt_msg_header_t *hdr) {
    size_t pos = 0;
    if (buf_len < SMT_MSG_HDR_SIZE) return -1;

    smt_read_bytes(buf, &pos, buf_len, hdr->magic, 4);
    smt_read_bytes(buf, &pos, buf_len, (uint8_t *)hdr->command, SMT_MSG_CMD_SIZE);
    smt_read_u32le(buf, &pos, buf_len, &hdr->payload_size);
    smt_read_bytes(buf, &pos, buf_len, hdr->checksum, 4);

    return 0;
}

/* ---- Build version message ---- */

int smt_msg_build_version(uint8_t *buf, size_t buf_size,
                          const smt_chain_params_t *params,
                          int32_t best_height,
                          const char *peer_ip, uint16_t peer_port) {
    uint8_t payload[512];
    size_t pos = 0;
    uint8_t a, b, c, d;
    uint8_t ip6[16];
    const char *ua = SMT_USER_AGENT;
    size_t ua_len = smt_strlen(ua);

    /* Protocol version */
    smt_write_i32le(payload, &pos, sizeof(payload), SMT_PROTOCOL_VERSION);

    /* Services: NODE_NETWORK | NODE_BLOOM */
    smt_write_u64le(payload, &pos, sizeof(payload), SMT_NODE_BLOOM);

    /* Timestamp */
    smt_write_i64le(payload, &pos, sizeof(payload), get_timestamp());

    /* addr_recv */
    smt_write_u64le(payload, &pos, sizeof(payload), SMT_NODE_NETWORK);
    if (parse_ipv4(peer_ip, &a, &b, &c, &d) == 0) {
        ipv4_to_mapped(ip6, a, b, c, d);
    } else {
        smt_memzero(ip6, 16);
    }
    smt_write_bytes(payload, &pos, sizeof(payload), ip6, 16);
    smt_write_u16be(payload, &pos, sizeof(payload), peer_port);

    /* addr_from (us - zeros is fine) */
    smt_write_u64le(payload, &pos, sizeof(payload), SMT_NODE_BLOOM);
    smt_memzero(ip6, 16);
    smt_write_bytes(payload, &pos, sizeof(payload), ip6, 16);
    smt_write_u16be(payload, &pos, sizeof(payload), 0);

    /* Nonce (random) */
    {
        uint64_t nonce = (uint64_t)get_timestamp() * 1103515245ULL + 12345ULL;
        smt_write_u64le(payload, &pos, sizeof(payload), nonce);
    }

    /* User agent */
    smt_write_varstr(payload, &pos, sizeof(payload), ua, ua_len);

    /* Start height */
    smt_write_i32le(payload, &pos, sizeof(payload), best_height);

    /* Relay (BIP37: 0 = we'll use bloom filters) */
    smt_write_u8(payload, &pos, sizeof(payload), 0);

    /* Dash/Smartiecoin: MNAUTH challenge (32 zero bytes) + fMasternode (0) */
    {
        uint8_t zeros[32];
        smt_memzero(zeros, 32);
        smt_write_bytes(payload, &pos, sizeof(payload), zeros, 32);
        smt_write_u8(payload, &pos, sizeof(payload), 0);
    }

    return smt_msg_serialize(buf, buf_size, params->magic, "version",
                             payload, (uint32_t)pos);
}

int smt_msg_build_verack(uint8_t *buf, size_t buf_size,
                         const uint8_t magic[4]) {
    return smt_msg_serialize(buf, buf_size, magic, "verack", NULL, 0);
}

int smt_msg_build_ping(uint8_t *buf, size_t buf_size,
                       const uint8_t magic[4], uint64_t nonce) {
    uint8_t payload[8];
    size_t pos = 0;
    smt_write_u64le(payload, &pos, sizeof(payload), nonce);
    return smt_msg_serialize(buf, buf_size, magic, "ping", payload, 8);
}

int smt_msg_build_pong(uint8_t *buf, size_t buf_size,
                       const uint8_t magic[4], uint64_t nonce) {
    uint8_t payload[8];
    size_t pos = 0;
    smt_write_u64le(payload, &pos, sizeof(payload), nonce);
    return smt_msg_serialize(buf, buf_size, magic, "pong", payload, 8);
}

int smt_msg_build_getheaders(uint8_t *buf, size_t buf_size,
                             const uint8_t magic[4],
                             int32_t version,
                             const hash256_t *locator_hashes,
                             int num_locator,
                             const hash256_t stop_hash) {
    uint8_t payload[4 + 9 + 32 * 64 + 32]; /* version + varint + hashes + stop */
    size_t pos = 0;
    int i;

    smt_write_u32le(payload, &pos, sizeof(payload), (uint32_t)version);
    smt_write_varint(payload, &pos, sizeof(payload), (uint64_t)num_locator);

    for (i = 0; i < num_locator; i++) {
        smt_write_bytes(payload, &pos, sizeof(payload), locator_hashes[i], 32);
    }

    if (stop_hash) {
        smt_write_bytes(payload, &pos, sizeof(payload), stop_hash, 32);
    } else {
        uint8_t zeros[32];
        smt_memzero(zeros, 32);
        smt_write_bytes(payload, &pos, sizeof(payload), zeros, 32);
    }

    return smt_msg_serialize(buf, buf_size, magic, "getheaders",
                             payload, (uint32_t)pos);
}

int smt_msg_build_getdata(uint8_t *buf, size_t buf_size,
                          const uint8_t magic[4],
                          const smt_inv_t *items, int num_items) {
    uint8_t payload[9 + 36 * 64]; /* varint + inv entries */
    size_t pos = 0;
    int i;

    smt_write_varint(payload, &pos, sizeof(payload), (uint64_t)num_items);
    for (i = 0; i < num_items; i++) {
        smt_write_u32le(payload, &pos, sizeof(payload), items[i].type);
        smt_write_bytes(payload, &pos, sizeof(payload), items[i].hash, 32);
    }

    return smt_msg_serialize(buf, buf_size, magic, "getdata",
                             payload, (uint32_t)pos);
}

int smt_msg_build_filterload(uint8_t *buf, size_t buf_size,
                             const uint8_t magic[4],
                             const uint8_t *filter, size_t filter_size,
                             uint32_t num_hash_funcs,
                             uint32_t tweak,
                             uint8_t flags) {
    uint8_t payload[9 + 36000 + 4 + 4 + 1]; /* max bloom filter size */
    size_t pos = 0;

    smt_write_varint(payload, &pos, sizeof(payload), (uint64_t)filter_size);
    smt_write_bytes(payload, &pos, sizeof(payload), filter, filter_size);
    smt_write_u32le(payload, &pos, sizeof(payload), num_hash_funcs);
    smt_write_u32le(payload, &pos, sizeof(payload), tweak);
    smt_write_u8(payload, &pos, sizeof(payload), flags);

    return smt_msg_serialize(buf, buf_size, magic, "filterload",
                             payload, (uint32_t)pos);
}

int smt_msg_build_tx(uint8_t *buf, size_t buf_size,
                     const uint8_t magic[4],
                     const uint8_t *tx_data, size_t tx_len) {
    return smt_msg_serialize(buf, buf_size, magic, "tx",
                             tx_data, (uint32_t)tx_len);
}

/* ---- Parse messages ---- */

int smt_msg_parse_version(const uint8_t *payload, size_t len,
                          smt_msg_version_t *ver) {
    size_t pos = 0;

    smt_memzero(ver, sizeof(smt_msg_version_t));

    if (smt_read_i32le(payload, &pos, len, &ver->version) < 0) return -1;
    if (smt_read_u64le(payload, &pos, len, &ver->services) < 0) return -1;
    if (smt_read_i64le(payload, &pos, len, &ver->timestamp) < 0) return -1;

    /* addr_recv */
    if (smt_read_u64le(payload, &pos, len, &ver->addr_recv.services) < 0) return -1;
    if (smt_read_bytes(payload, &pos, len, ver->addr_recv.ip, 16) < 0) return -1;
    if (smt_read_u16be(payload, &pos, len, &ver->addr_recv.port) < 0) return -1;

    /* addr_from */
    if (smt_read_u64le(payload, &pos, len, &ver->addr_from.services) < 0) return -1;
    if (smt_read_bytes(payload, &pos, len, ver->addr_from.ip, 16) < 0) return -1;
    if (smt_read_u16be(payload, &pos, len, &ver->addr_from.port) < 0) return -1;

    /* Nonce */
    if (smt_read_u64le(payload, &pos, len, &ver->nonce) < 0) return -1;

    /* User agent */
    {
        size_t ua_len;
        if (smt_read_varstr(payload, &pos, len, ver->user_agent,
                            sizeof(ver->user_agent), &ua_len) < 0) return -1;
    }

    /* Start height */
    if (smt_read_i32le(payload, &pos, len, &ver->start_height) < 0) return -1;

    /* Relay (optional) */
    if (pos < len) {
        smt_read_u8(payload, &pos, len, &ver->relay);
    }

    /* Dash/Smartiecoin extensions (optional) */
    if (pos + 32 <= len) {
        smt_read_bytes(payload, &pos, len, ver->mnauth_challenge, 32);
    }
    if (pos < len) {
        smt_read_u8(payload, &pos, len, &ver->fMasternode);
    }

    return 0;
}

int smt_msg_parse_headers(const uint8_t *payload, size_t len,
                          smt_block_header_t *headers, int max_headers,
                          int *num_parsed) {
    size_t pos = 0;
    uint64_t count;
    int i;

    if (smt_read_varint(payload, &pos, len, &count) < 0) return -1;
    if (count > (uint64_t)max_headers) count = (uint64_t)max_headers;

    for (i = 0; i < (int)count; i++) {
        uint64_t dummy_tx_count;

        if (smt_read_i32le(payload, &pos, len, &headers[i].version) < 0) return -1;
        if (smt_read_bytes(payload, &pos, len, headers[i].prev_hash, 32) < 0) return -1;
        if (smt_read_bytes(payload, &pos, len, headers[i].merkle_root, 32) < 0) return -1;
        if (smt_read_u32le(payload, &pos, len, &headers[i].timestamp) < 0) return -1;
        if (smt_read_u32le(payload, &pos, len, &headers[i].bits) < 0) return -1;
        if (smt_read_u32le(payload, &pos, len, &headers[i].nonce) < 0) return -1;

        /* Transaction count (always 0 in headers message) */
        if (smt_read_varint(payload, &pos, len, &dummy_tx_count) < 0) return -1;
    }

    *num_parsed = (int)count;
    return 0;
}

int smt_msg_parse_inv(const uint8_t *payload, size_t len,
                      smt_inv_t *items, int max_items, int *num_parsed) {
    size_t pos = 0;
    uint64_t count;
    int i;

    if (smt_read_varint(payload, &pos, len, &count) < 0) return -1;
    if (count > (uint64_t)max_items) count = (uint64_t)max_items;

    for (i = 0; i < (int)count; i++) {
        if (smt_read_u32le(payload, &pos, len, &items[i].type) < 0) return -1;
        if (smt_read_bytes(payload, &pos, len, items[i].hash, 32) < 0) return -1;
    }

    *num_parsed = (int)count;
    return 0;
}

int smt_msg_parse_merkleblock(const uint8_t *payload, size_t len,
                              smt_msg_merkleblock_t *mb) {
    size_t pos = 0;
    uint64_t count;
    int i;

    smt_memzero(mb, sizeof(smt_msg_merkleblock_t));

    /* Block header */
    if (smt_read_i32le(payload, &pos, len, &mb->header.version) < 0) return -1;
    if (smt_read_bytes(payload, &pos, len, mb->header.prev_hash, 32) < 0) return -1;
    if (smt_read_bytes(payload, &pos, len, mb->header.merkle_root, 32) < 0) return -1;
    if (smt_read_u32le(payload, &pos, len, &mb->header.timestamp) < 0) return -1;
    if (smt_read_u32le(payload, &pos, len, &mb->header.bits) < 0) return -1;
    if (smt_read_u32le(payload, &pos, len, &mb->header.nonce) < 0) return -1;

    /* Total transactions in block */
    if (smt_read_u32le(payload, &pos, len, &mb->num_tx) < 0) return -1;

    /* Hashes */
    if (smt_read_varint(payload, &pos, len, &count) < 0) return -1;
    if (count > SMT_MAX_MERKLE_HASHES) return -1;
    mb->num_hashes = (int)count;
    for (i = 0; i < mb->num_hashes; i++) {
        if (smt_read_bytes(payload, &pos, len, mb->hashes[i], 32) < 0) return -1;
    }

    /* Flag bits */
    if (smt_read_varint(payload, &pos, len, &count) < 0) return -1;
    if (count > SMT_MAX_MERKLE_FLAGS) return -1;
    mb->num_flag_bytes = (int)count;
    if (smt_read_bytes(payload, &pos, len, mb->flags, (size_t)count) < 0) return -1;

    return 0;
}

int smt_msg_parse_ping(const uint8_t *payload, size_t len, uint64_t *nonce) {
    size_t pos = 0;
    return smt_read_u64le(payload, &pos, len, nonce);
}

/* ---- P2P Manager ---- */

void smt_p2p_init(smt_p2p_manager_t *mgr, const smt_chain_params_t *params) {
    smt_memzero(mgr, sizeof(smt_p2p_manager_t));
    smt_memcpy(&mgr->params, params, sizeof(smt_chain_params_t));
    mgr->best_height = 0;
}

int smt_p2p_connect(smt_p2p_manager_t *mgr, const char *ip, uint16_t port) {
    int idx;
    smt_peer_t *peer;
    int sock;

    if (mgr->num_peers >= SMT_MAX_PEERS) return -1;

    sock = smt_net_connect(ip, port);
    if (sock < 0) return -1;

    idx = mgr->num_peers;
    peer = &mgr->peers[idx];
    smt_memzero(peer, sizeof(smt_peer_t));
    peer->sock = sock;
    peer->connected = SMT_TRUE;

    /* Copy IP string */
    {
        int i;
        for (i = 0; ip[i] && i < 63; i++) peer->peer_ip[i] = ip[i];
        peer->peer_ip[i] = '\0';
    }
    peer->peer_port = port;

    mgr->num_peers++;

    /* Send version message */
    {
        uint8_t msg_buf[512];
        int msg_len = smt_msg_build_version(msg_buf, sizeof(msg_buf),
                                            &mgr->params, mgr->best_height,
                                            ip, port);
        if (msg_len > 0) {
            smt_p2p_send(peer, msg_buf, (size_t)msg_len);
            peer->version_sent = SMT_TRUE;
        }
    }

    return idx;
}

void smt_p2p_disconnect(smt_p2p_manager_t *mgr, int peer_idx) {
    if (peer_idx < 0 || peer_idx >= mgr->num_peers) return;
    smt_net_close(mgr->peers[peer_idx].sock);
    mgr->peers[peer_idx].connected = SMT_FALSE;
    mgr->peers[peer_idx].sock = -1;
}

int smt_p2p_send(smt_peer_t *peer, const uint8_t *data, size_t len) {
    if (!peer->connected) return -1;
    return smt_net_send(peer->sock, data, len);
}

int smt_p2p_recv(smt_peer_t *peer) {
    int n;
    if (!peer->connected) return -1;
    if (peer->recv_len >= SMT_P2P_BUF_SIZE) return 0;

    n = smt_net_recv(peer->sock,
                     peer->recv_buf + peer->recv_len,
                     SMT_P2P_BUF_SIZE - peer->recv_len);
    if (n > 0)
        peer->recv_len += (size_t)n;
    else if (n < 0)
        peer->connected = SMT_FALSE;

    return n;
}

/* String compare helper for command names */
static int cmd_eq(const char *a, const char *b) {
    int i;
    for (i = 0; i < SMT_MSG_CMD_SIZE; i++) {
        if (a[i] != b[i]) return 0;
        if (a[i] == '\0') return 1;
    }
    return 1;
}

int smt_p2p_process(smt_p2p_manager_t *mgr, int peer_idx) {
    smt_peer_t *peer;
    smt_msg_header_t hdr;
    size_t total_size;
    const uint8_t *payload;

    if (peer_idx < 0 || peer_idx >= mgr->num_peers) return -1;
    peer = &mgr->peers[peer_idx];

    if (!peer->connected) return -1;

    /* Try to receive data */
    smt_p2p_recv(peer);

    /* Process all complete messages in buffer */
    while (peer->recv_len >= SMT_MSG_HDR_SIZE) {
        /* Parse header */
        if (smt_msg_parse_header(peer->recv_buf, peer->recv_len, &hdr) < 0)
            break;

        /* Check magic */
        if (smt_memcmp(hdr.magic, mgr->params.magic, 4) != 0) {
            /* Bad magic - desync, disconnect */
            smt_p2p_disconnect(mgr, peer_idx);
            return -1;
        }

        /* Check if full message is available */
        total_size = SMT_MSG_HDR_SIZE + hdr.payload_size;
        if (peer->recv_len < total_size)
            break;  /* need more data */

        /* Sanity check */
        if (hdr.payload_size > SMT_MAX_MESSAGE_SIZE) {
            smt_p2p_disconnect(mgr, peer_idx);
            return -1;
        }

        payload = peer->recv_buf + SMT_MSG_HDR_SIZE;

        /* Verify checksum */
        {
            hash256_t hash;
            if (hdr.payload_size > 0)
                smt_sha256d(payload, hdr.payload_size, hash);
            else
                smt_sha256d((const uint8_t *)"", 0, hash);

            if (smt_memcmp(hash, hdr.checksum, 4) != 0) {
                /* Bad checksum - skip message */
                goto consume;
            }
        }

        /* Handle message by command */
        if (cmd_eq(hdr.command, "version")) {
            smt_msg_version_t ver;
            if (smt_msg_parse_version(payload, hdr.payload_size, &ver) == 0) {
                peer->peer_version = ver.version;
                peer->peer_height = ver.start_height;
                peer->peer_services = ver.services;
                peer->version_received = SMT_TRUE;

                /* Copy user agent */
                {
                    int i;
                    for (i = 0; ver.user_agent[i] && i < 255; i++)
                        peer->peer_agent[i] = ver.user_agent[i];
                    peer->peer_agent[i] = '\0';
                }

                /* Send verack */
                {
                    uint8_t vabuf[64];
                    int valen = smt_msg_build_verack(vabuf, sizeof(vabuf),
                                                     mgr->params.magic);
                    if (valen > 0) smt_p2p_send(peer, vabuf, (size_t)valen);
                }
            }
        }
        else if (cmd_eq(hdr.command, "verack")) {
            peer->verack_received = SMT_TRUE;
        }
        else if (cmd_eq(hdr.command, "ping")) {
            uint64_t nonce;
            if (smt_msg_parse_ping(payload, hdr.payload_size, &nonce) == 0) {
                uint8_t pbuf[64];
                int plen = smt_msg_build_pong(pbuf, sizeof(pbuf),
                                              mgr->params.magic, nonce);
                if (plen > 0) smt_p2p_send(peer, pbuf, (size_t)plen);
            }
        }
        else if (cmd_eq(hdr.command, "headers")) {
            if (g_callbacks.on_headers) {
                smt_block_header_t headers[SMT_MAX_HEADERS_BATCH];
                int num_headers;
                if (smt_msg_parse_headers(payload, hdr.payload_size,
                                          headers, SMT_MAX_HEADERS_BATCH,
                                          &num_headers) == 0) {
                    g_callbacks.on_headers(headers, num_headers, g_callbacks.ctx);
                }
            }
        }
        else if (cmd_eq(hdr.command, "merklebloc")) { /* "merkleblock" truncated to 12 */
            if (g_callbacks.on_merkleblock) {
                smt_msg_merkleblock_t mb;
                if (smt_msg_parse_merkleblock(payload, hdr.payload_size, &mb) == 0) {
                    g_callbacks.on_merkleblock(&mb, g_callbacks.ctx);
                }
            }
        }
        else if (cmd_eq(hdr.command, "tx")) {
            if (g_callbacks.on_tx) {
                g_callbacks.on_tx(payload, hdr.payload_size, g_callbacks.ctx);
            }
        }
        else if (cmd_eq(hdr.command, "inv")) {
            if (g_callbacks.on_inv) {
                smt_inv_t items[256];
                int num_items;
                if (smt_msg_parse_inv(payload, hdr.payload_size,
                                      items, 256, &num_items) == 0) {
                    g_callbacks.on_inv(items, num_items, g_callbacks.ctx);
                }
            }
        }
        else if (cmd_eq(hdr.command, "sendheaders")) {
            /* Acknowledge - we prefer headers announcements */
            /* (already implicit via our version message) */
        }
        else if (cmd_eq(hdr.command, "sendcmpct")) {
            /* Ignore compact blocks - we don't support them */
        }
        /* Other messages: ignore silently */

consume:
        /* Remove processed message from buffer */
        if (total_size < peer->recv_len) {
            size_t remaining = peer->recv_len - total_size;
            size_t i;
            for (i = 0; i < remaining; i++)
                peer->recv_buf[i] = peer->recv_buf[total_size + i];
            peer->recv_len = remaining;
        } else {
            peer->recv_len = 0;
        }
    }

    return 0;
}

void smt_p2p_set_callbacks(smt_p2p_manager_t *mgr, const smt_p2p_callbacks_t *cb) {
    smt_memcpy(&g_callbacks, cb, sizeof(smt_p2p_callbacks_t));
    (void)mgr;
}
