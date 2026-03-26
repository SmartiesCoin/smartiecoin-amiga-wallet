/*
 * Smartiecoin Amiga Wallet - Block header chain
 */
#include "headers.h"
#include "../crypto/sha256.h"
#include "../net/serialize.h"

#ifdef AMIGA
#include <proto/exec.h>
#include <proto/dos.h>
#else
#include <stdlib.h>
#include <stdio.h>
#endif

/* Allocate memory */
static void *smt_alloc(size_t size) {
#ifdef AMIGA
    return AllocMem(size, MEMF_ANY | MEMF_CLEAR);
#else
    void *p = malloc(size);
    if (p) smt_memzero(p, size);
    return p;
#endif
}

static void smt_free(void *p, size_t size) {
#ifdef AMIGA
    if (p) FreeMem(p, size);
#else
    (void)size;
    free(p);
#endif
}

void smt_headers_init(smt_header_chain_t *chain) {
    int i;
    smt_memzero(chain, sizeof(smt_header_chain_t));
    chain->height = -1;
    chain->sync_peer = -1;
    for (i = 0; i < SMT_HEADERS_MAX_CHUNKS; i++)
        chain->chunks[i] = NULL;
}

void smt_headers_free(smt_header_chain_t *chain) {
    int i;
    for (i = 0; i < SMT_HEADERS_MAX_CHUNKS; i++) {
        if (chain->chunks[i]) {
            smt_free(chain->chunks[i],
                     SMT_HEADERS_CHUNK_SIZE * sizeof(smt_block_header_t));
            chain->chunks[i] = NULL;
        }
    }
    chain->height = -1;
}

static smt_block_header_t *get_mutable(smt_header_chain_t *chain, int32_t height) {
    int chunk = height / SMT_HEADERS_CHUNK_SIZE;
    int offset = height % SMT_HEADERS_CHUNK_SIZE;

    if (chunk >= SMT_HEADERS_MAX_CHUNKS) return NULL;

    /* Allocate chunk on demand */
    if (!chain->chunks[chunk]) {
        chain->chunks[chunk] = (smt_block_header_t *)smt_alloc(
            SMT_HEADERS_CHUNK_SIZE * sizeof(smt_block_header_t));
        if (!chain->chunks[chunk]) return NULL;
    }

    return &chain->chunks[chunk][offset];
}

const smt_block_header_t *smt_headers_get(const smt_header_chain_t *chain,
                                           int32_t height) {
    int chunk = height / SMT_HEADERS_CHUNK_SIZE;
    int offset = height % SMT_HEADERS_CHUNK_SIZE;

    if (height < 0 || height > chain->height) return NULL;
    if (chunk >= SMT_HEADERS_MAX_CHUNKS) return NULL;
    if (!chain->chunks[chunk]) return NULL;

    return &chain->chunks[chunk][offset];
}

void smt_header_hash(const smt_block_header_t *header, hash256_t hash) {
    /* Serialize the 80-byte block header in little-endian wire format */
    uint8_t buf[80];
    size_t pos = 0;

    smt_write_i32le(buf, &pos, 80, header->version);
    smt_write_bytes(buf, &pos, 80, header->prev_hash, 32);
    smt_write_bytes(buf, &pos, 80, header->merkle_root, 32);
    smt_write_u32le(buf, &pos, 80, header->timestamp);
    smt_write_u32le(buf, &pos, 80, header->bits);
    smt_write_u32le(buf, &pos, 80, header->nonce);

    smt_sha256d(buf, 80, hash);
}

int smt_headers_add(smt_header_chain_t *chain,
                    const smt_block_header_t *headers, int count) {
    int added = 0;
    int i;

    for (i = 0; i < count; i++) {
        hash256_t prev_hash;
        smt_block_header_t *slot;
        int32_t new_height = chain->height + 1;

        /* Validate: prev_hash must match current tip */
        if (chain->height >= 0) {
            if (smt_memcmp(headers[i].prev_hash, chain->tip_hash, 32) != 0) {
                /* Doesn't link to our chain - stop */
                break;
            }
        }
        /* For genesis block (height 0), accept any prev_hash */

        /* Store header */
        slot = get_mutable(chain, new_height);
        if (!slot) break; /* out of memory */

        smt_memcpy(slot, &headers[i], sizeof(smt_block_header_t));

        /* Update tip */
        smt_header_hash(slot, chain->tip_hash);
        chain->height = new_height;
        added++;
    }

    return added;
}

int smt_headers_get_locator(const smt_header_chain_t *chain,
                            hash256_t *hashes, int max_hashes) {
    int count = 0;
    int32_t step = 1;
    int32_t height = chain->height;

    /*
     * Block locator: start at tip, step back by 1 for first 10,
     * then exponentially (2, 4, 8, 16, ...) to cover the whole chain.
     */
    while (height >= 0 && count < max_hashes) {
        const smt_block_header_t *hdr = smt_headers_get(chain, height);
        if (!hdr) break;
        smt_header_hash(hdr, hashes[count]);
        count++;

        if (count > 10) step *= 2;
        height -= step;
    }

    /* Always include genesis (height 0) if not already */
    if (count > 0 && chain->height > 0) {
        const smt_block_header_t *genesis = smt_headers_get(chain, 0);
        if (genesis && count < max_hashes) {
            smt_header_hash(genesis, hashes[count]);
            count++;
        }
    }

    return count;
}

int smt_headers_save(const smt_header_chain_t *chain, const char *filename) {
    int32_t h;
    uint8_t buf[80];

#ifdef AMIGA
    BPTR fh = Open((STRPTR)filename, MODE_NEWFILE);
    if (!fh) return -1;

    /* Write height */
    Write(fh, &chain->height, 4);

    /* Write headers */
    for (h = 0; h <= chain->height; h++) {
        const smt_block_header_t *hdr = smt_headers_get(chain, h);
        size_t pos = 0;
        smt_write_i32le(buf, &pos, 80, hdr->version);
        smt_write_bytes(buf, &pos, 80, hdr->prev_hash, 32);
        smt_write_bytes(buf, &pos, 80, hdr->merkle_root, 32);
        smt_write_u32le(buf, &pos, 80, hdr->timestamp);
        smt_write_u32le(buf, &pos, 80, hdr->bits);
        smt_write_u32le(buf, &pos, 80, hdr->nonce);
        Write(fh, buf, 80);
    }

    Close(fh);
#else
    FILE *f = fopen(filename, "wb");
    if (!f) return -1;

    fwrite(&chain->height, 1, 4, f);

    for (h = 0; h <= chain->height; h++) {
        const smt_block_header_t *hdr = smt_headers_get(chain, h);
        size_t pos = 0;
        smt_write_i32le(buf, &pos, 80, hdr->version);
        smt_write_bytes(buf, &pos, 80, hdr->prev_hash, 32);
        smt_write_bytes(buf, &pos, 80, hdr->merkle_root, 32);
        smt_write_u32le(buf, &pos, 80, hdr->timestamp);
        smt_write_u32le(buf, &pos, 80, hdr->bits);
        smt_write_u32le(buf, &pos, 80, hdr->nonce);
        fwrite(buf, 1, 80, f);
    }

    fclose(f);
#endif
    return 0;
}

int smt_headers_load(smt_header_chain_t *chain, const char *filename) {
    int32_t stored_height;
    int32_t h;
    uint8_t buf[80];

    smt_headers_init(chain);

#ifdef AMIGA
    BPTR fh = Open((STRPTR)filename, MODE_OLDFILE);
    if (!fh) return -1;

    if (Read(fh, &stored_height, 4) != 4) { Close(fh); return -1; }

    for (h = 0; h <= stored_height; h++) {
        smt_block_header_t hdr;
        size_t pos = 0;
        if (Read(fh, buf, 80) != 80) { Close(fh); return -1; }

        smt_read_i32le(buf, &pos, 80, &hdr.version);
        smt_read_bytes(buf, &pos, 80, hdr.prev_hash, 32);
        smt_read_bytes(buf, &pos, 80, hdr.merkle_root, 32);
        smt_read_u32le(buf, &pos, 80, &hdr.timestamp);
        smt_read_u32le(buf, &pos, 80, &hdr.bits);
        smt_read_u32le(buf, &pos, 80, &hdr.nonce);

        smt_headers_add(chain, &hdr, 1);
    }

    Close(fh);
#else
    {
        FILE *f = fopen(filename, "rb");
        if (!f) return -1;

        if (fread(&stored_height, 1, 4, f) != 4) { fclose(f); return -1; }

        for (h = 0; h <= stored_height; h++) {
            smt_block_header_t hdr;
            size_t pos = 0;
            if (fread(buf, 1, 80, f) != 80) { fclose(f); return -1; }

            smt_read_i32le(buf, &pos, 80, &hdr.version);
            smt_read_bytes(buf, &pos, 80, hdr.prev_hash, 32);
            smt_read_bytes(buf, &pos, 80, hdr.merkle_root, 32);
            smt_read_u32le(buf, &pos, 80, &hdr.timestamp);
            smt_read_u32le(buf, &pos, 80, &hdr.bits);
            smt_read_u32le(buf, &pos, 80, &hdr.nonce);

            smt_headers_add(chain, &hdr, 1);
        }

        fclose(f);
    }
#endif
    return 0;
}

int smt_headers_start_sync(smt_header_chain_t *chain,
                           smt_p2p_manager_t *p2p, int peer_idx) {
    hash256_t locator[64];
    int num_locator;
    uint8_t msg_buf[4096];
    int msg_len;

    chain->syncing = SMT_TRUE;
    chain->sync_peer = peer_idx;

    num_locator = smt_headers_get_locator(chain, locator, 64);

    msg_len = smt_msg_build_getheaders(msg_buf, sizeof(msg_buf),
                                       p2p->params.magic,
                                       SMT_PROTOCOL_VERSION,
                                       locator, num_locator, NULL);
    if (msg_len < 0) return -1;

    return smt_p2p_send(&p2p->peers[peer_idx], msg_buf, (size_t)msg_len);
}

int smt_headers_continue_sync(smt_header_chain_t *chain,
                              smt_p2p_manager_t *p2p,
                              const smt_block_header_t *new_headers, int count) {
    int added;

    added = smt_headers_add(chain, new_headers, count);

    /* If we got a full batch, request more */
    if (added > 0 && count >= SMT_MAX_HEADERS_BATCH - 1) {
        return smt_headers_start_sync(chain, p2p, chain->sync_peer);
    }

    /* Sync complete */
    chain->syncing = SMT_FALSE;

    /* Save to disk */
    if (chain->filename) {
        smt_headers_save(chain, chain->filename);
    }

    return 0;
}

smt_bool smt_headers_is_synced(const smt_header_chain_t *chain, int32_t peer_height) {
    if (chain->height < 0) return SMT_FALSE;
    return (chain->height >= peer_height - 1) ? SMT_TRUE : SMT_FALSE;
}
