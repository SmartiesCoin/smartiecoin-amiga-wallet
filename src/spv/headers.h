/*
 * Smartiecoin Amiga Wallet - Block header chain (SPV)
 * Stores and validates the chain of block headers
 */
#ifndef SMT_HEADERS_H
#define SMT_HEADERS_H

#include "../types.h"
#include "../net/p2p.h"

/*
 * We store headers in a flat array. At ~41,000 blocks and 80 bytes each,
 * that's about 3.2 MB - well within Amiga memory constraints.
 * We allocate in chunks to avoid one huge allocation.
 */
#define SMT_HEADERS_CHUNK_SIZE 4096
#define SMT_HEADERS_MAX_CHUNKS 32  /* supports up to ~131,000 blocks */

typedef struct {
    smt_block_header_t *chunks[SMT_HEADERS_MAX_CHUNKS];
    int32_t  height;          /* current chain tip height (-1 = empty) */
    hash256_t tip_hash;       /* hash of the chain tip */
    smt_bool  syncing;        /* currently syncing headers? */
    int32_t   sync_peer;      /* peer index we're syncing from */
    const char *filename;     /* file to persist headers */
} smt_header_chain_t;

/* Initialize header chain */
void smt_headers_init(smt_header_chain_t *chain);

/* Free allocated memory */
void smt_headers_free(smt_header_chain_t *chain);

/* Get header at height. Returns NULL if out of range */
const smt_block_header_t *smt_headers_get(const smt_header_chain_t *chain, int32_t height);

/* Compute hash of a block header (SHA256d of the 80-byte serialization) */
void smt_header_hash(const smt_block_header_t *header, hash256_t hash);

/* Add headers to chain (validates prev_hash linkage). Returns number added */
int smt_headers_add(smt_header_chain_t *chain,
                    const smt_block_header_t *headers, int count);

/* Build block locator for getheaders (exponential backoff) */
int smt_headers_get_locator(const smt_header_chain_t *chain,
                            hash256_t *hashes, int max_hashes);

/* Save headers to file */
int smt_headers_save(const smt_header_chain_t *chain, const char *filename);

/* Load headers from file */
int smt_headers_load(smt_header_chain_t *chain, const char *filename);

/* Start syncing headers from a peer */
int smt_headers_start_sync(smt_header_chain_t *chain,
                           smt_p2p_manager_t *p2p, int peer_idx);

/* Continue syncing (call after receiving headers) */
int smt_headers_continue_sync(smt_header_chain_t *chain,
                              smt_p2p_manager_t *p2p,
                              const smt_block_header_t *new_headers, int count);

/* Check if we're synced (tip height >= peer height) */
smt_bool smt_headers_is_synced(const smt_header_chain_t *chain, int32_t peer_height);

#endif /* SMT_HEADERS_H */
