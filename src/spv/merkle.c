/*
 * Smartiecoin Amiga Wallet - Merkle proof verification
 */
#include "merkle.h"
#include "../crypto/sha256.h"

/*
 * Traverse the partial merkle tree recursively.
 * BIP37 defines the traversal order as DFS (left, right).
 *
 * The flag bits indicate:
 * - For leaf nodes: 1 = matched (this txid is included)
 * - For internal nodes: 1 = descend into this subtree
 *                       0 = this hash is a pruned subtree hash
 */

typedef struct {
    const smt_msg_merkleblock_t *mb;
    int hash_idx;
    int flag_idx;
    hash256_t *matches;
    int num_matches;
    int max_matches;
} merkle_state_t;

static int get_flag_bit(const merkle_state_t *state) {
    int byte_idx = state->flag_idx / 8;
    int bit_idx = state->flag_idx % 8;
    if (byte_idx >= state->mb->num_flag_bytes) return 0;
    return (state->mb->flags[byte_idx] >> bit_idx) & 1;
}

/*
 * Calculate tree height for a given number of transactions.
 * The merkle tree is a perfect binary tree, padded with duplicated hashes.
 */
static int tree_height(uint32_t num_tx) {
    int height = 0;
    uint32_t n = num_tx;
    while (n > 1) {
        n = (n + 1) / 2;
        height++;
    }
    return height;
}

/* Number of nodes at a given depth */
static uint32_t tree_width(uint32_t num_tx, int height, int depth) {
    int level = height - depth;
    uint32_t w = num_tx;
    int i;
    for (i = 0; i < level; i++) {
        w = (w + 1) / 2;
    }
    return w;
}

static void traverse(merkle_state_t *state, int depth, int pos,
                     int height, uint32_t num_tx, hash256_t result) {
    int flag;

    if (state->flag_idx >= state->mb->num_flag_bytes * 8) {
        smt_memzero(result, 32);
        return;
    }

    flag = get_flag_bit(state);
    state->flag_idx++;

    if (depth == height) {
        /* Leaf node */
        if (state->hash_idx < state->mb->num_hashes) {
            smt_memcpy(result, state->mb->hashes[state->hash_idx], 32);
            state->hash_idx++;
        } else {
            smt_memzero(result, 32);
        }

        /* If flagged, this is a matched transaction */
        if (flag && state->num_matches < state->max_matches) {
            smt_memcpy(state->matches[state->num_matches], result, 32);
            state->num_matches++;
        }
        return;
    }

    if (flag == 0) {
        /* Pruned subtree - use provided hash */
        if (state->hash_idx < state->mb->num_hashes) {
            smt_memcpy(result, state->mb->hashes[state->hash_idx], 32);
            state->hash_idx++;
        } else {
            smt_memzero(result, 32);
        }
        return;
    }

    /* Internal node with flag=1: descend */
    {
        hash256_t left, right;
        uint8_t combined[64];

        /* Left child */
        traverse(state, depth + 1, pos * 2, height, num_tx, left);

        /* Right child (only if it exists) */
        if ((uint32_t)(pos * 2 + 1) < tree_width(num_tx, height, depth + 1)) {
            traverse(state, depth + 1, pos * 2 + 1, height, num_tx, right);
        } else {
            /* Duplicate left hash (Bitcoin merkle tree padding) */
            smt_memcpy(right, left, 32);
        }

        /* Combine: SHA256d(left || right) */
        smt_memcpy(combined, left, 32);
        smt_memcpy(combined + 32, right, 32);
        smt_sha256d(combined, 64, result);
    }
}

int smt_merkle_extract_matches(const smt_msg_merkleblock_t *mb,
                               hash256_t *matched_txids,
                               int max_matches) {
    merkle_state_t state;
    hash256_t computed_root;
    int height;

    if (mb->num_tx == 0) return 0;

    state.mb = mb;
    state.hash_idx = 0;
    state.flag_idx = 0;
    state.matches = matched_txids;
    state.num_matches = 0;
    state.max_matches = max_matches;

    height = tree_height(mb->num_tx);
    traverse(&state, 0, 0, height, mb->num_tx, computed_root);

    /* Verify computed root matches header's merkle root */
    if (smt_memcmp(computed_root, mb->header.merkle_root, 32) != 0) {
        return -1; /* invalid proof */
    }

    return state.num_matches;
}

smt_bool smt_merkle_verify(const smt_msg_merkleblock_t *mb,
                           const hash256_t txid) {
    hash256_t matches[64];
    int num_matches;
    int i;

    num_matches = smt_merkle_extract_matches(mb, matches, 64);
    if (num_matches < 0) return SMT_FALSE;

    for (i = 0; i < num_matches; i++) {
        if (smt_memcmp(matches[i], txid, 32) == 0)
            return SMT_TRUE;
    }

    return SMT_FALSE;
}
