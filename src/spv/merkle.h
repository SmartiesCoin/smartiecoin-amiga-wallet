/*
 * Smartiecoin Amiga Wallet - Merkle proof verification
 * Verifies that a transaction is included in a block using BIP37 merkle proofs
 */
#ifndef SMT_MERKLE_H
#define SMT_MERKLE_H

#include "../types.h"
#include "../net/p2p.h"

/*
 * Verify a merkle proof from a merkleblock message.
 * Returns SMT_TRUE if the proof is valid and the given txid is matched.
 *
 * The merkle proof consists of:
 * - A partial merkle tree (hashes + flag bits)
 * - The expected merkle root (from the block header)
 *
 * This validates that the transaction with the given txid is included
 * in the block without needing to download the full block.
 */
smt_bool smt_merkle_verify(const smt_msg_merkleblock_t *mb,
                           const hash256_t txid);

/*
 * Extract all matched transaction hashes from a merkleblock.
 * Returns number of matched txids, fills matched_txids array.
 */
int smt_merkle_extract_matches(const smt_msg_merkleblock_t *mb,
                               hash256_t *matched_txids,
                               int max_matches);

#endif /* SMT_MERKLE_H */
