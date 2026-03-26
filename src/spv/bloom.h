/*
 * Smartiecoin Amiga Wallet - Bloom filter (BIP37)
 * Used to filter relevant transactions from peers
 */
#ifndef SMT_BLOOM_H
#define SMT_BLOOM_H

#include "../types.h"

#define SMT_BLOOM_MAX_SIZE    36000  /* max filter size in bytes */
#define SMT_BLOOM_MAX_FUNCS   50     /* max hash functions */
#define SMT_BLOOM_UPDATE_NONE 0
#define SMT_BLOOM_UPDATE_ALL  1
#define SMT_BLOOM_UPDATE_P2PUBKEY_ONLY 2

typedef struct {
    uint8_t  filter[SMT_BLOOM_MAX_SIZE];
    uint32_t filter_size;   /* actual size in bytes */
    uint32_t num_hash_funcs;
    uint32_t tweak;
    uint8_t  flags;
} smt_bloom_t;

/* Create a bloom filter sized for expected elements at given FP rate */
void smt_bloom_create(smt_bloom_t *bloom, int num_elements, double fp_rate,
                      uint32_t tweak, uint8_t flags);

/* Add data to the filter */
void smt_bloom_add(smt_bloom_t *bloom, const uint8_t *data, size_t len);

/* Check if data might be in the filter */
smt_bool smt_bloom_contains(const smt_bloom_t *bloom, const uint8_t *data, size_t len);

/* Clear the filter */
void smt_bloom_clear(smt_bloom_t *bloom);

/* Build bloom filter from wallet pubkey hashes and outpoints */
void smt_bloom_build_from_wallet(smt_bloom_t *bloom,
                                  const uint8_t (*pubkey_hashes)[20],
                                  int num_keys,
                                  uint32_t tweak);

#endif /* SMT_BLOOM_H */
