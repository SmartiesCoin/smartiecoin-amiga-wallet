/*
 * Smartiecoin Amiga Wallet - Bloom filter (BIP37)
 * MurmurHash3 based bloom filter for SPV transaction filtering
 */
#include "bloom.h"

/* MurmurHash3 (32-bit) - used by BIP37 bloom filters */
static uint32_t murmurhash3(const uint8_t *data, size_t len,
                            uint32_t seed) {
    uint32_t h = seed;
    uint32_t k;
    size_t i;
    size_t nblocks = len / 4;
    const uint32_t c1 = 0xCC9E2D51;
    const uint32_t c2 = 0x1B873593;

    /* Body */
    for (i = 0; i < nblocks; i++) {
        k = (uint32_t)data[i * 4]
          | ((uint32_t)data[i * 4 + 1] << 8)
          | ((uint32_t)data[i * 4 + 2] << 16)
          | ((uint32_t)data[i * 4 + 3] << 24);

        k *= c1;
        k = (k << 15) | (k >> 17);
        k *= c2;

        h ^= k;
        h = (h << 13) | (h >> 19);
        h = h * 5 + 0xE6546B64;
    }

    /* Tail */
    k = 0;
    {
        const uint8_t *tail = data + nblocks * 4;
        switch (len & 3) {
            case 3: k ^= (uint32_t)tail[2] << 16; /* fall through */
            case 2: k ^= (uint32_t)tail[1] << 8;  /* fall through */
            case 1: k ^= (uint32_t)tail[0];
                    k *= c1;
                    k = (k << 15) | (k >> 17);
                    k *= c2;
                    h ^= k;
        }
    }

    /* Finalization */
    h ^= (uint32_t)len;
    h ^= h >> 16;
    h *= 0x85EBCA6B;
    h ^= h >> 13;
    h *= 0xC2B2AE35;
    h ^= h >> 16;

    return h;
}

/* Simple log2 approximation for sizing */
static uint32_t approx_log2(double x) {
    /* Very rough approximation good enough for bloom filter sizing */
    uint32_t result = 0;
    while (x >= 2.0) {
        x /= 2.0;
        result++;
    }
    return result;
}

void smt_bloom_create(smt_bloom_t *bloom, int num_elements, double fp_rate,
                      uint32_t tweak, uint8_t flags) {
    /*
     * Optimal filter size: -1.0 / (LN2 * LN2) * n * ln(fp_rate)
     * Optimal hash functions: filter_size / n * LN2
     *
     * Using approximations since we can't use math.h on AmigaOS easily
     */
    uint32_t filter_bits;
    uint32_t filter_bytes;

    smt_memzero(bloom, sizeof(smt_bloom_t));

    /* Approximate: for fp_rate=0.0001, -ln(fp_rate) ~ 9.2 */
    /* filter_bits = n * 9.2 / (ln2^2) = n * 9.2 / 0.48 = n * 19.2 */
    if (fp_rate <= 0.00001) {
        filter_bits = (uint32_t)(num_elements * 24);
    } else if (fp_rate <= 0.0001) {
        filter_bits = (uint32_t)(num_elements * 20);
    } else if (fp_rate <= 0.001) {
        filter_bits = (uint32_t)(num_elements * 15);
    } else if (fp_rate <= 0.01) {
        filter_bits = (uint32_t)(num_elements * 10);
    } else {
        filter_bits = (uint32_t)(num_elements * 8);
    }

    filter_bytes = (filter_bits + 7) / 8;
    if (filter_bytes > SMT_BLOOM_MAX_SIZE)
        filter_bytes = SMT_BLOOM_MAX_SIZE;
    if (filter_bytes < 1)
        filter_bytes = 1;

    bloom->filter_size = filter_bytes;

    /* Optimal number of hash functions: (m/n) * ln(2) ~ (m/n) * 0.693 */
    bloom->num_hash_funcs = (filter_bytes * 8 * 693) / ((uint32_t)num_elements * 1000);
    if (bloom->num_hash_funcs > SMT_BLOOM_MAX_FUNCS)
        bloom->num_hash_funcs = SMT_BLOOM_MAX_FUNCS;
    if (bloom->num_hash_funcs < 1)
        bloom->num_hash_funcs = 1;

    bloom->tweak = tweak;
    bloom->flags = flags;
}

void smt_bloom_add(smt_bloom_t *bloom, const uint8_t *data, size_t len) {
    uint32_t i;
    for (i = 0; i < bloom->num_hash_funcs; i++) {
        uint32_t seed = i * 0xFBA4C795 + bloom->tweak;
        uint32_t bit_idx = murmurhash3(data, len, seed) % (bloom->filter_size * 8);
        bloom->filter[bit_idx / 8] |= (1 << (bit_idx % 8));
    }
}

smt_bool smt_bloom_contains(const smt_bloom_t *bloom, const uint8_t *data, size_t len) {
    uint32_t i;
    for (i = 0; i < bloom->num_hash_funcs; i++) {
        uint32_t seed = i * 0xFBA4C795 + bloom->tweak;
        uint32_t bit_idx = murmurhash3(data, len, seed) % (bloom->filter_size * 8);
        if (!(bloom->filter[bit_idx / 8] & (1 << (bit_idx % 8))))
            return SMT_FALSE;
    }
    return SMT_TRUE;
}

void smt_bloom_clear(smt_bloom_t *bloom) {
    smt_memzero(bloom->filter, bloom->filter_size);
}

void smt_bloom_build_from_wallet(smt_bloom_t *bloom,
                                  const uint8_t (*pubkey_hashes)[20],
                                  int num_keys,
                                  uint32_t tweak) {
    int i;

    /* Size for our keys with very low false positive rate */
    smt_bloom_create(bloom, num_keys > 0 ? num_keys : 1, 0.0001, tweak,
                     SMT_BLOOM_UPDATE_ALL);

    /* Add each pubkey hash */
    for (i = 0; i < num_keys; i++) {
        smt_bloom_add(bloom, pubkey_hashes[i], 20);
    }
}
