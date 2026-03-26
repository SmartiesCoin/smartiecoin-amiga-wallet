/*
 * Smartiecoin Amiga Wallet - SHA-256 implementation
 * Compatible with VBCC compiler for AmigaOS m68k
 *
 * Pure C, no dynamic allocation, big-endian aware.
 * Implements FIPS 180-4 SHA-256.
 */
#ifndef SMT_SHA256_H
#define SMT_SHA256_H

#include "../types.h"

#define SMT_SHA256_BLOCK_SIZE  64
#define SMT_SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];                   /* hash state H0..H7          */
    uint64_t bitcount;                   /* total bits processed       */
    uint8_t  buffer[SMT_SHA256_BLOCK_SIZE]; /* partial block buffer    */
    uint32_t buflen;                     /* bytes currently in buffer  */
} smt_sha256_ctx;

/*
 * Core streaming interface
 */
void smt_sha256_init(smt_sha256_ctx *ctx);
void smt_sha256_update(smt_sha256_ctx *ctx, const uint8_t *data, size_t len);
void smt_sha256_final(smt_sha256_ctx *ctx, uint8_t hash[32]);

/*
 * Convenience: single-shot SHA-256
 */
void smt_sha256(const uint8_t *data, size_t len, uint8_t hash[32]);

/*
 * Double SHA-256: SHA-256(SHA-256(data))
 * This is the standard hash used throughout Bitcoin/Smartiecoin
 * for block headers, transaction hashes, merkle trees, etc.
 */
void smt_sha256d(const uint8_t *data, size_t len, uint8_t hash[32]);

/*
 * Alias for smt_sha256d (matches Bitcoin Core naming: Hash256)
 */
void smt_hash256(const uint8_t *data, size_t len, uint8_t hash[32]);

#endif /* SMT_SHA256_H */
