/*
 * Smartiecoin Amiga Wallet - RIPEMD-160 implementation
 * Compatible with VBCC compiler for AmigaOS m68k
 *
 * Pure C, no dynamic allocation, big-endian aware.
 * Implements the RIPEMD-160 hash function (ISO/IEC 10118-3).
 */
#ifndef SMT_RIPEMD160_H
#define SMT_RIPEMD160_H

#include "../types.h"

#define SMT_RIPEMD160_BLOCK_SIZE  64
#define SMT_RIPEMD160_DIGEST_SIZE 20

typedef struct {
    uint32_t state[5];                       /* hash state H0..H4          */
    uint64_t bitcount;                       /* total bits processed       */
    uint8_t  buffer[SMT_RIPEMD160_BLOCK_SIZE]; /* partial block buffer     */
    uint32_t buflen;                         /* bytes currently in buffer  */
} smt_ripemd160_ctx;

/*
 * Core streaming interface
 */
void smt_ripemd160_init(smt_ripemd160_ctx *ctx);
void smt_ripemd160_update(smt_ripemd160_ctx *ctx, const uint8_t *data,
                          size_t len);
void smt_ripemd160_final(smt_ripemd160_ctx *ctx, uint8_t hash[20]);

/*
 * Convenience: single-shot RIPEMD-160
 */
void smt_ripemd160(const uint8_t *data, size_t len, uint8_t hash[20]);

/*
 * HASH160: RIPEMD-160(SHA-256(data))
 * This is the standard hash used in Bitcoin/Smartiecoin for
 * public key hashing (P2PKH addresses, P2SH script hashes).
 */
void smt_hash160(const uint8_t *data, size_t len, uint8_t hash[20]);

#endif /* SMT_RIPEMD160_H */
