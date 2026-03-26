/*
 * Smartiecoin Amiga Wallet - secp256k1 elliptic curve implementation
 * Compatible with VBCC compiler for AmigaOS m68k
 *
 * Pure C, no dynamic allocation, big-endian aware.
 * Implements core ECDSA operations on the secp256k1 curve.
 *
 * WARNING: This implementation is functionally correct but not
 * hardened against side-channel attacks (timing, power analysis).
 * Suitable for low-value hobby use on Amiga hardware only.
 */
#ifndef SMT_SECP256K1_H
#define SMT_SECP256K1_H

#include "../types.h"

/*
 * 256-bit unsigned integer: 8 x uint32_t in big-endian word order.
 * word[0] is the most significant 32-bit limb.
 */
typedef uint32_t smt_uint256_t[8];

/*
 * Elliptic curve point in affine coordinates.
 * When infinity is non-zero, x and y are undefined (point at infinity).
 */
typedef struct {
    smt_uint256_t x;
    smt_uint256_t y;
    int infinity;
} smt_point_t;

/* ------------------------------------------------------------------ */
/*  256-bit integer utilities                                         */
/* ------------------------------------------------------------------ */

/* Convert 32 big-endian bytes to uint256 */
void smt_uint256_from_bytes(smt_uint256_t out, const uint8_t bytes[32]);

/* Convert uint256 to 32 big-endian bytes */
void smt_uint256_to_bytes(const smt_uint256_t in, uint8_t bytes[32]);

/* Returns 1 if a == 0, else 0 */
int smt_uint256_is_zero(const smt_uint256_t a);

/* Returns -1, 0, or 1 for a < b, a == b, a > b */
int smt_uint256_cmp(const smt_uint256_t a, const smt_uint256_t b);

/* ------------------------------------------------------------------ */
/*  Field arithmetic (mod p)                                          */
/*  p = 2^256 - 2^32 - 977                                           */
/*    = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE    */
/*      FFFFFC2F                                                      */
/* ------------------------------------------------------------------ */

void smt_field_add(smt_uint256_t r, const smt_uint256_t a,
                   const smt_uint256_t b);

void smt_field_sub(smt_uint256_t r, const smt_uint256_t a,
                   const smt_uint256_t b);

void smt_field_mul(smt_uint256_t r, const smt_uint256_t a,
                   const smt_uint256_t b);

/* Modular inverse via Fermat's little theorem: a^(p-2) mod p */
void smt_field_inv(smt_uint256_t r, const smt_uint256_t a);

/* ------------------------------------------------------------------ */
/*  Scalar arithmetic (mod n)                                         */
/*  n = order of secp256k1 generator G                                */
/* ------------------------------------------------------------------ */

void smt_scalar_mod_n(smt_uint256_t r, const smt_uint256_t a);
void smt_scalar_add_mod_n(smt_uint256_t r, const smt_uint256_t a,
                          const smt_uint256_t b);
void smt_scalar_mul_mod_n(smt_uint256_t r, const smt_uint256_t a,
                          const smt_uint256_t b);
void smt_scalar_inv_mod_n(smt_uint256_t r, const smt_uint256_t a);

/* ------------------------------------------------------------------ */
/*  EC point operations on secp256k1: y^2 = x^3 + 7                  */
/* ------------------------------------------------------------------ */

/* Point doubling: r = 2*p */
void smt_point_double(smt_point_t *r, const smt_point_t *p);

/* Point addition: r = p + q */
void smt_point_add(smt_point_t *r, const smt_point_t *p,
                   const smt_point_t *q);

/* Scalar multiplication: r = k * p (double-and-add) */
void smt_point_mul(smt_point_t *r, const smt_point_t *p,
                   const smt_uint256_t k);

/* ------------------------------------------------------------------ */
/*  High-level ECDSA operations                                      */
/* ------------------------------------------------------------------ */

/*
 * Compute compressed public key (33 bytes) from 32-byte private key.
 * pubkey[0] = 0x02 or 0x03 depending on y parity.
 * pubkey[1..32] = x coordinate in big-endian.
 */
void smt_ec_pubkey_create(uint8_t pubkey[33], const uint8_t privkey[32]);

/*
 * Create a DER-encoded ECDSA signature.
 * Uses RFC 6979 deterministic k for safety.
 * sig must point to a buffer of at least 72 bytes.
 * *sig_len receives the actual DER length.
 * Returns 1 on success, 0 on failure (invalid key, etc).
 */
int smt_ecdsa_sign(uint8_t *sig, size_t *sig_len,
                   const uint8_t hash[32], const uint8_t privkey[32]);

/*
 * Verify a DER-encoded ECDSA signature against a compressed public key.
 * Returns 1 if valid, 0 if invalid.
 */
int smt_ecdsa_verify(const uint8_t *sig, size_t sig_len,
                     const uint8_t hash[32], const uint8_t pubkey[33]);

/* ------------------------------------------------------------------ */
/*  HMAC-SHA256 (used internally for RFC 6979, exposed for reuse)     */
/* ------------------------------------------------------------------ */

void smt_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[32]);

#endif /* SMT_SECP256K1_H */
