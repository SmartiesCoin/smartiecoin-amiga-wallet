/*
 * Smartiecoin Amiga Wallet - RIPEMD-160 implementation
 * Compatible with VBCC compiler for AmigaOS m68k
 *
 * Pure C, no dynamic allocation, big-endian aware.
 * Implements the RIPEMD-160 hash function per ISO/IEC 10118-3.
 *
 * Reference: "RIPEMD-160: A Strengthened Version of RIPEMD"
 *            Hans Dobbertin, Antoon Bosselaers, Bart Preneel (1996)
 */

#include "ripemd160.h"
#include "sha256.h"

/* ------------------------------------------------------------------ */
/* Byte-order helpers                                                  */
/* RIPEMD-160 operates on 32-bit words in LITTLE-ENDIAN byte order.    */
/* m68k is big-endian, so we must swap when reading/writing.           */
/* ------------------------------------------------------------------ */

static uint32_t rmd_read_le32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static void rmd_write_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void rmd_write_le64(uint8_t *p, uint64_t v)
{
    rmd_write_le32(p, (uint32_t)(v & 0xFFFFFFFFUL));
    rmd_write_le32(p + 4, (uint32_t)(v >> 32));
}

/* ------------------------------------------------------------------ */
/* Bit rotation                                                        */
/* ------------------------------------------------------------------ */

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* ------------------------------------------------------------------ */
/* RIPEMD-160 boolean functions                                        */
/* ------------------------------------------------------------------ */

#define F0(x, y, z) ((x) ^ (y) ^ (z))
#define F1(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define F2(x, y, z) (((x) | ~(y)) ^ (z))
#define F3(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define F4(x, y, z) ((x) ^ ((y) | ~(z)))

/* ------------------------------------------------------------------ */
/* Round constants                                                     */
/* ------------------------------------------------------------------ */

/* Left rounds */
#define KL0 0x00000000UL
#define KL1 0x5A827999UL
#define KL2 0x6ED9EBA1UL
#define KL3 0x8F1BBCDCUL
#define KL4 0xA953FD4EUL

/* Right (parallel) rounds */
#define KR0 0x50A28BE6UL
#define KR1 0x5C4DD124UL
#define KR2 0x6D703EF3UL
#define KR3 0x7A6D76E9UL
#define KR4 0x00000000UL

/* ------------------------------------------------------------------ */
/* Round macros                                                        */
/* ------------------------------------------------------------------ */

#define RND(a, b, c, d, e, f, x, k, s) do { \
    (a) += f((b), (c), (d)) + (x) + (k);    \
    (a) = ROL32((a), (s)) + (e);             \
    (c) = ROL32((c), 10);                    \
} while (0)

/* ------------------------------------------------------------------ */
/* Compress one 64-byte block                                          */
/* ------------------------------------------------------------------ */

static void rmd160_compress(uint32_t state[5], const uint8_t block[64])
{
    uint32_t W[16];
    uint32_t al, bl, cl, dl, el;  /* left  path */
    uint32_t ar, br, cr, dr, er;  /* right path */
    int i;

    /* Parse block into 16 little-endian 32-bit words */
    for (i = 0; i < 16; i++) {
        W[i] = rmd_read_le32(block + i * 4);
    }

    al = state[0]; bl = state[1]; cl = state[2]; dl = state[3]; el = state[4];
    ar = state[0]; br = state[1]; cr = state[2]; dr = state[3]; er = state[4];

    /* ---- Left rounds ---- */

    /* Round 1 (F0, KL0) */
    RND(al, bl, cl, dl, el, F0, W[ 0], KL0, 11);
    RND(el, al, bl, cl, dl, F0, W[ 1], KL0, 14);
    RND(dl, el, al, bl, cl, F0, W[ 2], KL0, 15);
    RND(cl, dl, el, al, bl, F0, W[ 3], KL0, 12);
    RND(bl, cl, dl, el, al, F0, W[ 4], KL0,  5);
    RND(al, bl, cl, dl, el, F0, W[ 5], KL0,  8);
    RND(el, al, bl, cl, dl, F0, W[ 6], KL0,  7);
    RND(dl, el, al, bl, cl, F0, W[ 7], KL0,  9);
    RND(cl, dl, el, al, bl, F0, W[ 8], KL0, 11);
    RND(bl, cl, dl, el, al, F0, W[ 9], KL0, 13);
    RND(al, bl, cl, dl, el, F0, W[10], KL0, 14);
    RND(el, al, bl, cl, dl, F0, W[11], KL0, 15);
    RND(dl, el, al, bl, cl, F0, W[12], KL0,  6);
    RND(cl, dl, el, al, bl, F0, W[13], KL0,  7);
    RND(bl, cl, dl, el, al, F0, W[14], KL0,  9);
    RND(al, bl, cl, dl, el, F0, W[15], KL0,  8);

    /* Round 2 (F1, KL1) */
    RND(el, al, bl, cl, dl, F1, W[ 7], KL1,  7);
    RND(dl, el, al, bl, cl, F1, W[ 4], KL1,  6);
    RND(cl, dl, el, al, bl, F1, W[13], KL1,  8);
    RND(bl, cl, dl, el, al, F1, W[ 1], KL1, 13);
    RND(al, bl, cl, dl, el, F1, W[10], KL1, 11);
    RND(el, al, bl, cl, dl, F1, W[ 6], KL1,  9);
    RND(dl, el, al, bl, cl, F1, W[15], KL1,  7);
    RND(cl, dl, el, al, bl, F1, W[ 3], KL1, 15);
    RND(bl, cl, dl, el, al, F1, W[12], KL1,  7);
    RND(al, bl, cl, dl, el, F1, W[ 0], KL1, 12);
    RND(el, al, bl, cl, dl, F1, W[ 9], KL1, 15);
    RND(dl, el, al, bl, cl, F1, W[ 5], KL1,  9);
    RND(cl, dl, el, al, bl, F1, W[ 2], KL1, 11);
    RND(bl, cl, dl, el, al, F1, W[14], KL1,  7);
    RND(al, bl, cl, dl, el, F1, W[11], KL1, 13);
    RND(el, al, bl, cl, dl, F1, W[ 8], KL1, 12);

    /* Round 3 (F2, KL2) */
    RND(dl, el, al, bl, cl, F2, W[ 3], KL2, 11);
    RND(cl, dl, el, al, bl, F2, W[10], KL2, 13);
    RND(bl, cl, dl, el, al, F2, W[14], KL2,  6);
    RND(al, bl, cl, dl, el, F2, W[ 4], KL2,  7);
    RND(el, al, bl, cl, dl, F2, W[ 9], KL2, 14);
    RND(dl, el, al, bl, cl, F2, W[15], KL2,  9);
    RND(cl, dl, el, al, bl, F2, W[ 8], KL2, 13);
    RND(bl, cl, dl, el, al, F2, W[ 1], KL2, 15);
    RND(al, bl, cl, dl, el, F2, W[ 2], KL2, 14);
    RND(el, al, bl, cl, dl, F2, W[ 7], KL2,  8);
    RND(dl, el, al, bl, cl, F2, W[ 0], KL2, 13);
    RND(cl, dl, el, al, bl, F2, W[ 6], KL2,  6);
    RND(bl, cl, dl, el, al, F2, W[13], KL2,  5);
    RND(al, bl, cl, dl, el, F2, W[11], KL2, 12);
    RND(el, al, bl, cl, dl, F2, W[ 5], KL2,  7);
    RND(dl, el, al, bl, cl, F2, W[12], KL2,  5);

    /* Round 4 (F3, KL3) */
    RND(cl, dl, el, al, bl, F3, W[ 1], KL3, 11);
    RND(bl, cl, dl, el, al, F3, W[ 9], KL3, 12);
    RND(al, bl, cl, dl, el, F3, W[11], KL3, 14);
    RND(el, al, bl, cl, dl, F3, W[10], KL3, 15);
    RND(dl, el, al, bl, cl, F3, W[ 0], KL3, 14);
    RND(cl, dl, el, al, bl, F3, W[ 8], KL3, 15);
    RND(bl, cl, dl, el, al, F3, W[12], KL3,  9);
    RND(al, bl, cl, dl, el, F3, W[ 4], KL3,  8);
    RND(el, al, bl, cl, dl, F3, W[13], KL3,  9);
    RND(dl, el, al, bl, cl, F3, W[ 3], KL3, 14);
    RND(cl, dl, el, al, bl, F3, W[ 7], KL3,  5);
    RND(bl, cl, dl, el, al, F3, W[15], KL3,  6);
    RND(al, bl, cl, dl, el, F3, W[14], KL3,  8);
    RND(el, al, bl, cl, dl, F3, W[ 5], KL3,  6);
    RND(dl, el, al, bl, cl, F3, W[ 6], KL3,  5);
    RND(cl, dl, el, al, bl, F3, W[ 2], KL3, 12);

    /* Round 5 (F4, KL4) */
    RND(bl, cl, dl, el, al, F4, W[ 4], KL4,  9);
    RND(al, bl, cl, dl, el, F4, W[ 0], KL4, 15);
    RND(el, al, bl, cl, dl, F4, W[ 5], KL4,  5);
    RND(dl, el, al, bl, cl, F4, W[ 9], KL4, 11);
    RND(cl, dl, el, al, bl, F4, W[ 7], KL4,  6);
    RND(bl, cl, dl, el, al, F4, W[12], KL4,  8);
    RND(al, bl, cl, dl, el, F4, W[ 2], KL4, 13);
    RND(el, al, bl, cl, dl, F4, W[10], KL4, 12);
    RND(dl, el, al, bl, cl, F4, W[14], KL4,  5);
    RND(cl, dl, el, al, bl, F4, W[ 1], KL4, 12);
    RND(bl, cl, dl, el, al, F4, W[ 3], KL4, 13);
    RND(al, bl, cl, dl, el, F4, W[ 8], KL4, 14);
    RND(el, al, bl, cl, dl, F4, W[11], KL4, 11);
    RND(dl, el, al, bl, cl, F4, W[ 6], KL4,  8);
    RND(cl, dl, el, al, bl, F4, W[15], KL4,  5);
    RND(bl, cl, dl, el, al, F4, W[13], KL4,  6);

    /* ---- Right (parallel) rounds ---- */

    /* Round 1' (F4, KR0) */
    RND(ar, br, cr, dr, er, F4, W[ 5], KR0,  8);
    RND(er, ar, br, cr, dr, F4, W[14], KR0,  9);
    RND(dr, er, ar, br, cr, F4, W[ 7], KR0,  9);
    RND(cr, dr, er, ar, br, F4, W[ 0], KR0, 11);
    RND(br, cr, dr, er, ar, F4, W[ 9], KR0, 13);
    RND(ar, br, cr, dr, er, F4, W[ 2], KR0, 15);
    RND(er, ar, br, cr, dr, F4, W[11], KR0, 15);
    RND(dr, er, ar, br, cr, F4, W[ 4], KR0,  5);
    RND(cr, dr, er, ar, br, F4, W[13], KR0,  7);
    RND(br, cr, dr, er, ar, F4, W[ 6], KR0,  7);
    RND(ar, br, cr, dr, er, F4, W[15], KR0,  8);
    RND(er, ar, br, cr, dr, F4, W[ 8], KR0, 11);
    RND(dr, er, ar, br, cr, F4, W[ 1], KR0, 14);
    RND(cr, dr, er, ar, br, F4, W[10], KR0, 14);
    RND(br, cr, dr, er, ar, F4, W[ 3], KR0, 12);
    RND(ar, br, cr, dr, er, F4, W[12], KR0,  6);

    /* Round 2' (F3, KR1) */
    RND(er, ar, br, cr, dr, F3, W[ 6], KR1,  9);
    RND(dr, er, ar, br, cr, F3, W[11], KR1, 13);
    RND(cr, dr, er, ar, br, F3, W[ 3], KR1, 15);
    RND(br, cr, dr, er, ar, F3, W[ 7], KR1,  7);
    RND(ar, br, cr, dr, er, F3, W[ 0], KR1, 12);
    RND(er, ar, br, cr, dr, F3, W[13], KR1,  8);
    RND(dr, er, ar, br, cr, F3, W[ 5], KR1,  9);
    RND(cr, dr, er, ar, br, F3, W[10], KR1, 11);
    RND(br, cr, dr, er, ar, F3, W[14], KR1,  7);
    RND(ar, br, cr, dr, er, F3, W[15], KR1,  7);
    RND(er, ar, br, cr, dr, F3, W[ 8], KR1, 12);
    RND(dr, er, ar, br, cr, F3, W[12], KR1,  7);
    RND(cr, dr, er, ar, br, F3, W[ 4], KR1,  6);
    RND(br, cr, dr, er, ar, F3, W[ 9], KR1, 15);
    RND(ar, br, cr, dr, er, F3, W[ 1], KR1, 13);
    RND(er, ar, br, cr, dr, F3, W[ 2], KR1, 11);

    /* Round 3' (F2, KR2) */
    RND(dr, er, ar, br, cr, F2, W[15], KR2,  9);
    RND(cr, dr, er, ar, br, F2, W[ 5], KR2,  7);
    RND(br, cr, dr, er, ar, F2, W[ 1], KR2, 15);
    RND(ar, br, cr, dr, er, F2, W[ 3], KR2, 11);
    RND(er, ar, br, cr, dr, F2, W[ 7], KR2,  8);
    RND(dr, er, ar, br, cr, F2, W[14], KR2,  6);
    RND(cr, dr, er, ar, br, F2, W[ 6], KR2,  6);
    RND(br, cr, dr, er, ar, F2, W[ 9], KR2, 14);
    RND(ar, br, cr, dr, er, F2, W[11], KR2, 12);
    RND(er, ar, br, cr, dr, F2, W[ 8], KR2, 13);
    RND(dr, er, ar, br, cr, F2, W[12], KR2,  5);
    RND(cr, dr, er, ar, br, F2, W[ 2], KR2, 14);
    RND(br, cr, dr, er, ar, F2, W[10], KR2, 13);
    RND(ar, br, cr, dr, er, F2, W[ 0], KR2, 13);
    RND(er, ar, br, cr, dr, F2, W[ 4], KR2,  7);
    RND(dr, er, ar, br, cr, F2, W[13], KR2,  5);

    /* Round 4' (F1, KR3) */
    RND(cr, dr, er, ar, br, F1, W[ 8], KR3, 15);
    RND(br, cr, dr, er, ar, F1, W[ 6], KR3,  5);
    RND(ar, br, cr, dr, er, F1, W[ 4], KR3,  8);
    RND(er, ar, br, cr, dr, F1, W[ 1], KR3, 11);
    RND(dr, er, ar, br, cr, F1, W[ 3], KR3, 14);
    RND(cr, dr, er, ar, br, F1, W[11], KR3, 14);
    RND(br, cr, dr, er, ar, F1, W[15], KR3,  6);
    RND(ar, br, cr, dr, er, F1, W[ 0], KR3, 14);
    RND(er, ar, br, cr, dr, F1, W[ 5], KR3,  6);
    RND(dr, er, ar, br, cr, F1, W[12], KR3,  9);
    RND(cr, dr, er, ar, br, F1, W[ 2], KR3, 12);
    RND(br, cr, dr, er, ar, F1, W[13], KR3,  9);
    RND(ar, br, cr, dr, er, F1, W[ 9], KR3, 12);
    RND(er, ar, br, cr, dr, F1, W[ 7], KR3,  5);
    RND(dr, er, ar, br, cr, F1, W[10], KR3, 15);
    RND(cr, dr, er, ar, br, F1, W[14], KR3,  8);

    /* Round 5' (F0, KR4) */
    RND(br, cr, dr, er, ar, F0, W[12], KR4,  8);
    RND(ar, br, cr, dr, er, F0, W[15], KR4,  5);
    RND(er, ar, br, cr, dr, F0, W[10], KR4, 12);
    RND(dr, er, ar, br, cr, F0, W[ 4], KR4,  9);
    RND(cr, dr, er, ar, br, F0, W[ 1], KR4, 12);
    RND(br, cr, dr, er, ar, F0, W[ 5], KR4,  5);
    RND(ar, br, cr, dr, er, F0, W[ 8], KR4, 14);
    RND(er, ar, br, cr, dr, F0, W[ 7], KR4,  6);
    RND(dr, er, ar, br, cr, F0, W[ 6], KR4,  8);
    RND(cr, dr, er, ar, br, F0, W[ 2], KR4, 13);
    RND(br, cr, dr, er, ar, F0, W[13], KR4,  6);
    RND(ar, br, cr, dr, er, F0, W[14], KR4,  5);
    RND(er, ar, br, cr, dr, F0, W[ 0], KR4, 15);
    RND(dr, er, ar, br, cr, F0, W[ 3], KR4, 13);
    RND(cr, dr, er, ar, br, F0, W[ 9], KR4, 11);
    RND(br, cr, dr, er, ar, F0, W[11], KR4, 11);

    /* ---- Final addition ---- */
    {
        uint32_t t;
        t = state[1] + cl + dr;
        state[1] = state[2] + dl + er;
        state[2] = state[3] + el + ar;
        state[3] = state[4] + al + br;
        state[4] = state[0] + bl + cr;
        state[0] = t;
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void smt_ripemd160_init(smt_ripemd160_ctx *ctx)
{
    ctx->state[0] = 0x67452301UL;
    ctx->state[1] = 0xEFCDAB89UL;
    ctx->state[2] = 0x98BADCFEUL;
    ctx->state[3] = 0x10325476UL;
    ctx->state[4] = 0xC3D2E1F0UL;
    ctx->bitcount = 0;
    ctx->buflen   = 0;
}

void smt_ripemd160_update(smt_ripemd160_ctx *ctx, const uint8_t *data,
                          size_t len)
{
    while (len > 0) {
        uint32_t space = SMT_RIPEMD160_BLOCK_SIZE - ctx->buflen;
        uint32_t chunk = (len < space) ? (uint32_t)len : space;
        uint32_t i;

        for (i = 0; i < chunk; i++) {
            ctx->buffer[ctx->buflen + i] = data[i];
        }
        ctx->buflen += chunk;
        data += chunk;
        len  -= chunk;

        if (ctx->buflen == SMT_RIPEMD160_BLOCK_SIZE) {
            rmd160_compress(ctx->state, ctx->buffer);
            ctx->bitcount += (uint64_t)SMT_RIPEMD160_BLOCK_SIZE * 8;
            ctx->buflen = 0;
        }
    }
}

void smt_ripemd160_final(smt_ripemd160_ctx *ctx, uint8_t hash[20])
{
    uint64_t totalbits;
    int i;

    /* Total bit count including the remaining buffer bytes */
    totalbits = ctx->bitcount + (uint64_t)ctx->buflen * 8;

    /* Append 0x80 byte */
    ctx->buffer[ctx->buflen++] = 0x80;

    /* If there isn't room for the 8-byte length, pad and compress */
    if (ctx->buflen > 56) {
        while (ctx->buflen < SMT_RIPEMD160_BLOCK_SIZE) {
            ctx->buffer[ctx->buflen++] = 0x00;
        }
        rmd160_compress(ctx->state, ctx->buffer);
        ctx->buflen = 0;
    }

    /* Pad with zeros up to byte 56 */
    while (ctx->buflen < 56) {
        ctx->buffer[ctx->buflen++] = 0x00;
    }

    /* Append total bit count as 64-bit little-endian */
    rmd_write_le64(ctx->buffer + 56, totalbits);

    /* Final compress */
    rmd160_compress(ctx->state, ctx->buffer);

    /* Write hash in little-endian byte order */
    for (i = 0; i < 5; i++) {
        rmd_write_le32(hash + i * 4, ctx->state[i]);
    }

    /* Clear sensitive data */
    smt_memzero(ctx, sizeof(*ctx));
}

void smt_ripemd160(const uint8_t *data, size_t len, uint8_t hash[20])
{
    smt_ripemd160_ctx ctx;
    smt_ripemd160_init(&ctx);
    smt_ripemd160_update(&ctx, data, len);
    smt_ripemd160_final(&ctx, hash);
}

void smt_hash160(const uint8_t *data, size_t len, uint8_t hash[20])
{
    uint8_t sha_hash[SMT_SHA256_DIGEST_SIZE];

    /* Step 1: SHA-256 */
    smt_sha256(data, len, sha_hash);

    /* Step 2: RIPEMD-160 of the SHA-256 result */
    smt_ripemd160(sha_hash, SMT_SHA256_DIGEST_SIZE, hash);

    /* Clear intermediate hash */
    smt_memzero(sha_hash, sizeof(sha_hash));
}
