/*
 * Smartiecoin Amiga Wallet - SHA-256 implementation
 * Compatible with VBCC compiler for AmigaOS m68k
 *
 * FIPS 180-4 compliant SHA-256.
 * Pure C, no dynamic allocation, big-endian aware.
 *
 * Reference: https://csrc.nist.gov/publications/detail/fips/180/4/final
 */

#include "sha256.h"

/* ---------- SHA-256 round constants (section 4.2.2) ---------- */

static const uint32_t K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

/* ---------- Bit manipulation (section 3.2, 4.1.2) ---------- */

#define ROTR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x, n)   ((x) >> (n))

#define CH(x, y, z)   (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define SIGMA0(x)  (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA1(x)  (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x)  (ROTR(x,  7) ^ ROTR(x, 18) ^ SHR(x,  3))
#define sigma1(x)  (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

/* ---------- Big-endian load/store ---------- */
/*
 * SHA-256 operates on 32-bit big-endian words.
 * m68k is natively big-endian, so on Amiga we could read directly,
 * but byte-level access is portable and avoids alignment issues.
 */

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |
           ((uint32_t)p[3]);
}

static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v);
}

static void store_be64(uint8_t *p, uint64_t v)
{
    store_be32(p,     (uint32_t)(v >> 32));
    store_be32(p + 4, (uint32_t)(v & 0xFFFFFFFFUL));
}

/* ---------- Process one 512-bit block (section 6.2.2) ---------- */

static void sha256_transform(uint32_t state[8], const uint8_t block[64])
{
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t T1, T2;
    int t;

    /* 1. Prepare the message schedule */
    for (t = 0; t < 16; t++) {
        W[t] = load_be32(block + t * 4);
    }
    for (t = 16; t < 64; t++) {
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
    }

    /* 2. Initialize working variables */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    /* 3. Compression loop */
    for (t = 0; t < 64; t++) {
        T1 = h + SIGMA1(e) + CH(e, f, g) + K[t] + W[t];
        T2 = SIGMA0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    /* 4. Update hash state */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

/* ---------- Public API ---------- */

void smt_sha256_init(smt_sha256_ctx *ctx)
{
    /* Initial hash values (section 5.3.3) */
    ctx->state[0] = 0x6a09e667UL;
    ctx->state[1] = 0xbb67ae85UL;
    ctx->state[2] = 0x3c6ef372UL;
    ctx->state[3] = 0xa54ff53aUL;
    ctx->state[4] = 0x510e527fUL;
    ctx->state[5] = 0x9b05688cUL;
    ctx->state[6] = 0x1f83d9abUL;
    ctx->state[7] = 0x5be0cd19UL;

    ctx->bitcount = 0;
    ctx->buflen   = 0;
}

void smt_sha256_update(smt_sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t i;

    ctx->bitcount += (uint64_t)len * 8;

    /* If we have buffered data, try to complete a block */
    if (ctx->buflen > 0) {
        size_t need = SMT_SHA256_BLOCK_SIZE - ctx->buflen;
        if (len < need) {
            /* Not enough to complete a block; just buffer */
            for (i = 0; i < len; i++) {
                ctx->buffer[ctx->buflen + i] = data[i];
            }
            ctx->buflen += (uint32_t)len;
            return;
        }
        /* Complete the block */
        for (i = 0; i < need; i++) {
            ctx->buffer[ctx->buflen + i] = data[i];
        }
        sha256_transform(ctx->state, ctx->buffer);
        data += need;
        len  -= need;
        ctx->buflen = 0;
    }

    /* Process full blocks directly from input */
    while (len >= SMT_SHA256_BLOCK_SIZE) {
        sha256_transform(ctx->state, data);
        data += SMT_SHA256_BLOCK_SIZE;
        len  -= SMT_SHA256_BLOCK_SIZE;
    }

    /* Buffer remaining bytes */
    for (i = 0; i < len; i++) {
        ctx->buffer[i] = data[i];
    }
    ctx->buflen = (uint32_t)len;
}

void smt_sha256_final(smt_sha256_ctx *ctx, uint8_t hash[32])
{
    size_t i;
    uint32_t pad_start;

    /*
     * Pad the message per FIPS 180-4 section 5.1.1:
     *   - append bit '1' (0x80 byte)
     *   - append zeros until length = 448 mod 512 bits (56 mod 64 bytes)
     *   - append original message length as 64-bit big-endian
     */

    pad_start = ctx->buflen;

    /* Append 0x80 */
    ctx->buffer[pad_start] = 0x80;
    pad_start++;

    if (pad_start > 56) {
        /* Not enough room for the length field; pad this block and process */
        for (i = pad_start; i < SMT_SHA256_BLOCK_SIZE; i++) {
            ctx->buffer[i] = 0;
        }
        sha256_transform(ctx->state, ctx->buffer);
        pad_start = 0;
    }

    /* Zero-pad up to byte 56 */
    for (i = pad_start; i < 56; i++) {
        ctx->buffer[i] = 0;
    }

    /* Append bit length as big-endian 64-bit integer */
    store_be64(ctx->buffer + 56, ctx->bitcount);

    sha256_transform(ctx->state, ctx->buffer);

    /* Write output hash in big-endian */
    for (i = 0; i < 8; i++) {
        store_be32(hash + i * 4, ctx->state[i]);
    }

    /* Clear sensitive state */
    smt_memzero(ctx, sizeof(smt_sha256_ctx));
}

void smt_sha256(const uint8_t *data, size_t len, uint8_t hash[32])
{
    smt_sha256_ctx ctx;
    smt_sha256_init(&ctx);
    smt_sha256_update(&ctx, data, len);
    smt_sha256_final(&ctx, hash);
}

void smt_sha256d(const uint8_t *data, size_t len, uint8_t hash[32])
{
    /* First pass */
    smt_sha256(data, len, hash);
    /* Second pass: hash the 32-byte digest */
    smt_sha256(hash, SMT_SHA256_DIGEST_SIZE, hash);
}

void smt_hash256(const uint8_t *data, size_t len, uint8_t hash[32])
{
    smt_sha256d(data, len, hash);
}
