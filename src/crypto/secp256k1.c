/*
 * Smartiecoin Amiga Wallet - secp256k1 elliptic curve implementation
 * Compatible with VBCC compiler for AmigaOS m68k
 *
 * Pure C, no dynamic allocation, big-endian aware.
 *
 * Curve: y^2 = x^3 + 7 over F_p
 * p = 2^256 - 2^32 - 977
 * n = order of generator G
 *
 * All 256-bit integers use big-endian word order: word[0] = MSW.
 */

#include "secp256k1.h"
#include "sha256.h"

/* ================================================================== */
/*  Constants                                                         */
/* ================================================================== */

/* Field prime p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F */
static const smt_uint256_t SECP256K1_P = {
    0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL,
    0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL, 0xFFFFFC2FUL
};

/* Curve order n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 */
static const smt_uint256_t SECP256K1_N = {
    0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL,
    0xBAAEDCE6UL, 0xAF48A03BUL, 0xBFD25E8CUL, 0xD0364141UL
};

/* n/2 -- for low-S normalization */
static const smt_uint256_t SECP256K1_N_HALF = {
    0x7FFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL,
    0x5D576E73UL, 0x57A4501DUL, 0xDFE92F46UL, 0x681B20A0UL
};

/* Generator point G */
static const smt_uint256_t SECP256K1_GX = {
    0x79BE667EUL, 0xF9DCBBACUL, 0x55A06295UL, 0xCE870B07UL,
    0x029BFCDBUL, 0x2DCE28D9UL, 0x59F2815BUL, 0x16F81798UL
};

static const smt_uint256_t SECP256K1_GY = {
    0x483ADA77UL, 0x26A3C465UL, 0x5DA4FBFCUL, 0x0E1108A8UL,
    0xFD17B448UL, 0xA6855419UL, 0x9C47D08FUL, 0xFB10D4B8UL
};

/* p - 2, for Fermat inverse mod p */
static const smt_uint256_t SECP256K1_P_MINUS_2 = {
    0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL,
    0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL, 0xFFFFFC2DUL
};

/* n - 2, for Fermat inverse mod n */
static const smt_uint256_t SECP256K1_N_MINUS_2 = {
    0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL,
    0xBAAEDCE6UL, 0xAF48A03BUL, 0xBFD25E8CUL, 0xD036413FUL
};

/* ================================================================== */
/*  Internal helpers                                                  */
/* ================================================================== */

static void uint256_zero(smt_uint256_t r)
{
    int i;
    for (i = 0; i < 8; i++) r[i] = 0;
}

static void uint256_copy(smt_uint256_t r, const smt_uint256_t a)
{
    int i;
    for (i = 0; i < 8; i++) r[i] = a[i];
}

static void uint256_set_word(smt_uint256_t r, uint32_t w)
{
    int i;
    for (i = 0; i < 7; i++) r[i] = 0;
    r[7] = w;
}

/* ================================================================== */
/*  256-bit integer utilities                                         */
/* ================================================================== */

void smt_uint256_from_bytes(smt_uint256_t out, const uint8_t bytes[32])
{
    int i;
    for (i = 0; i < 8; i++) {
        const uint8_t *b = bytes + i * 4;
        out[i] = ((uint32_t)b[0] << 24) |
                 ((uint32_t)b[1] << 16) |
                 ((uint32_t)b[2] <<  8) |
                 ((uint32_t)b[3]);
    }
}

void smt_uint256_to_bytes(const smt_uint256_t in, uint8_t bytes[32])
{
    int i;
    for (i = 0; i < 8; i++) {
        bytes[i * 4    ] = (uint8_t)(in[i] >> 24);
        bytes[i * 4 + 1] = (uint8_t)(in[i] >> 16);
        bytes[i * 4 + 2] = (uint8_t)(in[i] >>  8);
        bytes[i * 4 + 3] = (uint8_t)(in[i]      );
    }
}

int smt_uint256_is_zero(const smt_uint256_t a)
{
    int i;
    uint32_t acc = 0;
    for (i = 0; i < 8; i++) acc |= a[i];
    return acc == 0;
}

int smt_uint256_cmp(const smt_uint256_t a, const smt_uint256_t b)
{
    int i;
    for (i = 0; i < 8; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return  1;
    }
    return 0;
}

/* ================================================================== */
/*  Raw 256-bit add/sub (no modular reduction)                        */
/* ================================================================== */

/* r = a + b, returns carry (0 or 1) */
static uint32_t uint256_add_raw(smt_uint256_t r,
                                const smt_uint256_t a,
                                const smt_uint256_t b)
{
    int i;
    uint64_t carry = 0;
    for (i = 7; i >= 0; i--) {
        carry += (uint64_t)a[i] + (uint64_t)b[i];
        r[i] = (uint32_t)(carry & 0xFFFFFFFFUL);
        carry >>= 32;
    }
    return (uint32_t)carry;
}

/* r = a - b, returns borrow (0 or 1) */
static uint32_t uint256_sub_raw(smt_uint256_t r,
                                const smt_uint256_t a,
                                const smt_uint256_t b)
{
    int i;
    int64_t borrow = 0;
    for (i = 7; i >= 0; i--) {
        borrow += (int64_t)(uint64_t)a[i] - (int64_t)(uint64_t)b[i];
        if (borrow < 0) {
            r[i] = (uint32_t)(borrow + 0x100000000LL);
            borrow = -1;
        } else {
            r[i] = (uint32_t)borrow;
            borrow = 0;
        }
    }
    return (uint32_t)(borrow != 0 ? 1 : 0);
}

/* ================================================================== */
/*  Field arithmetic (mod p)                                          */
/* ================================================================== */

void smt_field_add(smt_uint256_t r, const smt_uint256_t a,
                   const smt_uint256_t b)
{
    uint32_t carry;

    carry = uint256_add_raw(r, a, b);

    /* If carry or r >= p, subtract p */
    if (carry || smt_uint256_cmp(r, SECP256K1_P) >= 0) {
        uint256_sub_raw(r, r, SECP256K1_P);
    }
}

void smt_field_sub(smt_uint256_t r, const smt_uint256_t a,
                   const smt_uint256_t b)
{
    uint32_t borrow;

    borrow = uint256_sub_raw(r, a, b);

    /* If borrow, add p back */
    if (borrow) {
        uint256_add_raw(r, r, SECP256K1_P);
    }
}

/*
 * Field multiplication: r = a * b mod p
 *
 * Strategy: schoolbook 8x8 limb multiply into 16-limb product,
 * then reduce mod p using the special structure of p.
 *
 * p = 2^256 - C where C = 2^32 + 977 = 0x1000003D1
 * So for a 512-bit product T = T_hi * 2^256 + T_lo:
 *   T mod p = T_lo + T_hi * C (mod p)
 *
 * We repeat the reduction since T_hi * C may still exceed p.
 */
void smt_field_mul(smt_uint256_t r, const smt_uint256_t a,
                   const smt_uint256_t b)
{
    uint32_t prod[16]; /* 512-bit product, big-endian: prod[0]=MSW */
    uint64_t acc;
    int i, j;
    uint64_t carry;

    /* Zero the product */
    for (i = 0; i < 16; i++) prod[i] = 0;

    /*
     * Schoolbook multiply: a[i] * b[j] -> prod[i+j+1] (with offset
     * because indices start from MSW).
     *
     * a has limbs a[0..7] (a[0]=MSW), same for b.
     * Product limb at position i+j (0-based from MSW) accumulates
     * a[i]*b[j]. But since each multiply produces at most a 64-bit
     * result, we process column by column.
     */
    for (i = 7; i >= 0; i--) {
        carry = 0;
        for (j = 7; j >= 0; j--) {
            int pos = i + j + 1; /* 1-based offset: max = 15, min = 1 */
            acc = (uint64_t)a[i] * (uint64_t)b[j]
                + (uint64_t)prod[pos] + carry;
            prod[pos] = (uint32_t)(acc & 0xFFFFFFFFUL);
            carry = acc >> 32;
        }
        prod[i] += (uint32_t)carry; /* i+j+1 where j=-1 => i+0 = i */
    }

    /*
     * Now prod[0..15] holds the 512-bit product.
     * prod[0..7] = high 256 bits (T_hi)
     * prod[8..15] = low 256 bits (T_lo)
     *
     * Reduce: result = T_lo + T_hi * C mod p
     * where C = 0x1000003D1 (33 bits).
     *
     * T_hi * C can be up to ~289 bits, so T_lo + T_hi*C is at most
     * ~290 bits. We may need at most 2 subtractions of p, but it's
     * cleaner to do the reduction in two passes.
     */
    {
        /*
         * Reduce 512-bit product mod p using p = 2^256 - C, C = 0x1000003D1.
         * T mod p = T_lo + T_hi * C, iterated until result fits 256 bits.
         */
        uint32_t t_hi[8], t_lo[8];
        uint32_t reduced[9]; /* 9 words: reduced[0] is overflow */
        uint32_t c_lo = 0x3D1UL;

        for (i = 0; i < 8; i++) {
            t_hi[i] = prod[i];
            t_lo[i] = prod[i + 8];
        }

        /*
         * Compute T_hi * C where C = 2^32 + 0x3D1.
         *
         * T_hi * 0x3D1 -> 9 words (reduced[0..8])
         * T_hi * 2^32  -> 9 words with t_hi[0..7] at [0..7], 0 at [8]
         * Sum of both gives T_hi * C in 9 words.
         * Then add T_lo to get partially reduced result.
         */

        /* Step 1: T_hi * 0x3D1 -> reduced[0..8] */
        carry = 0;
        for (i = 7; i >= 0; i--) {
            acc = (uint64_t)t_hi[i] * (uint64_t)c_lo + carry;
            reduced[i + 1] = (uint32_t)(acc & 0xFFFFFFFFUL);
            carry = acc >> 32;
        }
        reduced[0] = (uint32_t)carry;

        /* Step 2: Add T_hi << 32 (= t_hi at positions [0..7] of 9 words) */
        carry = 0;
        for (i = 7; i >= 0; i--) {
            acc = (uint64_t)reduced[i] + (uint64_t)t_hi[i] + carry;
            reduced[i] = (uint32_t)(acc & 0xFFFFFFFFUL);
            carry = acc >> 32;
        }

        /* Step 3: Add T_lo at positions reduced[1..8] */
        carry = 0;
        for (i = 7; i >= 0; i--) {
            acc = (uint64_t)reduced[i + 1] + (uint64_t)t_lo[i] + carry;
            reduced[i + 1] = (uint32_t)(acc & 0xFFFFFFFFUL);
            carry = acc >> 32;
        }
        reduced[0] += (uint32_t)carry;

        /*
         * reduced[0..8] holds the partially reduced result.
         * reduced[0] should be small. Fold again if nonzero.
         */
        while (reduced[0] != 0) {
            uint32_t top = reduced[0];
            uint64_t extra;
            reduced[0] = 0;

            /* Add top * C = top * 2^32 + top * 0x3D1 to reduced[1..8] */
            extra = (uint64_t)top * (uint64_t)c_lo;
            acc = (uint64_t)reduced[8] + extra;
            reduced[8] = (uint32_t)(acc & 0xFFFFFFFFUL);
            carry = acc >> 32;

            for (i = 7; i >= 2; i--) {
                acc = (uint64_t)reduced[i] + carry;
                reduced[i] = (uint32_t)(acc & 0xFFFFFFFFUL);
                carry = acc >> 32;
            }

            /* top * 2^32: add top to reduced[1] */
            acc = (uint64_t)reduced[1] + (uint64_t)top + carry;
            reduced[1] = (uint32_t)(acc & 0xFFFFFFFFUL);
            reduced[0] += (uint32_t)(acc >> 32);
        }

        /* Copy reduced[1..8] -> r[0..7] */
        for (i = 0; i < 8; i++) r[i] = reduced[i + 1];

        /* Final reduction: if r >= p, subtract p */
        while (smt_uint256_cmp(r, SECP256K1_P) >= 0) {
            uint256_sub_raw(r, r, SECP256K1_P);
        }
    }
}

/* Modular exponentiation: r = base^exp mod p, using square-and-multiply */
static void field_pow(smt_uint256_t r, const smt_uint256_t base,
                      const smt_uint256_t exp)
{
    smt_uint256_t acc, b;
    int i, j, started;

    uint256_set_word(acc, 1);
    uint256_copy(b, base);

    started = 0;
    for (i = 0; i < 8; i++) {
        uint32_t word = exp[i];
        for (j = 31; j >= 0; j--) {
            if (started) {
                smt_field_mul(acc, acc, acc); /* square */
            }
            if (word & (1UL << j)) {
                if (started) {
                    smt_field_mul(acc, acc, b);
                } else {
                    uint256_copy(acc, b);
                    started = 1;
                }
            }
        }
    }
    uint256_copy(r, acc);
}

void smt_field_inv(smt_uint256_t r, const smt_uint256_t a)
{
    /* a^(p-2) mod p by Fermat's little theorem */
    field_pow(r, a, SECP256K1_P_MINUS_2);
}

/* ================================================================== */
/*  Scalar (mod n) arithmetic                                         */
/* ================================================================== */

/* r = a mod n, assuming a < 2*n (single subtraction) */
void smt_scalar_mod_n(smt_uint256_t r, const smt_uint256_t a)
{
    uint256_copy(r, a);
    if (smt_uint256_cmp(r, SECP256K1_N) >= 0) {
        uint256_sub_raw(r, r, SECP256K1_N);
    }
}

void smt_scalar_add_mod_n(smt_uint256_t r, const smt_uint256_t a,
                          const smt_uint256_t b)
{
    uint32_t carry;
    carry = uint256_add_raw(r, a, b);
    if (carry || smt_uint256_cmp(r, SECP256K1_N) >= 0) {
        uint256_sub_raw(r, r, SECP256K1_N);
    }
}

/*
 * Scalar multiplication mod n.
 * Uses schoolbook multiply then Barrett-like reduction.
 * Since n has a similar special structure issue as p but is different,
 * we use a generic mod-n reduction via trial subtractions on the
 * 512-bit product.
 *
 * For simplicity and correctness, we do schoolbook multiply to 512 bits
 * then repeated subtraction using shifts of n. This is slow but correct
 * and only used for signing (once per signature).
 */
void smt_scalar_mul_mod_n(smt_uint256_t r, const smt_uint256_t a,
                          const smt_uint256_t b)
{
    uint32_t prod[16];
    uint64_t acc;
    uint64_t carry;
    int i, j;

    /* Schoolbook multiply (same as field_mul) */
    for (i = 0; i < 16; i++) prod[i] = 0;

    for (i = 7; i >= 0; i--) {
        carry = 0;
        for (j = 7; j >= 0; j--) {
            int pos = i + j + 1;
            acc = (uint64_t)a[i] * (uint64_t)b[j]
                + (uint64_t)prod[pos] + carry;
            prod[pos] = (uint32_t)(acc & 0xFFFFFFFFUL);
            carry = acc >> 32;
        }
        prod[i] += (uint32_t)carry;
    }

    /*
     * Reduce prod[0..15] mod n.
     * We use a simple approach: since we only need this for signing,
     * we implement 512-bit mod 256-bit via long division.
     *
     * Shift-and-subtract: process bit-by-bit from MSB.
     * Accumulator is 257 bits (to detect overflow past n).
     */
    {
        smt_uint256_t rem;
        uint32_t rem_carry;
        int bit;

        uint256_zero(rem);
        rem_carry = 0;

        for (bit = 511; bit >= 0; bit--) {
            int word_idx = (511 - bit) / 32; /* word in prod (MSB first) */
            int bit_idx = bit % 32;
            uint32_t b_val;

            /* Shift rem left by 1 */
            rem_carry = (rem_carry << 1) | (rem[0] >> 31);
            for (i = 0; i < 7; i++) {
                rem[i] = (rem[i] << 1) | (rem[i + 1] >> 31);
            }
            rem[7] = rem[7] << 1;

            /* Bring in next bit of prod */
            b_val = (prod[word_idx] >> bit_idx) & 1;
            rem[7] |= b_val;

            /* If rem >= n, subtract n */
            if (rem_carry || smt_uint256_cmp(rem, SECP256K1_N) >= 0) {
                uint256_sub_raw(rem, rem, SECP256K1_N);
                rem_carry = 0;
            }
        }

        uint256_copy(r, rem);
    }
}

/* Scalar inverse mod n: a^(n-2) mod n, using square-and-multiply */
void smt_scalar_inv_mod_n(smt_uint256_t r, const smt_uint256_t a)
{
    smt_uint256_t acc, base;
    int i, j, started;

    uint256_set_word(acc, 1);
    uint256_copy(base, a);

    started = 0;
    for (i = 0; i < 8; i++) {
        uint32_t word = SECP256K1_N_MINUS_2[i];
        for (j = 31; j >= 0; j--) {
            if (started) {
                smt_scalar_mul_mod_n(acc, acc, acc);
            }
            if (word & (1UL << j)) {
                if (started) {
                    smt_scalar_mul_mod_n(acc, acc, base);
                } else {
                    uint256_copy(acc, base);
                    started = 1;
                }
            }
        }
    }
    uint256_copy(r, acc);
}

/* ================================================================== */
/*  EC point operations                                               */
/* ================================================================== */

static void point_set_infinity(smt_point_t *p)
{
    uint256_zero(p->x);
    uint256_zero(p->y);
    p->infinity = 1;
}

static void point_copy(smt_point_t *r, const smt_point_t *p)
{
    uint256_copy(r->x, p->x);
    uint256_copy(r->y, p->y);
    r->infinity = p->infinity;
}

void smt_point_double(smt_point_t *r, const smt_point_t *p)
{
    smt_uint256_t s, x3, y3, tmp, tmp2;

    if (p->infinity || smt_uint256_is_zero(p->y)) {
        point_set_infinity(r);
        return;
    }

    /*
     * s = (3 * x^2) / (2 * y) mod p
     * x3 = s^2 - 2*x
     * y3 = s * (x - x3) - y
     *
     * For secp256k1, a=0, so: s = 3*x^2 / (2*y)
     */

    /* tmp = x^2 */
    smt_field_mul(tmp, p->x, p->x);

    /* tmp2 = 3 * x^2 */
    smt_field_add(tmp2, tmp, tmp);   /* 2*x^2 */
    smt_field_add(tmp2, tmp2, tmp);  /* 3*x^2 */

    /* tmp = 2*y */
    smt_field_add(tmp, p->y, p->y);

    /* s = tmp2 / tmp = 3*x^2 * inv(2*y) */
    smt_field_inv(tmp, tmp);
    smt_field_mul(s, tmp2, tmp);

    /* x3 = s^2 - 2*x */
    smt_field_mul(x3, s, s);
    smt_field_sub(x3, x3, p->x);
    smt_field_sub(x3, x3, p->x);

    /* y3 = s * (x - x3) - y */
    smt_field_sub(tmp, p->x, x3);
    smt_field_mul(y3, s, tmp);
    smt_field_sub(y3, y3, p->y);

    uint256_copy(r->x, x3);
    uint256_copy(r->y, y3);
    r->infinity = 0;
}

void smt_point_add(smt_point_t *r, const smt_point_t *p,
                   const smt_point_t *q)
{
    smt_uint256_t s, x3, y3, dx, dy, tmp;

    if (p->infinity) {
        point_copy(r, q);
        return;
    }
    if (q->infinity) {
        point_copy(r, p);
        return;
    }

    /* Check if p == q (use point doubling) */
    if (smt_uint256_cmp(p->x, q->x) == 0) {
        if (smt_uint256_cmp(p->y, q->y) == 0) {
            smt_point_double(r, p);
            return;
        }
        /* p.x == q.x but p.y != q.y => p = -q => result is infinity */
        point_set_infinity(r);
        return;
    }

    /* s = (y2 - y1) / (x2 - x1) */
    smt_field_sub(dy, q->y, p->y);
    smt_field_sub(dx, q->x, p->x);
    smt_field_inv(dx, dx);
    smt_field_mul(s, dy, dx);

    /* x3 = s^2 - x1 - x2 */
    smt_field_mul(x3, s, s);
    smt_field_sub(x3, x3, p->x);
    smt_field_sub(x3, x3, q->x);

    /* y3 = s * (x1 - x3) - y1 */
    smt_field_sub(tmp, p->x, x3);
    smt_field_mul(y3, s, tmp);
    smt_field_sub(y3, y3, p->y);

    uint256_copy(r->x, x3);
    uint256_copy(r->y, y3);
    r->infinity = 0;
}

void smt_point_mul(smt_point_t *r, const smt_point_t *p,
                   const smt_uint256_t k)
{
    smt_point_t result, addend;
    int i, j, started;

    point_set_infinity(&result);
    point_copy(&addend, p);

    started = 0;
    for (i = 0; i < 8; i++) {
        uint32_t word = k[i];
        for (j = 31; j >= 0; j--) {
            if (started) {
                smt_point_double(&result, &result);
            }
            if (word & (1UL << j)) {
                if (started) {
                    smt_point_add(&result, &result, &addend);
                } else {
                    point_copy(&result, &addend);
                    started = 1;
                }
            }
        }
    }

    point_copy(r, &result);
}

/* ================================================================== */
/*  HMAC-SHA256                                                       */
/* ================================================================== */

void smt_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[32])
{
    uint8_t k_pad[64];
    uint8_t tk[32];
    smt_sha256_ctx ctx;
    int i;

    /* If key > 64 bytes, hash it first */
    if (key_len > 64) {
        smt_sha256(key, key_len, tk);
        key = tk;
        key_len = 32;
    }

    /* Prepare padded key */
    for (i = 0; i < 64; i++) k_pad[i] = 0;
    for (i = 0; i < (int)key_len; i++) k_pad[i] = key[i];

    /* Inner hash: SHA256((key XOR ipad) || data) */
    for (i = 0; i < 64; i++) k_pad[i] ^= 0x36;

    smt_sha256_init(&ctx);
    smt_sha256_update(&ctx, k_pad, 64);
    smt_sha256_update(&ctx, data, data_len);
    smt_sha256_final(&ctx, out);

    /* Undo ipad XOR, apply opad */
    for (i = 0; i < 64; i++) k_pad[i] ^= (0x36 ^ 0x5C);

    /* Outer hash: SHA256((key XOR opad) || inner_hash) */
    smt_sha256_init(&ctx);
    smt_sha256_update(&ctx, k_pad, 64);
    smt_sha256_update(&ctx, out, 32);
    smt_sha256_final(&ctx, out);

    /* Clean sensitive data */
    smt_memzero(k_pad, 64);
    smt_memzero(tk, 32);
}

/* ================================================================== */
/*  RFC 6979 deterministic k generation                               */
/* ================================================================== */

/*
 * Generate deterministic k per RFC 6979 Section 3.2
 * Uses HMAC-SHA256 as the HMAC_DRBG.
 */
static int rfc6979_generate_k(smt_uint256_t k_out,
                               const uint8_t hash[32],
                               const uint8_t privkey[32])
{
    uint8_t V[32]; /* HMAC_DRBG V */
    uint8_t K[32]; /* HMAC_DRBG K */
    uint8_t concat[97]; /* V(32) + 0x00/0x01(1) + privkey(32) + hash(32) */
    int i;
    int attempts;

    /* Step b: V = 0x01 0x01 ... 0x01 (32 bytes) */
    for (i = 0; i < 32; i++) V[i] = 0x01;

    /* Step c: K = 0x00 0x00 ... 0x00 (32 bytes) */
    for (i = 0; i < 32; i++) K[i] = 0x00;

    /* Step d: K = HMAC_K(V || 0x00 || privkey || hash) */
    smt_memcpy(concat, V, 32);
    concat[32] = 0x00;
    smt_memcpy(concat + 33, privkey, 32);
    smt_memcpy(concat + 65, hash, 32);
    smt_hmac_sha256(K, 32, concat, 97, K);

    /* Step e: V = HMAC_K(V) */
    smt_hmac_sha256(K, 32, V, 32, V);

    /* Step f: K = HMAC_K(V || 0x01 || privkey || hash) */
    smt_memcpy(concat, V, 32);
    concat[32] = 0x01;
    smt_memcpy(concat + 33, privkey, 32);
    smt_memcpy(concat + 65, hash, 32);
    smt_hmac_sha256(K, 32, concat, 97, K);

    /* Step g: V = HMAC_K(V) */
    smt_hmac_sha256(K, 32, V, 32, V);

    /* Step h: loop until valid k is found */
    for (attempts = 0; attempts < 100; attempts++) {
        /* h.2: V = HMAC_K(V) */
        smt_hmac_sha256(K, 32, V, 32, V);

        /* h.3: k = bits2int(V) -- V is already 32 bytes = 256 bits */
        smt_uint256_from_bytes(k_out, V);

        /* Check 0 < k < n */
        if (!smt_uint256_is_zero(k_out) &&
            smt_uint256_cmp(k_out, SECP256K1_N) < 0) {
            smt_memzero(K, 32);
            smt_memzero(V, 32);
            smt_memzero(concat, 97);
            return 1;
        }

        /* h.3 failed: K = HMAC_K(V || 0x00), V = HMAC_K(V) */
        smt_memcpy(concat, V, 32);
        concat[32] = 0x00;
        smt_hmac_sha256(K, 32, concat, 33, K);
        smt_hmac_sha256(K, 32, V, 32, V);
    }

    smt_memzero(K, 32);
    smt_memzero(V, 32);
    smt_memzero(concat, 97);
    return 0; /* failed to find valid k */
}

/* ================================================================== */
/*  DER encoding/decoding helpers                                     */
/* ================================================================== */

/* Encode a 256-bit integer as a DER INTEGER.
 * Returns number of bytes written to out.
 * out must have room for at most 34 bytes (tag + len + 33 value bytes).
 */
static size_t der_encode_integer(uint8_t *out, const smt_uint256_t val)
{
    uint8_t raw[32];
    int leading_zeros, len;
    int need_pad;
    size_t pos;

    smt_uint256_to_bytes(val, raw);

    /* Count leading zero bytes */
    leading_zeros = 0;
    while (leading_zeros < 31 && raw[leading_zeros] == 0) {
        leading_zeros++;
    }

    /* DER integers are signed; add 0x00 pad if high bit set */
    need_pad = (raw[leading_zeros] & 0x80) ? 1 : 0;
    len = 32 - leading_zeros;

    pos = 0;
    out[pos++] = 0x02; /* INTEGER tag */
    out[pos++] = (uint8_t)(len + need_pad);
    if (need_pad) out[pos++] = 0x00;
    smt_memcpy(out + pos, raw + leading_zeros, (size_t)len);
    pos += (size_t)len;

    return pos;
}

/* Decode a DER INTEGER into a uint256. Returns bytes consumed, 0 on error. */
static size_t der_decode_integer(smt_uint256_t out, const uint8_t *der,
                                 size_t der_len)
{
    uint8_t raw[32];
    int len, skip, copy_len;
    int i;

    if (der_len < 2) return 0;
    if (der[0] != 0x02) return 0;

    len = der[1];
    if ((size_t)(len + 2) > der_len) return 0;
    if (len < 1 || len > 33) return 0;

    /* Skip leading zero padding byte (used for positive DER integers) */
    skip = 0;
    if (len >= 2 && der[2] == 0x00 && (der[3] & 0x80)) {
        skip = 1;
    }

    copy_len = len - skip;
    if (copy_len > 32) return 0;

    /* Zero-fill raw, then copy right-aligned */
    for (i = 0; i < 32; i++) raw[i] = 0;
    smt_memcpy(raw + 32 - copy_len, der + 2 + skip, (size_t)copy_len);

    smt_uint256_from_bytes(out, raw);

    return (size_t)(len + 2);
}

/* ================================================================== */
/*  High-level operations                                             */
/* ================================================================== */

void smt_ec_pubkey_create(uint8_t pubkey[33], const uint8_t privkey[32])
{
    smt_uint256_t k;
    smt_point_t G, Q;

    /* Set up generator */
    uint256_copy(G.x, SECP256K1_GX);
    uint256_copy(G.y, SECP256K1_GY);
    G.infinity = 0;

    /* Parse private key */
    smt_uint256_from_bytes(k, privkey);

    /* Q = k * G */
    smt_point_mul(&Q, &G, k);

    /* Encode compressed: 0x02 + x if y is even, 0x03 + x if y is odd */
    pubkey[0] = (Q.y[7] & 1) ? 0x03 : 0x02;
    smt_uint256_to_bytes(Q.x, pubkey + 1);

    /* Clean sensitive data */
    smt_memzero(&k, sizeof(k));
}

int smt_ecdsa_sign(uint8_t *sig, size_t *sig_len,
                   const uint8_t hash[32], const uint8_t privkey[32])
{
    smt_uint256_t z, d, k, r_val, s_val, kinv, tmp;
    smt_point_t G, R;
    size_t pos, r_len, s_len;
    uint8_t r_der[34], s_der[34];

    /* Parse inputs */
    smt_uint256_from_bytes(z, hash);
    smt_uint256_from_bytes(d, privkey);

    /* Reduce z mod n (hash may be >= n) */
    if (smt_uint256_cmp(z, SECP256K1_N) >= 0) {
        uint256_sub_raw(z, z, SECP256K1_N);
    }

    /* Validate private key: 0 < d < n */
    if (smt_uint256_is_zero(d) || smt_uint256_cmp(d, SECP256K1_N) >= 0) {
        return 0;
    }

    /* Set up generator */
    uint256_copy(G.x, SECP256K1_GX);
    uint256_copy(G.y, SECP256K1_GY);
    G.infinity = 0;

    /* Generate deterministic k via RFC 6979 */
    if (!rfc6979_generate_k(k, hash, privkey)) {
        return 0;
    }

    /* R = k * G */
    smt_point_mul(&R, &G, k);

    if (R.infinity) {
        smt_memzero(&k, sizeof(k));
        return 0;
    }

    /* r = R.x mod n */
    uint256_copy(r_val, R.x);
    smt_scalar_mod_n(r_val, r_val);

    if (smt_uint256_is_zero(r_val)) {
        smt_memzero(&k, sizeof(k));
        return 0;
    }

    /* s = k^(-1) * (z + r*d) mod n */
    smt_scalar_inv_mod_n(kinv, k);
    smt_scalar_mul_mod_n(tmp, r_val, d);        /* r*d mod n */
    smt_scalar_add_mod_n(tmp, z, tmp);           /* z + r*d mod n */
    smt_scalar_mul_mod_n(s_val, kinv, tmp);      /* k^-1 * (z+r*d) mod n */

    if (smt_uint256_is_zero(s_val)) {
        smt_memzero(&k, sizeof(k));
        smt_memzero(&kinv, sizeof(kinv));
        return 0;
    }

    /* Low-S normalization: if s > n/2, set s = n - s */
    if (smt_uint256_cmp(s_val, SECP256K1_N_HALF) > 0) {
        uint256_sub_raw(s_val, SECP256K1_N, s_val);
    }

    /* DER encode the signature */
    r_len = der_encode_integer(r_der, r_val);
    s_len = der_encode_integer(s_der, s_val);

    /* SEQUENCE tag + length + r INTEGER + s INTEGER */
    pos = 0;
    sig[pos++] = 0x30; /* SEQUENCE tag */
    sig[pos++] = (uint8_t)(r_len + s_len);
    smt_memcpy(sig + pos, r_der, r_len);
    pos += r_len;
    smt_memcpy(sig + pos, s_der, s_len);
    pos += s_len;

    *sig_len = pos;

    /* Clean sensitive data */
    smt_memzero(&k, sizeof(k));
    smt_memzero(&d, sizeof(d));
    smt_memzero(&kinv, sizeof(kinv));

    return 1;
}

/*
 * Decompress a compressed public key (33 bytes) into a point.
 * Returns 1 on success, 0 on failure.
 */
static int decompress_pubkey(smt_point_t *p, const uint8_t pubkey[33])
{
    smt_uint256_t x, y2, y, tmp;
    int parity;

    if (pubkey[0] != 0x02 && pubkey[0] != 0x03) return 0;
    parity = pubkey[0] & 1; /* 0 for even y, 1 for odd y */

    smt_uint256_from_bytes(x, pubkey + 1);

    /* Validate x < p */
    if (smt_uint256_cmp(x, SECP256K1_P) >= 0) return 0;

    /* y^2 = x^3 + 7 mod p */
    smt_field_mul(y2, x, x);      /* x^2 */
    smt_field_mul(y2, y2, x);     /* x^3 */
    uint256_set_word(tmp, 7);
    smt_field_add(y2, y2, tmp);   /* x^3 + 7 */

    /*
     * Compute square root: y = y2^((p+1)/4) mod p
     * This works because p = 3 mod 4 for secp256k1.
     *
     * (p+1)/4 = (2^256 - 2^32 - 977 + 1) / 4
     *         = (2^256 - 2^32 - 976) / 4
     *         = 2^254 - 2^30 - 244
     *
     * We compute this exponent explicitly.
     */
    {
        /* (p+1)/4 as uint256 */
        /*
         * (p+1)/4 for modular square root (works since p = 3 mod 4)
         * p   = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
         * p+1 = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC30
         * /4  = 3FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF BFFFFF0C
         */
        static const smt_uint256_t EXP_SQRT = {
            0x3FFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL,
            0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xBFFFFF0CUL
        };

        field_pow(y, y2, EXP_SQRT);
    }

    /* Verify: y^2 mod p == y2 */
    smt_field_mul(tmp, y, y);
    if (smt_uint256_cmp(tmp, y2) != 0) {
        /* No valid square root exists: invalid public key */
        return 0;
    }

    /* Choose correct parity */
    if ((y[7] & 1) != (uint32_t)parity) {
        /* y = p - y */
        uint256_sub_raw(y, SECP256K1_P, y);
    }

    uint256_copy(p->x, x);
    uint256_copy(p->y, y);
    p->infinity = 0;

    return 1;
}

int smt_ecdsa_verify(const uint8_t *sig, size_t sig_len,
                     const uint8_t hash[32], const uint8_t pubkey[33])
{
    smt_uint256_t r, s, z, sinv, u1, u2;
    smt_point_t G, Q, R1, R2, R;
    size_t consumed;

    /* Parse DER signature */
    if (sig_len < 8 || sig[0] != 0x30) return 0;
    {
        size_t inner_len = sig[1];
        const uint8_t *inner = sig + 2;

        if (inner_len + 2 != sig_len) return 0;

        consumed = der_decode_integer(r, inner, inner_len);
        if (consumed == 0) return 0;

        consumed = der_decode_integer(s, inner + consumed,
                                      inner_len - consumed);
        if (consumed == 0) return 0;
    }

    /* Validate r, s in [1, n-1] */
    if (smt_uint256_is_zero(r) || smt_uint256_cmp(r, SECP256K1_N) >= 0)
        return 0;
    if (smt_uint256_is_zero(s) || smt_uint256_cmp(s, SECP256K1_N) >= 0)
        return 0;

    /* Parse public key */
    if (!decompress_pubkey(&Q, pubkey)) return 0;

    /* z = hash as integer, reduced mod n */
    smt_uint256_from_bytes(z, hash);
    if (smt_uint256_cmp(z, SECP256K1_N) >= 0) {
        uint256_sub_raw(z, z, SECP256K1_N);
    }

    /* s_inv = s^(-1) mod n */
    smt_scalar_inv_mod_n(sinv, s);

    /* u1 = z * s_inv mod n */
    smt_scalar_mul_mod_n(u1, z, sinv);

    /* u2 = r * s_inv mod n */
    smt_scalar_mul_mod_n(u2, r, sinv);

    /* R = u1*G + u2*Q */
    uint256_copy(G.x, SECP256K1_GX);
    uint256_copy(G.y, SECP256K1_GY);
    G.infinity = 0;

    smt_point_mul(&R1, &G, u1);
    smt_point_mul(&R2, &Q, u2);
    smt_point_add(&R, &R1, &R2);

    if (R.infinity) return 0;

    /* Verify: r == R.x mod n */
    {
        smt_uint256_t rx;
        uint256_copy(rx, R.x);
        smt_scalar_mod_n(rx, rx);
        if (smt_uint256_cmp(rx, r) == 0) return 1;
    }

    return 0;
}
