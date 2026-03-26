/*
 * Smartiecoin Amiga Wallet - Base58 / Base58Check encoding
 *
 * Pure C implementation compatible with VBCC for AmigaOS m68k.
 * No dynamic memory allocation.
 *
 * Algorithm notes:
 *   Base58 encoding works by treating the input bytes as a big-endian
 *   big integer, then repeatedly dividing by 58 and collecting remainders.
 *   Leading zero bytes in the input map to leading '1' characters.
 *
 *   Base58Check prepends a version byte, appends 4 bytes of SHA-256d
 *   checksum, then Base58-encodes the whole thing.
 */

#include "base58.h"
#include "sha256.h"

/* ------------------------------------------------------------------ */
/* Bitcoin Base58 alphabet                                             */
/* ------------------------------------------------------------------ */

static const char b58_alphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/*
 * Reverse lookup table: ASCII value -> Base58 digit value.
 * -1 means invalid character.
 * Only entries for the 58 valid characters are set; everything else is -1.
 */
static const int8_t b58_digit_value[128] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,  /* 0x00-0x0F */
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,  /* 0x10-0x1F */
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,  /* 0x20-0x2F */
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,  /* 0x30-0x3F  '1'..'9' */
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,  /* 0x40-0x4F  'A'..'P' */
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,  /* 0x50-0x5F  'Q'..'Z' */
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,  /* 0x60-0x6F  'a'..'p' */
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1   /* 0x70-0x7F  'q'..'z' */
};

/* Maximum raw data size we support (version + payload + checksum).
 * 128 bytes is generous for any address or key encoding. */
#define BASE58_MAX_RAW 128

/* ------------------------------------------------------------------ */
/* Base58 encode                                                       */
/* ------------------------------------------------------------------ */

int smt_base58_encode(const uint8_t *input, size_t input_len,
                      char *output, size_t output_size)
{
    /*
     * We work on a mutable copy of the input so we can do in-place
     * division.  The copy lives on the stack to avoid malloc.
     */
    uint8_t buf[BASE58_MAX_RAW];
    size_t buf_len;
    size_t leading_zeros;
    size_t i;
    /* Worst case: each input byte can produce at most log(256)/log(58) ~ 1.37
     * characters.  138/100 ~ 1.38 is a safe ratio.  +1 for potential rounding,
     * +1 for null terminator. */
    char tmp[BASE58_MAX_RAW * 2];  /* more than enough */
    size_t tmp_len;
    size_t result_len;

    if (input == NULL || output == NULL) return -1;
    if (input_len == 0) {
        if (output_size < 1) return -1;
        output[0] = '\0';
        return 0;
    }
    if (input_len > BASE58_MAX_RAW) return -1;

    /* Copy input into working buffer */
    buf_len = input_len;
    for (i = 0; i < input_len; i++) {
        buf[i] = input[i];
    }

    /* Count leading zero bytes -> they become '1' characters */
    leading_zeros = 0;
    while (leading_zeros < buf_len && buf[leading_zeros] == 0) {
        leading_zeros++;
    }

    /*
     * Repeatedly divide the big number (in buf) by 58.
     * Collect remainders in tmp[] (in reverse order).
     */
    tmp_len = 0;
    while (buf_len > 0) {
        uint32_t carry = 0;
        size_t new_len = 0;
        size_t j;

        /* Divide buf[] by 58, collecting the quotient back into buf
         * and the remainder in carry. */
        for (j = 0; j < buf_len; j++) {
            carry = carry * 256 + buf[j];
            buf[j] = (uint8_t)(carry / 58);
            carry = carry % 58;
        }

        /* The remainder is one Base58 digit */
        tmp[tmp_len++] = b58_alphabet[carry];

        /* Strip leading zero bytes from the quotient */
        new_len = 0;
        for (j = 0; j < buf_len; j++) {
            if (buf[j] != 0 || new_len > 0) {
                buf[new_len++] = buf[j];
            }
        }
        buf_len = new_len;
    }

    /* Total length = leading '1's + Base58 digits */
    result_len = leading_zeros + tmp_len;
    if (output_size < result_len + 1) return -1;  /* +1 for '\0' */

    /* Write leading '1' characters */
    for (i = 0; i < leading_zeros; i++) {
        output[i] = '1';
    }

    /* Write Base58 digits in reverse (tmp[] was built backwards) */
    for (i = 0; i < tmp_len; i++) {
        output[leading_zeros + i] = tmp[tmp_len - 1 - i];
    }

    output[result_len] = '\0';

    /* Scrub working buffers */
    smt_memzero(buf, sizeof(buf));
    smt_memzero(tmp, sizeof(tmp));

    return (int)result_len;
}

/* ------------------------------------------------------------------ */
/* Base58 decode                                                       */
/* ------------------------------------------------------------------ */

int smt_base58_decode(const char *input,
                      uint8_t *output, size_t output_size)
{
    /*
     * Work buffer: we build up the result by multiplying-and-adding
     * in base 256.  The result can be at most as long as the input
     * (each Base58 digit adds at most ceil(log2(58)/8) bytes, but
     * the output is always <= input_len bytes).
     */
    uint8_t buf[BASE58_MAX_RAW];
    size_t buf_len = 0;
    size_t input_len;
    size_t leading_ones;
    size_t i, j;
    size_t result_len;

    if (input == NULL || output == NULL) return -1;

    input_len = smt_strlen(input);
    if (input_len == 0) {
        return 0;
    }
    if (input_len > BASE58_MAX_RAW * 2) return -1;

    smt_memzero(buf, sizeof(buf));

    /* Count leading '1' characters -> they become 0x00 bytes */
    leading_ones = 0;
    while (leading_ones < input_len && input[leading_ones] == '1') {
        leading_ones++;
    }

    /*
     * For each Base58 character, multiply the accumulator by 58
     * and add the digit value.  We work in base 256.
     */
    buf_len = 0;
    for (i = leading_ones; i < input_len; i++) {
        uint8_t c = (uint8_t)input[i];
        int val;
        uint32_t carry;

        /* Validate character */
        if (c >= 128) return -1;
        val = b58_digit_value[c];
        if (val < 0) return -1;

        /* Multiply buf[] by 58 and add val */
        carry = (uint32_t)val;
        for (j = buf_len; j > 0; j--) {
            carry += (uint32_t)buf[j - 1] * 58;
            buf[j - 1] = (uint8_t)(carry & 0xFF);
            carry >>= 8;
        }
        /* If there is still carry, prepend bytes */
        while (carry > 0) {
            /* Shift buffer right to make room at front */
            if (buf_len + 1 > BASE58_MAX_RAW) return -1;
            for (j = buf_len; j > 0; j--) {
                buf[j] = buf[j - 1];
            }
            buf[0] = (uint8_t)(carry & 0xFF);
            carry >>= 8;
            buf_len++;
        }

        /* If buf_len is still 0 but we wrote into buf[0], account for it.
         * This happens on the first non-zero digit. */
        if (buf_len == 0 && buf[0] != 0) {
            buf_len = 1;
        }
    }

    /* Total result = leading zero bytes + decoded bytes */
    result_len = leading_ones + buf_len;
    if (output_size < result_len) return -1;

    /* Write leading zero bytes */
    for (i = 0; i < leading_ones; i++) {
        output[i] = 0;
    }

    /* Write decoded bytes */
    for (i = 0; i < buf_len; i++) {
        output[leading_ones + i] = buf[i];
    }

    /* Scrub working buffer */
    smt_memzero(buf, sizeof(buf));

    return (int)result_len;
}

/* ------------------------------------------------------------------ */
/* Base58Check encode                                                  */
/* ------------------------------------------------------------------ */

int smt_base58check_encode(uint8_t version,
                           const uint8_t *payload, size_t payload_len,
                           char *output, size_t output_size)
{
    /*
     * Layout: [version(1)] [payload(N)] [checksum(4)]
     * Checksum = first 4 bytes of SHA256(SHA256(version || payload))
     */
    uint8_t raw[BASE58_MAX_RAW];
    size_t raw_len;
    hash256_t hash1;
    hash256_t hash2;

    if (payload == NULL || output == NULL) return -1;
    raw_len = 1 + payload_len + 4;
    if (raw_len > BASE58_MAX_RAW) return -1;

    /* Build the raw data: version + payload */
    raw[0] = version;
    smt_memcpy(raw + 1, payload, payload_len);

    /* Compute double-SHA256 checksum */
    smt_sha256(raw, 1 + payload_len, hash1);
    smt_sha256(hash1, 32, hash2);

    /* Append first 4 bytes of checksum */
    raw[1 + payload_len + 0] = hash2[0];
    raw[1 + payload_len + 1] = hash2[1];
    raw[1 + payload_len + 2] = hash2[2];
    raw[1 + payload_len + 3] = hash2[3];

    /* Scrub intermediate hashes */
    smt_memzero(hash1, sizeof(hash1));
    smt_memzero(hash2, sizeof(hash2));

    /* Base58 encode */
    {
        int result = smt_base58_encode(raw, raw_len, output, output_size);
        smt_memzero(raw, sizeof(raw));
        return result;
    }
}

/* ------------------------------------------------------------------ */
/* Base58Check decode                                                  */
/* ------------------------------------------------------------------ */

int smt_base58check_decode(const char *input,
                           uint8_t *version,
                           uint8_t *payload, size_t payload_size,
                           size_t *payload_len)
{
    uint8_t raw[BASE58_MAX_RAW];
    int raw_len;
    size_t plen;
    hash256_t hash1;
    hash256_t hash2;

    if (input == NULL || version == NULL ||
        payload == NULL || payload_len == NULL) {
        return -1;
    }

    /* Decode the Base58 string */
    raw_len = smt_base58_decode(input, raw, sizeof(raw));
    if (raw_len < 0) return -1;

    /* Must have at least 1 (version) + 4 (checksum) = 5 bytes */
    if (raw_len < 5) {
        smt_memzero(raw, sizeof(raw));
        return -1;
    }

    /* Verify checksum: SHA256d of everything except last 4 bytes */
    smt_sha256(raw, (size_t)(raw_len - 4), hash1);
    smt_sha256(hash1, 32, hash2);

    if (hash2[0] != raw[raw_len - 4] ||
        hash2[1] != raw[raw_len - 3] ||
        hash2[2] != raw[raw_len - 2] ||
        hash2[3] != raw[raw_len - 1]) {
        /* Checksum mismatch */
        smt_memzero(raw, sizeof(raw));
        smt_memzero(hash1, sizeof(hash1));
        smt_memzero(hash2, sizeof(hash2));
        return -1;
    }

    smt_memzero(hash1, sizeof(hash1));
    smt_memzero(hash2, sizeof(hash2));

    /* Extract version byte */
    *version = raw[0];

    /* Extract payload (everything between version and checksum) */
    plen = (size_t)(raw_len - 5);
    if (plen > payload_size) {
        smt_memzero(raw, sizeof(raw));
        return -1;
    }

    smt_memcpy(payload, raw + 1, plen);
    *payload_len = plen;

    smt_memzero(raw, sizeof(raw));
    return 0;
}
