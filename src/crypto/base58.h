/*
 * Smartiecoin Amiga Wallet - Base58 / Base58Check encoding
 *
 * Pure C implementation compatible with VBCC for AmigaOS m68k.
 * Uses the standard Bitcoin Base58 alphabet.
 *
 * No dynamic memory allocation -- all buffers are caller-provided.
 */
#ifndef SMT_BASE58_H
#define SMT_BASE58_H

#include "../types.h"

/*
 * smt_base58_encode
 *
 * Encode a raw byte array into a Base58 string (no checksum).
 *
 * input       - bytes to encode
 * input_len   - number of bytes in input
 * output      - destination buffer for the null-terminated Base58 string
 * output_size - capacity of output buffer (including space for '\0')
 *
 * Returns the length of the encoded string (excluding '\0'), or -1 on error.
 */
int smt_base58_encode(const uint8_t *input, size_t input_len,
                      char *output, size_t output_size);

/*
 * smt_base58_decode
 *
 * Decode a Base58 string into raw bytes (no checksum verification).
 *
 * input       - null-terminated Base58 string
 * output      - destination buffer for decoded bytes
 * output_size - capacity of output buffer
 *
 * Returns the number of decoded bytes written to output, or -1 on error
 * (invalid character or buffer too small).
 */
int smt_base58_decode(const char *input,
                      uint8_t *output, size_t output_size);

/*
 * smt_base58check_encode
 *
 * Encode payload with a version byte and 4-byte SHA-256d checksum,
 * then Base58-encode the result.
 *
 * version     - version / network byte (e.g. 0x3F for Smartiecoin P2PKH)
 * payload     - raw payload bytes (e.g. 20-byte pubkey hash)
 * payload_len - number of payload bytes
 * output      - destination buffer for the null-terminated Base58Check string
 * output_size - capacity of output buffer (including '\0')
 *
 * Returns the length of the encoded string (excluding '\0'), or -1 on error.
 */
int smt_base58check_encode(uint8_t version,
                           const uint8_t *payload, size_t payload_len,
                           char *output, size_t output_size);

/*
 * smt_base58check_decode
 *
 * Decode and verify a Base58Check-encoded string.
 *
 * input        - null-terminated Base58Check string
 * version      - receives the version byte
 * payload      - destination buffer for the decoded payload
 * payload_size - capacity of the payload buffer
 * payload_len  - receives the number of payload bytes written
 *
 * Returns 0 on success, -1 on error (bad character, checksum mismatch,
 * truncated data, or buffer too small).
 */
int smt_base58check_decode(const char *input,
                           uint8_t *version,
                           uint8_t *payload, size_t payload_size,
                           size_t *payload_len);

#endif /* SMT_BASE58_H */
