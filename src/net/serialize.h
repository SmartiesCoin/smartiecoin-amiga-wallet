/*
 * Smartiecoin Amiga Wallet - Binary serialization for P2P protocol
 */
#ifndef SMT_SERIALIZE_H
#define SMT_SERIALIZE_H

#include "../types.h"

/* Variable-length integer (Bitcoin CompactSize) */
int smt_write_varint(uint8_t *buf, size_t *pos, size_t max, uint64_t v);
int smt_read_varint(const uint8_t *buf, size_t *pos, size_t max, uint64_t *v);

/* Variable-length string */
int smt_write_varstr(uint8_t *buf, size_t *pos, size_t max,
                     const char *str, size_t str_len);
int smt_read_varstr(const uint8_t *buf, size_t *pos, size_t max,
                    char *str, size_t str_size, size_t *str_len);

/* Fixed-size writes (little-endian on wire) */
int smt_write_u8(uint8_t *buf, size_t *pos, size_t max, uint8_t v);
int smt_write_u16le(uint8_t *buf, size_t *pos, size_t max, uint16_t v);
int smt_write_u32le(uint8_t *buf, size_t *pos, size_t max, uint32_t v);
int smt_write_u64le(uint8_t *buf, size_t *pos, size_t max, uint64_t v);
int smt_write_i32le(uint8_t *buf, size_t *pos, size_t max, int32_t v);
int smt_write_i64le(uint8_t *buf, size_t *pos, size_t max, int64_t v);
int smt_write_bytes(uint8_t *buf, size_t *pos, size_t max,
                    const uint8_t *data, size_t len);

/* Big-endian writes (used for IP addresses in network messages) */
int smt_write_u16be(uint8_t *buf, size_t *pos, size_t max, uint16_t v);

/* Fixed-size reads */
int smt_read_u8(const uint8_t *buf, size_t *pos, size_t max, uint8_t *v);
int smt_read_u16le(const uint8_t *buf, size_t *pos, size_t max, uint16_t *v);
int smt_read_u32le(const uint8_t *buf, size_t *pos, size_t max, uint32_t *v);
int smt_read_u64le(const uint8_t *buf, size_t *pos, size_t max, uint64_t *v);
int smt_read_i32le(const uint8_t *buf, size_t *pos, size_t max, int32_t *v);
int smt_read_i64le(const uint8_t *buf, size_t *pos, size_t max, int64_t *v);
int smt_read_u16be(const uint8_t *buf, size_t *pos, size_t max, uint16_t *v);
int smt_read_bytes(const uint8_t *buf, size_t *pos, size_t max,
                   uint8_t *out, size_t len);

#endif /* SMT_SERIALIZE_H */
