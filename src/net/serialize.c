/*
 * Smartiecoin Amiga Wallet - Binary serialization for P2P protocol
 */
#include "serialize.h"

int smt_write_u8(uint8_t *buf, size_t *pos, size_t max, uint8_t v) {
    if (*pos + 1 > max) return -1;
    buf[(*pos)++] = v;
    return 0;
}

int smt_write_u16le(uint8_t *buf, size_t *pos, size_t max, uint16_t v) {
    if (*pos + 2 > max) return -1;
    buf[(*pos)++] = (uint8_t)(v & 0xFF);
    buf[(*pos)++] = (uint8_t)((v >> 8) & 0xFF);
    return 0;
}

int smt_write_u16be(uint8_t *buf, size_t *pos, size_t max, uint16_t v) {
    if (*pos + 2 > max) return -1;
    buf[(*pos)++] = (uint8_t)((v >> 8) & 0xFF);
    buf[(*pos)++] = (uint8_t)(v & 0xFF);
    return 0;
}

int smt_write_u32le(uint8_t *buf, size_t *pos, size_t max, uint32_t v) {
    if (*pos + 4 > max) return -1;
    buf[(*pos)++] = (uint8_t)(v & 0xFF);
    buf[(*pos)++] = (uint8_t)((v >> 8) & 0xFF);
    buf[(*pos)++] = (uint8_t)((v >> 16) & 0xFF);
    buf[(*pos)++] = (uint8_t)((v >> 24) & 0xFF);
    return 0;
}

int smt_write_u64le(uint8_t *buf, size_t *pos, size_t max, uint64_t v) {
    if (*pos + 8 > max) return -1;
    buf[(*pos)++] = (uint8_t)(v & 0xFF);
    buf[(*pos)++] = (uint8_t)((v >> 8) & 0xFF);
    buf[(*pos)++] = (uint8_t)((v >> 16) & 0xFF);
    buf[(*pos)++] = (uint8_t)((v >> 24) & 0xFF);
    buf[(*pos)++] = (uint8_t)((v >> 32) & 0xFF);
    buf[(*pos)++] = (uint8_t)((v >> 40) & 0xFF);
    buf[(*pos)++] = (uint8_t)((v >> 48) & 0xFF);
    buf[(*pos)++] = (uint8_t)((v >> 56) & 0xFF);
    return 0;
}

int smt_write_i32le(uint8_t *buf, size_t *pos, size_t max, int32_t v) {
    return smt_write_u32le(buf, pos, max, (uint32_t)v);
}

int smt_write_i64le(uint8_t *buf, size_t *pos, size_t max, int64_t v) {
    return smt_write_u64le(buf, pos, max, (uint64_t)v);
}

int smt_write_bytes(uint8_t *buf, size_t *pos, size_t max,
                    const uint8_t *data, size_t len) {
    if (*pos + len > max) return -1;
    smt_memcpy(buf + *pos, data, len);
    *pos += len;
    return 0;
}

int smt_write_varint(uint8_t *buf, size_t *pos, size_t max, uint64_t v) {
    if (v < 0xFD) {
        return smt_write_u8(buf, pos, max, (uint8_t)v);
    } else if (v <= 0xFFFF) {
        if (smt_write_u8(buf, pos, max, 0xFD) < 0) return -1;
        return smt_write_u16le(buf, pos, max, (uint16_t)v);
    } else if (v <= 0xFFFFFFFFUL) {
        if (smt_write_u8(buf, pos, max, 0xFE) < 0) return -1;
        return smt_write_u32le(buf, pos, max, (uint32_t)v);
    } else {
        if (smt_write_u8(buf, pos, max, 0xFF) < 0) return -1;
        return smt_write_u64le(buf, pos, max, v);
    }
}

int smt_write_varstr(uint8_t *buf, size_t *pos, size_t max,
                     const char *str, size_t str_len) {
    if (smt_write_varint(buf, pos, max, (uint64_t)str_len) < 0) return -1;
    return smt_write_bytes(buf, pos, max, (const uint8_t *)str, str_len);
}

/* ---- Read functions ---- */

int smt_read_u8(const uint8_t *buf, size_t *pos, size_t max, uint8_t *v) {
    if (*pos + 1 > max) return -1;
    *v = buf[(*pos)++];
    return 0;
}

int smt_read_u16le(const uint8_t *buf, size_t *pos, size_t max, uint16_t *v) {
    if (*pos + 2 > max) return -1;
    *v = (uint16_t)buf[*pos] | ((uint16_t)buf[*pos + 1] << 8);
    *pos += 2;
    return 0;
}

int smt_read_u16be(const uint8_t *buf, size_t *pos, size_t max, uint16_t *v) {
    if (*pos + 2 > max) return -1;
    *v = ((uint16_t)buf[*pos] << 8) | (uint16_t)buf[*pos + 1];
    *pos += 2;
    return 0;
}

int smt_read_u32le(const uint8_t *buf, size_t *pos, size_t max, uint32_t *v) {
    if (*pos + 4 > max) return -1;
    *v = (uint32_t)buf[*pos] | ((uint32_t)buf[*pos+1] << 8) |
         ((uint32_t)buf[*pos+2] << 16) | ((uint32_t)buf[*pos+3] << 24);
    *pos += 4;
    return 0;
}

int smt_read_u64le(const uint8_t *buf, size_t *pos, size_t max, uint64_t *v) {
    if (*pos + 8 > max) return -1;
    *v = (uint64_t)buf[*pos] | ((uint64_t)buf[*pos+1] << 8) |
         ((uint64_t)buf[*pos+2] << 16) | ((uint64_t)buf[*pos+3] << 24) |
         ((uint64_t)buf[*pos+4] << 32) | ((uint64_t)buf[*pos+5] << 40) |
         ((uint64_t)buf[*pos+6] << 48) | ((uint64_t)buf[*pos+7] << 56);
    *pos += 8;
    return 0;
}

int smt_read_i32le(const uint8_t *buf, size_t *pos, size_t max, int32_t *v) {
    uint32_t u;
    if (smt_read_u32le(buf, pos, max, &u) < 0) return -1;
    *v = (int32_t)u;
    return 0;
}

int smt_read_i64le(const uint8_t *buf, size_t *pos, size_t max, int64_t *v) {
    uint64_t u;
    if (smt_read_u64le(buf, pos, max, &u) < 0) return -1;
    *v = (int64_t)u;
    return 0;
}

int smt_read_bytes(const uint8_t *buf, size_t *pos, size_t max,
                   uint8_t *out, size_t len) {
    if (*pos + len > max) return -1;
    smt_memcpy(out, buf + *pos, len);
    *pos += len;
    return 0;
}

int smt_read_varint(const uint8_t *buf, size_t *pos, size_t max, uint64_t *v) {
    uint8_t first;
    if (smt_read_u8(buf, pos, max, &first) < 0) return -1;
    if (first < 0xFD) {
        *v = first;
    } else if (first == 0xFD) {
        uint16_t val;
        if (smt_read_u16le(buf, pos, max, &val) < 0) return -1;
        *v = val;
    } else if (first == 0xFE) {
        uint32_t val;
        if (smt_read_u32le(buf, pos, max, &val) < 0) return -1;
        *v = val;
    } else {
        if (smt_read_u64le(buf, pos, max, v) < 0) return -1;
    }
    return 0;
}

int smt_read_varstr(const uint8_t *buf, size_t *pos, size_t max,
                    char *str, size_t str_size, size_t *str_len) {
    uint64_t len;
    if (smt_read_varint(buf, pos, max, &len) < 0) return -1;
    if (len >= str_size) return -1;
    if (smt_read_bytes(buf, pos, max, (uint8_t *)str, (size_t)len) < 0) return -1;
    str[len] = '\0';
    *str_len = (size_t)len;
    return 0;
}
