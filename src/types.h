/*
 * Smartiecoin Amiga Wallet - Portable type definitions
 * Compatible with VBCC (AmigaOS m68k) and modern compilers
 */
#ifndef SMT_TYPES_H
#define SMT_TYPES_H

#ifdef AMIGA
/* VBCC / AmigaOS - no stdint.h */
typedef unsigned char      uint8_t;
typedef signed char        int8_t;
typedef unsigned short     uint16_t;
typedef signed short       int16_t;
typedef unsigned long      uint32_t;
typedef signed long        int32_t;

/* 64-bit: VBCC supports long long on 68k */
typedef unsigned long long uint64_t;
typedef signed long long   int64_t;

typedef unsigned long      size_t;

#define NULL ((void *)0)

#define UINT32_MAX 0xFFFFFFFFUL
#define UINT64_MAX 0xFFFFFFFFFFFFFFFFULL

#else
/* Modern compilers */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#endif

/* Boolean type */
#ifndef __cplusplus
typedef int smt_bool;
#define SMT_TRUE  1
#define SMT_FALSE 0
#endif

/* Smartiecoin amount (satoshis) */
typedef int64_t smt_amount_t;

/* Fixed-size byte arrays */
typedef uint8_t hash256_t[32];
typedef uint8_t hash160_t[20];
typedef uint8_t pubkey_t[33];      /* compressed public key */
typedef uint8_t privkey_t[32];
typedef uint8_t signature_t[72];   /* DER-encoded, max 72 bytes */

/* Endian helpers - Amiga m68k is big-endian, x86 is little-endian */
/* Bitcoin/Smartiecoin wire protocol uses little-endian */

static uint16_t smt_htole16(uint16_t v) {
#ifdef AMIGA
    return ((v & 0xFF) << 8) | ((v >> 8) & 0xFF);
#else
    return v; /* assume little-endian host for testing */
#endif
}

static uint32_t smt_htole32(uint32_t v) {
#ifdef AMIGA
    return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) |
           ((v >> 8) & 0xFF00) | ((v >> 24) & 0xFF);
#else
    return v;
#endif
}

static uint64_t smt_htole64(uint64_t v) {
#ifdef AMIGA
    uint32_t hi = (uint32_t)(v >> 32);
    uint32_t lo = (uint32_t)(v & 0xFFFFFFFF);
    return ((uint64_t)smt_htole32(lo) << 32) | smt_htole32(hi);
#else
    return v;
#endif
}

#define smt_le16toh smt_htole16
#define smt_le32toh smt_htole32
#define smt_le64toh smt_htole64

/* Memory helpers */
static void smt_memzero(void *p, size_t n) {
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) *vp++ = 0;
}

static void smt_memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) *d++ = *s++;
}

static int smt_memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    while (n--) {
        if (*pa != *pb) return (*pa < *pb) ? -1 : 1;
        pa++; pb++;
    }
    return 0;
}

static size_t smt_strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

#endif /* SMT_TYPES_H */
