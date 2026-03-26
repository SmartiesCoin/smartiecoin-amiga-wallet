/*
 * Smartiecoin Amiga Wallet - Address utilities
 */
#include "address.h"
#include "../crypto/sha256.h"
#include "../crypto/ripemd160.h"
#include "../crypto/base58.h"

/* Bitcoin script opcodes */
#define OP_DUP          0x76
#define OP_HASH160      0xA9
#define OP_EQUALVERIFY  0x88
#define OP_CHECKSIG     0xAC

int smt_address_from_pubkey_hash(uint8_t version, const uint8_t hash[20],
                                  char *address, size_t address_size) {
    return smt_base58check_encode(version, hash, 20, address, address_size);
}

int smt_address_from_pubkey(uint8_t version, const uint8_t pubkey[33],
                            char *address, size_t address_size) {
    hash160_t hash;
    smt_hash160(pubkey, 33, hash);
    return smt_base58check_encode(version, hash, 20, address, address_size);
}

int smt_address_decode(const char *address, uint8_t *version,
                       uint8_t hash[20]) {
    size_t payload_len;
    return smt_base58check_decode(address, version, hash, 20, &payload_len);
}

smt_bool smt_address_validate(const char *address, uint8_t expected_version) {
    uint8_t version;
    uint8_t hash[20];
    size_t payload_len;

    if (smt_base58check_decode(address, &version, hash, 20, &payload_len) < 0)
        return SMT_FALSE;
    if (version != expected_version)
        return SMT_FALSE;
    if (payload_len != 20)
        return SMT_FALSE;
    return SMT_TRUE;
}

int smt_create_p2pkh_script(const uint8_t hash[20], uint8_t *script, size_t script_size) {
    /* P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG = 25 bytes */
    if (script_size < 25) return -1;

    script[0] = OP_DUP;
    script[1] = OP_HASH160;
    script[2] = 0x14;  /* push 20 bytes */
    smt_memcpy(script + 3, hash, 20);
    script[23] = OP_EQUALVERIFY;
    script[24] = OP_CHECKSIG;
    return 25;
}
