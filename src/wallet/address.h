/*
 * Smartiecoin Amiga Wallet - Address utilities
 */
#ifndef SMT_ADDRESS_H
#define SMT_ADDRESS_H

#include "../types.h"

/* Create a P2PKH address from a public key hash */
int smt_address_from_pubkey_hash(uint8_t version, const uint8_t hash[20],
                                  char *address, size_t address_size);

/* Create a P2PKH address from a compressed public key */
int smt_address_from_pubkey(uint8_t version, const uint8_t pubkey[33],
                            char *address, size_t address_size);

/* Decode an address to get version byte and pubkey hash */
int smt_address_decode(const char *address, uint8_t *version,
                       uint8_t hash[20]);

/* Validate an address (checksum + version check) */
smt_bool smt_address_validate(const char *address, uint8_t expected_version);

/* Create a P2PKH scriptPubKey from pubkey hash: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG */
int smt_create_p2pkh_script(const uint8_t hash[20], uint8_t *script, size_t script_size);

#endif /* SMT_ADDRESS_H */
