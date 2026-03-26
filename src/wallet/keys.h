/*
 * Smartiecoin Amiga Wallet - Key management
 * Generate, store, and manage private/public key pairs
 */
#ifndef SMT_KEYS_H
#define SMT_KEYS_H

#include "../types.h"

#define SMT_MAX_KEYS 64  /* max keys in wallet */

/* A single key pair */
typedef struct {
    privkey_t  privkey;
    pubkey_t   pubkey;       /* compressed */
    hash160_t  pubkey_hash;  /* HASH160 of pubkey */
    char       address[36];  /* Base58Check address */
    smt_bool   used;         /* has this key been used in a transaction? */
    smt_bool   is_change;    /* is this a change address? */
} smt_keypair_t;

/* Key store */
typedef struct {
    smt_keypair_t keys[SMT_MAX_KEYS];
    int           num_keys;
    uint8_t       addr_prefix;  /* network address version byte */
    uint8_t       wif_prefix;   /* WIF version byte */
} smt_keystore_t;

/* Initialize key store */
void smt_keystore_init(smt_keystore_t *ks, uint8_t addr_prefix, uint8_t wif_prefix);

/* Generate a new key pair and add to store. Returns index or -1 on error */
int smt_keystore_generate(smt_keystore_t *ks, smt_bool is_change);

/* Import a private key (WIF format). Returns index or -1 on error */
int smt_keystore_import_wif(smt_keystore_t *ks, const char *wif);

/* Export a private key to WIF format */
int smt_keystore_export_wif(const smt_keystore_t *ks, int index, char *wif_out, size_t wif_size);

/* Find key by address. Returns index or -1 */
int smt_keystore_find_by_address(const smt_keystore_t *ks, const char *address);

/* Find key by pubkey hash. Returns index or -1 */
int smt_keystore_find_by_hash160(const smt_keystore_t *ks, const uint8_t hash[20]);

/* Get a fresh unused receive address */
const char *smt_keystore_get_receive_address(smt_keystore_t *ks);

/* Get a change address */
const char *smt_keystore_get_change_address(smt_keystore_t *ks);

/* Save key store to file (encrypted with passphrase) */
int smt_keystore_save(const smt_keystore_t *ks, const char *filename, const char *passphrase);

/* Load key store from file */
int smt_keystore_load(smt_keystore_t *ks, const char *filename, const char *passphrase);

/* Get entropy from Amiga hardware (timer, VBlank, mouse, CIA) */
void smt_get_entropy(uint8_t *buf, size_t len);

#endif /* SMT_KEYS_H */
