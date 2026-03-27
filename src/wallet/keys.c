/*
 * Smartiecoin Amiga Wallet - Key management
 */
#include "keys.h"
#include "address.h"
#include "../crypto/sha256.h"
#include "../crypto/ripemd160.h"
#include "../crypto/secp256k1.h"
#include "../crypto/base58.h"

#ifdef AMIGA
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/timer.h>
#include <proto/intuition.h>
#include <dos/dos.h>
#include <devices/timer.h>
#include <hardware/cia.h>
#include <hardware/custom.h>
#else
#include <stdio.h>
#include <time.h>
#endif

void smt_keystore_init(smt_keystore_t *ks, uint8_t addr_prefix, uint8_t wif_prefix) {
    smt_memzero(ks, sizeof(smt_keystore_t));
    ks->addr_prefix = addr_prefix;
    ks->wif_prefix = wif_prefix;
}

/* Gather entropy from available sources */
void smt_get_entropy(uint8_t *buf, size_t len) {
#ifdef AMIGA
    /*
     * On Amiga, combine multiple entropy sources:
     * - CIA timer A/B values (microsecond resolution)
     * - VBlank counter
     * - Vertical beam position
     * - Mouse position
     * Then hash it all together with SHA-256
     */
    size_t pos = 0;
    uint8_t raw[64];
    hash256_t hash;

    while (pos < len) {
        volatile struct CIA *ciaa = (struct CIA *)0xBFE001;
        volatile struct Custom *custom = (struct Custom *)0xDFF000;
        size_t i;

        /* Read CIA timers */
        raw[0] = ciaa->ciatalo;
        raw[1] = ciaa->ciatahi;
        raw[2] = ciaa->ciatblo;
        raw[3] = ciaa->ciatbhi;

        /* Vertical beam position */
        raw[4] = (uint8_t)(custom->vhposr >> 8);
        raw[5] = (uint8_t)(custom->vhposr & 0xFF);

        /* Mouse position */
        raw[6] = (uint8_t)(custom->joy0dat >> 8);
        raw[7] = (uint8_t)(custom->joy0dat & 0xFF);

        /* Read some exec counters */
        raw[8] = (uint8_t)((uint32_t)FindTask(NULL) & 0xFF);
        raw[9] = (uint8_t)(((uint32_t)FindTask(NULL) >> 8) & 0xFF);

        /* Fill rest with timer reads in a loop for jitter */
        for (i = 10; i < 64; i++) {
            raw[i] = ciaa->ciatalo ^ ciaa->ciatblo;
        }

        smt_sha256(raw, 64, hash);

        for (i = 0; i < 32 && pos < len; i++, pos++) {
            buf[pos] = hash[i];
        }
    }
    smt_memzero(raw, sizeof(raw));
#else
    /* Fallback for testing on PC: use /dev/urandom or time-based */
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(buf, 1, len, f);
        fclose(f);
    } else {
        /* Very weak fallback - only for testing! */
        size_t i;
        hash256_t hash;
        uint32_t seed = (uint32_t)time(NULL);
        for (i = 0; i < len; i++) {
            seed = seed * 1103515245 + 12345;
            buf[i] = (uint8_t)(seed >> 16);
        }
        /* Hash it to spread entropy */
        smt_sha256(buf, len, hash);
        for (i = 0; i < len && i < 32; i++)
            buf[i] = hash[i];
    }
#endif
}

int smt_keystore_generate(smt_keystore_t *ks, smt_bool is_change) {
    smt_keypair_t *kp;
    int idx;

    if (ks->num_keys >= SMT_MAX_KEYS)
        return -1;

    idx = ks->num_keys;
    kp = &ks->keys[idx];
    smt_memzero(kp, sizeof(smt_keypair_t));

    /* Generate random private key */
    smt_get_entropy(kp->privkey, 32);

    /* Ensure private key is valid (non-zero, less than curve order) */
    /* Simple check: if all zeros, regenerate */
    {
        int all_zero = 1;
        int i;
        for (i = 0; i < 32; i++) {
            if (kp->privkey[i] != 0) { all_zero = 0; break; }
        }
        if (all_zero) {
            smt_get_entropy(kp->privkey, 32);
        }
    }

    /* Derive compressed public key */
    smt_ec_pubkey_create(kp->pubkey, kp->privkey);

    /* Compute HASH160 of public key */
    smt_hash160(kp->pubkey, 33, kp->pubkey_hash);

    /* Create address */
    smt_address_from_pubkey_hash(ks->addr_prefix, kp->pubkey_hash,
                                 kp->address, sizeof(kp->address));

    kp->used = SMT_FALSE;
    kp->is_change = is_change;
    ks->num_keys++;

    return idx;
}

int smt_keystore_import_wif(smt_keystore_t *ks, const char *wif) {
    uint8_t version;
    uint8_t payload[34]; /* 32 bytes key + optional 0x01 compression flag */
    size_t payload_len;
    smt_keypair_t *kp;
    int idx;

    if (ks->num_keys >= SMT_MAX_KEYS)
        return -1;

    if (smt_base58check_decode(wif, &version, payload, sizeof(payload), &payload_len) < 0)
        return -1;

    if (version != ks->wif_prefix)
        return -1;

    /* WIF: 32 bytes = uncompressed, 33 bytes (last=0x01) = compressed */
    if (payload_len != 32 && payload_len != 33)
        return -1;

    idx = ks->num_keys;
    kp = &ks->keys[idx];
    smt_memzero(kp, sizeof(smt_keypair_t));

    smt_memcpy(kp->privkey, payload, 32);
    smt_memzero(payload, sizeof(payload));

    /* Always use compressed public keys */
    smt_ec_pubkey_create(kp->pubkey, kp->privkey);
    smt_hash160(kp->pubkey, 33, kp->pubkey_hash);
    smt_address_from_pubkey_hash(ks->addr_prefix, kp->pubkey_hash,
                                 kp->address, sizeof(kp->address));

    kp->used = SMT_FALSE;
    kp->is_change = SMT_FALSE;
    ks->num_keys++;

    return idx;
}

int smt_keystore_export_wif(const smt_keystore_t *ks, int index,
                            char *wif_out, size_t wif_size) {
    uint8_t payload[33];

    if (index < 0 || index >= ks->num_keys)
        return -1;

    smt_memcpy(payload, ks->keys[index].privkey, 32);
    payload[32] = 0x01; /* compressed flag */

    return smt_base58check_encode(ks->wif_prefix, payload, 33, wif_out, wif_size);
}

int smt_keystore_find_by_address(const smt_keystore_t *ks, const char *address) {
    int i;
    for (i = 0; i < ks->num_keys; i++) {
        size_t len1 = smt_strlen(ks->keys[i].address);
        size_t len2 = smt_strlen(address);
        if (len1 == len2 && smt_memcmp(ks->keys[i].address, address, len1) == 0)
            return i;
    }
    return -1;
}

int smt_keystore_find_by_hash160(const smt_keystore_t *ks, const uint8_t hash[20]) {
    int i;
    for (i = 0; i < ks->num_keys; i++) {
        if (smt_memcmp(ks->keys[i].pubkey_hash, hash, 20) == 0)
            return i;
    }
    return -1;
}

const char *smt_keystore_get_receive_address(smt_keystore_t *ks) {
    int i;
    /* Find first unused non-change key */
    for (i = 0; i < ks->num_keys; i++) {
        if (!ks->keys[i].used && !ks->keys[i].is_change)
            return ks->keys[i].address;
    }
    /* Generate a new one */
    i = smt_keystore_generate(ks, SMT_FALSE);
    if (i < 0) return NULL;
    return ks->keys[i].address;
}

const char *smt_keystore_get_change_address(smt_keystore_t *ks) {
    int i;
    for (i = 0; i < ks->num_keys; i++) {
        if (!ks->keys[i].used && ks->keys[i].is_change)
            return ks->keys[i].address;
    }
    i = smt_keystore_generate(ks, SMT_TRUE);
    if (i < 0) return NULL;
    return ks->keys[i].address;
}

/*
 * Simple wallet file format (encrypted):
 * [4 bytes] "SMTW" magic
 * [4 bytes] version (1)
 * [32 bytes] salt (random)
 * [32 bytes] checksum (SHA256 of decrypted data)
 * [N bytes] encrypted key data (XOR with SHA256-derived keystream)
 *
 * Encryption: derive key from SHA256(passphrase || salt), then XOR stream
 * This is simple but adequate for the Amiga platform.
 */

static void derive_file_key(const char *passphrase, const uint8_t salt[32],
                            uint8_t key[32]) {
    smt_sha256_ctx ctx;
    smt_sha256_init(&ctx);
    smt_sha256_update(&ctx, (const uint8_t *)passphrase, smt_strlen(passphrase));
    smt_sha256_update(&ctx, salt, 32);
    smt_sha256_final(&ctx, key);
}

static void xor_crypt(uint8_t *data, size_t len, const uint8_t key[32]) {
    size_t i;
    hash256_t block;
    uint8_t counter[36]; /* key(32) + counter(4) */
    uint32_t ctr = 0;
    size_t pos = 0;

    smt_memcpy(counter, key, 32);

    while (pos < len) {
        counter[32] = (uint8_t)(ctr & 0xFF);
        counter[33] = (uint8_t)((ctr >> 8) & 0xFF);
        counter[34] = (uint8_t)((ctr >> 16) & 0xFF);
        counter[35] = (uint8_t)((ctr >> 24) & 0xFF);
        smt_sha256(counter, 36, block);

        for (i = 0; i < 32 && pos < len; i++, pos++) {
            data[pos] ^= block[i];
        }
        ctr++;
    }
}

int smt_keystore_save(const smt_keystore_t *ks, const char *filename,
                      const char *passphrase) {
    uint8_t salt[32];
    uint8_t file_key[32];
    hash256_t checksum;
    uint8_t header[72]; /* 4 magic + 4 version + 32 salt + 32 checksum */
    uint8_t data[SMT_MAX_KEYS * (32 + 33 + 20 + 36 + 2)]; /* privkey+pubkey+hash+addr+flags */
    size_t data_len = 0;
    int i;

#ifdef AMIGA
    BPTR fh;
#else
    FILE *f;
#endif

    /* Serialize key data */
    for (i = 0; i < ks->num_keys; i++) {
        const smt_keypair_t *kp = &ks->keys[i];
        smt_memcpy(data + data_len, kp->privkey, 32); data_len += 32;
        smt_memcpy(data + data_len, kp->pubkey, 33); data_len += 33;
        smt_memcpy(data + data_len, kp->pubkey_hash, 20); data_len += 20;
        smt_memcpy(data + data_len, kp->address, 36); data_len += 36;
        data[data_len++] = kp->used ? 1 : 0;
        data[data_len++] = kp->is_change ? 1 : 0;
    }

    /* Generate salt */
    smt_get_entropy(salt, 32);

    /* Compute checksum of plaintext */
    smt_sha256(data, data_len, checksum);

    /* Derive encryption key and encrypt */
    derive_file_key(passphrase, salt, file_key);
    xor_crypt(data, data_len, file_key);

    /* Build header */
    header[0] = 'S'; header[1] = 'M'; header[2] = 'T'; header[3] = 'W';
    header[4] = 1; header[5] = 0; header[6] = 0; header[7] = 0; /* version 1 */
    smt_memcpy(header + 8, salt, 32);
    smt_memcpy(header + 40, checksum, 32);

    /* Write file */
#ifdef AMIGA
    fh = Open((STRPTR)filename, MODE_NEWFILE);
    if (!fh) return -1;
    Write(fh, header, 72);
    Write(fh, &ks->num_keys, 4);
    Write(fh, data, data_len);
    Close(fh);
#else
    f = fopen(filename, "wb");
    if (!f) return -1;
    fwrite(header, 1, 72, f);
    fwrite(&ks->num_keys, 1, 4, f);
    fwrite(data, 1, data_len, f);
    fclose(f);
#endif

    smt_memzero(file_key, 32);
    smt_memzero(data, sizeof(data));
    return 0;
}

int smt_keystore_load(smt_keystore_t *ks, const char *filename,
                      const char *passphrase) {
    uint8_t header[72];
    uint8_t file_key[32];
    hash256_t checksum, verify;
    uint8_t data[SMT_MAX_KEYS * (32 + 33 + 20 + 36 + 2)];
    int32_t num_keys;
    size_t data_len, pos;
    int i;

#ifdef AMIGA
    BPTR fh;
    LONG bytes_read;
#else
    FILE *f;
#endif

#ifdef AMIGA
    fh = Open((STRPTR)filename, MODE_OLDFILE);
    if (!fh) return -1;
    bytes_read = Read(fh, header, 72);
    if (bytes_read != 72) { Close(fh); return -1; }
    Read(fh, &num_keys, 4);
#else
    f = fopen(filename, "rb");
    if (!f) return -1;
    if (fread(header, 1, 72, f) != 72) { fclose(f); return -1; }
    fread(&num_keys, 1, 4, f);
#endif

    /* Verify magic */
    if (header[0] != 'S' || header[1] != 'M' || header[2] != 'T' || header[3] != 'W') {
#ifdef AMIGA
        Close(fh);
#else
        fclose(f);
#endif
        return -1;
    }

    if (num_keys < 0 || num_keys > SMT_MAX_KEYS) {
#ifdef AMIGA
        Close(fh);
#else
        fclose(f);
#endif
        return -1;
    }

    data_len = (size_t)num_keys * (32 + 33 + 20 + 36 + 2);

#ifdef AMIGA
    Read(fh, data, data_len);
    Close(fh);
#else
    fread(data, 1, data_len, f);
    fclose(f);
#endif

    /* Decrypt */
    smt_memcpy(checksum, header + 40, 32);
    derive_file_key(passphrase, header + 8, file_key);
    xor_crypt(data, data_len, file_key);

    /* Verify checksum */
    smt_sha256(data, data_len, verify);
    if (smt_memcmp(checksum, verify, 32) != 0) {
        smt_memzero(data, sizeof(data));
        smt_memzero(file_key, 32);
        return -1; /* wrong passphrase */
    }

    /* Deserialize */
    pos = 0;
    for (i = 0; i < num_keys; i++) {
        smt_keypair_t *kp = &ks->keys[i];
        smt_memcpy(kp->privkey, data + pos, 32); pos += 32;
        smt_memcpy(kp->pubkey, data + pos, 33); pos += 33;
        smt_memcpy(kp->pubkey_hash, data + pos, 20); pos += 20;
        smt_memcpy(kp->address, data + pos, 36); pos += 36;
        kp->used = data[pos++] ? SMT_TRUE : SMT_FALSE;
        kp->is_change = data[pos++] ? SMT_TRUE : SMT_FALSE;
    }
    ks->num_keys = num_keys;

    smt_memzero(data, sizeof(data));
    smt_memzero(file_key, 32);
    return 0;
}
