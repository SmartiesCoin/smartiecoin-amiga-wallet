/*
 * Smartiecoin Amiga Wallet - Transaction creation and signing
 */
#include "tx.h"
#include "keys.h"
#include "address.h"
#include "../chainparams.h"
#include "../crypto/sha256.h"
#include "../crypto/secp256k1.h"
#include "../crypto/base58.h"

/* Script opcodes */
#define OP_DUP          0x76
#define OP_HASH160      0xA9
#define OP_EQUALVERIFY  0x88
#define OP_CHECKSIG     0xAC

/* ---- Serialization helpers ---- */

static int write_u8(uint8_t *buf, size_t *pos, size_t max, uint8_t v) {
    if (*pos + 1 > max) return -1;
    buf[(*pos)++] = v;
    return 0;
}

static int write_u16le(uint8_t *buf, size_t *pos, size_t max, uint16_t v) {
    if (*pos + 2 > max) return -1;
    buf[(*pos)++] = (uint8_t)(v & 0xFF);
    buf[(*pos)++] = (uint8_t)((v >> 8) & 0xFF);
    return 0;
}

static int write_u32le(uint8_t *buf, size_t *pos, size_t max, uint32_t v) {
    if (*pos + 4 > max) return -1;
    buf[(*pos)++] = (uint8_t)(v & 0xFF);
    buf[(*pos)++] = (uint8_t)((v >> 8) & 0xFF);
    buf[(*pos)++] = (uint8_t)((v >> 16) & 0xFF);
    buf[(*pos)++] = (uint8_t)((v >> 24) & 0xFF);
    return 0;
}

static int write_i32le(uint8_t *buf, size_t *pos, size_t max, int32_t v) {
    return write_u32le(buf, pos, max, (uint32_t)v);
}

static int write_u64le(uint8_t *buf, size_t *pos, size_t max, uint64_t v) {
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

static int write_bytes(uint8_t *buf, size_t *pos, size_t max,
                       const uint8_t *data, size_t len) {
    if (*pos + len > max) return -1;
    smt_memcpy(buf + *pos, data, len);
    *pos += len;
    return 0;
}

static int write_varint(uint8_t *buf, size_t *pos, size_t max, uint64_t v) {
    if (v < 0xFD) {
        return write_u8(buf, pos, max, (uint8_t)v);
    } else if (v <= 0xFFFF) {
        if (write_u8(buf, pos, max, 0xFD) < 0) return -1;
        return write_u16le(buf, pos, max, (uint16_t)v);
    } else if (v <= 0xFFFFFFFF) {
        if (write_u8(buf, pos, max, 0xFE) < 0) return -1;
        return write_u32le(buf, pos, max, (uint32_t)v);
    } else {
        if (write_u8(buf, pos, max, 0xFF) < 0) return -1;
        return write_u64le(buf, pos, max, v);
    }
}

/* ---- Read helpers for deserialization ---- */

static int read_u8(const uint8_t *buf, size_t *pos, size_t max, uint8_t *v) {
    if (*pos + 1 > max) return -1;
    *v = buf[(*pos)++];
    return 0;
}

static int read_u32le(const uint8_t *buf, size_t *pos, size_t max, uint32_t *v) {
    if (*pos + 4 > max) return -1;
    *v = (uint32_t)buf[*pos] | ((uint32_t)buf[*pos+1] << 8) |
         ((uint32_t)buf[*pos+2] << 16) | ((uint32_t)buf[*pos+3] << 24);
    *pos += 4;
    return 0;
}

static int read_i32le(const uint8_t *buf, size_t *pos, size_t max, int32_t *v) {
    uint32_t u;
    if (read_u32le(buf, pos, max, &u) < 0) return -1;
    *v = (int32_t)u;
    return 0;
}

static int read_u64le(const uint8_t *buf, size_t *pos, size_t max, uint64_t *v) {
    if (*pos + 8 > max) return -1;
    *v = (uint64_t)buf[*pos] | ((uint64_t)buf[*pos+1] << 8) |
         ((uint64_t)buf[*pos+2] << 16) | ((uint64_t)buf[*pos+3] << 24) |
         ((uint64_t)buf[*pos+4] << 32) | ((uint64_t)buf[*pos+5] << 40) |
         ((uint64_t)buf[*pos+6] << 48) | ((uint64_t)buf[*pos+7] << 56);
    *pos += 8;
    return 0;
}

static int read_u16le(const uint8_t *buf, size_t *pos, size_t max, uint16_t *v) {
    if (*pos + 2 > max) return -1;
    *v = (uint16_t)buf[*pos] | ((uint16_t)buf[*pos+1] << 8);
    *pos += 2;
    return 0;
}

static int read_varint(const uint8_t *buf, size_t *pos, size_t max, uint64_t *v) {
    uint8_t first;
    if (read_u8(buf, pos, max, &first) < 0) return -1;
    if (first < 0xFD) {
        *v = first;
    } else if (first == 0xFD) {
        uint16_t val;
        if (read_u16le(buf, pos, max, &val) < 0) return -1;
        *v = val;
    } else if (first == 0xFE) {
        uint32_t val;
        if (read_u32le(buf, pos, max, &val) < 0) return -1;
        *v = val;
    } else {
        if (read_u64le(buf, pos, max, v) < 0) return -1;
    }
    return 0;
}

static int read_bytes(const uint8_t *buf, size_t *pos, size_t max,
                      uint8_t *out, size_t len) {
    if (*pos + len > max) return -1;
    smt_memcpy(out, buf + *pos, len);
    *pos += len;
    return 0;
}

/* ---- Transaction functions ---- */

void smt_tx_init(smt_tx_t *tx) {
    smt_memzero(tx, sizeof(smt_tx_t));
    tx->version = 3;  /* Smartiecoin/Dash v3 transactions */
    tx->locktime = 0;
    tx->tx_type = 0;
}

int smt_tx_add_input(smt_tx_t *tx, const hash256_t txid, uint32_t vout) {
    smt_txin_t *in;
    if (tx->num_inputs >= SMT_MAX_TX_INPUTS) return -1;

    in = &tx->inputs[tx->num_inputs];
    smt_memcpy(in->prevout.txid, txid, 32);
    in->prevout.vout = vout;
    in->script_sig_len = 0;
    in->sequence = 0xFFFFFFFF;
    tx->num_inputs++;
    return tx->num_inputs - 1;
}

int smt_tx_add_output(smt_tx_t *tx, smt_amount_t value, const char *address,
                      uint8_t addr_version) {
    smt_txout_t *out;
    uint8_t version;
    uint8_t hash[20];
    int script_len;

    if (tx->num_outputs >= SMT_MAX_TX_OUTPUTS) return -1;

    /* Decode address to get pubkey hash */
    if (smt_address_decode(address, &version, hash) < 0)
        return -1;
    if (version != addr_version)
        return -1;

    out = &tx->outputs[tx->num_outputs];
    out->value = value;

    script_len = smt_create_p2pkh_script(hash, out->script_pubkey,
                                          SMT_MAX_SCRIPT_SIZE);
    if (script_len < 0) return -1;
    out->script_pubkey_len = (size_t)script_len;

    tx->num_outputs++;
    return tx->num_outputs - 1;
}

int smt_tx_add_output_raw(smt_tx_t *tx, smt_amount_t value,
                          const uint8_t pubkey_hash[20]) {
    smt_txout_t *out;
    int script_len;

    if (tx->num_outputs >= SMT_MAX_TX_OUTPUTS) return -1;

    out = &tx->outputs[tx->num_outputs];
    out->value = value;

    script_len = smt_create_p2pkh_script(pubkey_hash, out->script_pubkey,
                                          SMT_MAX_SCRIPT_SIZE);
    if (script_len < 0) return -1;
    out->script_pubkey_len = (size_t)script_len;

    tx->num_outputs++;
    return tx->num_outputs - 1;
}

int smt_tx_serialize(const smt_tx_t *tx, uint8_t *buf, size_t buf_size) {
    size_t pos = 0;
    int i;
    /* Dash/Smartiecoin: version includes type in upper 16 bits */
    int32_t nVersion = tx->version | ((int32_t)tx->tx_type << 16);

    if (write_i32le(buf, &pos, buf_size, nVersion) < 0) return -1;

    /* Inputs */
    if (write_varint(buf, &pos, buf_size, (uint64_t)tx->num_inputs) < 0) return -1;
    for (i = 0; i < tx->num_inputs; i++) {
        const smt_txin_t *in = &tx->inputs[i];
        if (write_bytes(buf, &pos, buf_size, in->prevout.txid, 32) < 0) return -1;
        if (write_u32le(buf, &pos, buf_size, in->prevout.vout) < 0) return -1;
        if (write_varint(buf, &pos, buf_size, (uint64_t)in->script_sig_len) < 0) return -1;
        if (in->script_sig_len > 0) {
            if (write_bytes(buf, &pos, buf_size, in->script_sig, in->script_sig_len) < 0) return -1;
        }
        if (write_u32le(buf, &pos, buf_size, in->sequence) < 0) return -1;
    }

    /* Outputs */
    if (write_varint(buf, &pos, buf_size, (uint64_t)tx->num_outputs) < 0) return -1;
    for (i = 0; i < tx->num_outputs; i++) {
        const smt_txout_t *out = &tx->outputs[i];
        if (write_u64le(buf, &pos, buf_size, (uint64_t)out->value) < 0) return -1;
        if (write_varint(buf, &pos, buf_size, (uint64_t)out->script_pubkey_len) < 0) return -1;
        if (write_bytes(buf, &pos, buf_size, out->script_pubkey, out->script_pubkey_len) < 0) return -1;
    }

    /* Locktime */
    if (write_u32le(buf, &pos, buf_size, tx->locktime) < 0) return -1;

    /* Extra payload for special transactions (Dash/Smartiecoin) */
    if (tx->tx_type != 0 && tx->extra_payload_len > 0) {
        if (write_varint(buf, &pos, buf_size, (uint64_t)tx->extra_payload_len) < 0) return -1;
        if (write_bytes(buf, &pos, buf_size, tx->extra_payload, tx->extra_payload_len) < 0) return -1;
    }

    return (int)pos;
}

int smt_tx_deserialize(smt_tx_t *tx, const uint8_t *buf, size_t buf_len) {
    size_t pos = 0;
    int32_t nVersion;
    uint64_t count;
    int i;

    smt_memzero(tx, sizeof(smt_tx_t));

    if (read_i32le(buf, &pos, buf_len, &nVersion) < 0) return -1;
    tx->version = nVersion & 0xFFFF;
    tx->tx_type = (uint16_t)((nVersion >> 16) & 0xFFFF);

    /* Inputs */
    if (read_varint(buf, &pos, buf_len, &count) < 0) return -1;
    if (count > SMT_MAX_TX_INPUTS) return -1;
    tx->num_inputs = (int)count;

    for (i = 0; i < tx->num_inputs; i++) {
        smt_txin_t *in = &tx->inputs[i];
        uint64_t script_len;
        if (read_bytes(buf, &pos, buf_len, in->prevout.txid, 32) < 0) return -1;
        if (read_u32le(buf, &pos, buf_len, &in->prevout.vout) < 0) return -1;
        if (read_varint(buf, &pos, buf_len, &script_len) < 0) return -1;
        if (script_len > SMT_MAX_SCRIPT_SIZE) return -1;
        in->script_sig_len = (size_t)script_len;
        if (script_len > 0) {
            if (read_bytes(buf, &pos, buf_len, in->script_sig, in->script_sig_len) < 0) return -1;
        }
        if (read_u32le(buf, &pos, buf_len, &in->sequence) < 0) return -1;
    }

    /* Outputs */
    if (read_varint(buf, &pos, buf_len, &count) < 0) return -1;
    if (count > SMT_MAX_TX_OUTPUTS) return -1;
    tx->num_outputs = (int)count;

    for (i = 0; i < tx->num_outputs; i++) {
        smt_txout_t *out = &tx->outputs[i];
        uint64_t script_len;
        uint64_t raw_value;
        if (read_u64le(buf, &pos, buf_len, &raw_value) < 0) return -1;
        out->value = (smt_amount_t)raw_value;
        if (read_varint(buf, &pos, buf_len, &script_len) < 0) return -1;
        if (script_len > SMT_MAX_SCRIPT_SIZE) return -1;
        out->script_pubkey_len = (size_t)script_len;
        if (read_bytes(buf, &pos, buf_len, out->script_pubkey, out->script_pubkey_len) < 0) return -1;
    }

    /* Locktime */
    if (read_u32le(buf, &pos, buf_len, &tx->locktime) < 0) return -1;

    /* Extra payload */
    if (tx->tx_type != 0 && pos < buf_len) {
        uint64_t payload_len;
        if (read_varint(buf, &pos, buf_len, &payload_len) < 0) return -1;
        if (payload_len > sizeof(tx->extra_payload)) return -1;
        tx->extra_payload_len = (size_t)payload_len;
        if (read_bytes(buf, &pos, buf_len, tx->extra_payload, tx->extra_payload_len) < 0) return -1;
    }

    return (int)pos;
}

int smt_tx_sighash(const smt_tx_t *tx, int input_index,
                   const uint8_t *prev_script, size_t prev_script_len,
                   uint8_t hash[32]) {
    /*
     * SIGHASH_ALL: serialize the transaction with:
     * - all inputs' scriptSigs cleared to empty
     * - the signing input's scriptSig set to prev_script
     * - append SIGHASH_ALL as uint32_t LE
     * Then SHA256d the result
     */
    uint8_t buf[8192]; /* should be enough for our transactions */
    size_t pos = 0;
    int i;
    int32_t nVersion = tx->version | ((int32_t)tx->tx_type << 16);

    if (write_i32le(buf, &pos, sizeof(buf), nVersion) < 0) return -1;

    /* Inputs */
    if (write_varint(buf, &pos, sizeof(buf), (uint64_t)tx->num_inputs) < 0) return -1;
    for (i = 0; i < tx->num_inputs; i++) {
        const smt_txin_t *in = &tx->inputs[i];
        if (write_bytes(buf, &pos, sizeof(buf), in->prevout.txid, 32) < 0) return -1;
        if (write_u32le(buf, &pos, sizeof(buf), in->prevout.vout) < 0) return -1;

        if (i == input_index) {
            /* Insert the previous output's scriptPubKey */
            if (write_varint(buf, &pos, sizeof(buf), (uint64_t)prev_script_len) < 0) return -1;
            if (write_bytes(buf, &pos, sizeof(buf), prev_script, prev_script_len) < 0) return -1;
        } else {
            /* Empty script */
            if (write_varint(buf, &pos, sizeof(buf), 0) < 0) return -1;
        }
        if (write_u32le(buf, &pos, sizeof(buf), in->sequence) < 0) return -1;
    }

    /* Outputs */
    if (write_varint(buf, &pos, sizeof(buf), (uint64_t)tx->num_outputs) < 0) return -1;
    for (i = 0; i < tx->num_outputs; i++) {
        const smt_txout_t *out = &tx->outputs[i];
        if (write_u64le(buf, &pos, sizeof(buf), (uint64_t)out->value) < 0) return -1;
        if (write_varint(buf, &pos, sizeof(buf), (uint64_t)out->script_pubkey_len) < 0) return -1;
        if (write_bytes(buf, &pos, sizeof(buf), out->script_pubkey, out->script_pubkey_len) < 0) return -1;
    }

    /* Locktime */
    if (write_u32le(buf, &pos, sizeof(buf), tx->locktime) < 0) return -1;

    /* SIGHASH_ALL */
    if (write_u32le(buf, &pos, sizeof(buf), SMT_SIGHASH_ALL) < 0) return -1;

    /* Double SHA-256 */
    smt_sha256d(buf, pos, hash);
    return 0;
}

int smt_tx_sign_input(smt_tx_t *tx, int input_index,
                      const uint8_t privkey[32], const uint8_t pubkey[33],
                      const uint8_t *prev_script, size_t prev_script_len) {
    hash256_t sighash;
    uint8_t sig[72];
    size_t sig_len;
    smt_txin_t *in;
    size_t pos;

    if (input_index < 0 || input_index >= tx->num_inputs)
        return -1;

    /* Compute sighash */
    if (smt_tx_sighash(tx, input_index, prev_script, prev_script_len, sighash) < 0)
        return -1;

    /* Sign */
    if (smt_ecdsa_sign(sig, &sig_len, sighash, privkey) < 0)
        return -1;

    /* Build scriptSig: <sig + SIGHASH_ALL byte> <pubkey> */
    in = &tx->inputs[input_index];
    pos = 0;

    /* Push signature + hashtype */
    in->script_sig[pos++] = (uint8_t)(sig_len + 1); /* push length */
    smt_memcpy(in->script_sig + pos, sig, sig_len);
    pos += sig_len;
    in->script_sig[pos++] = SMT_SIGHASH_ALL;

    /* Push compressed pubkey */
    in->script_sig[pos++] = 33; /* push 33 bytes */
    smt_memcpy(in->script_sig + pos, pubkey, 33);
    pos += 33;

    in->script_sig_len = pos;
    return 0;
}

void smt_tx_txid(const smt_tx_t *tx, hash256_t txid) {
    uint8_t buf[8192];
    int len;
    int i;

    len = smt_tx_serialize(tx, buf, sizeof(buf));
    if (len < 0) {
        smt_memzero(txid, 32);
        return;
    }

    smt_sha256d(buf, (size_t)len, txid);

    /* Bitcoin/Smartiecoin txid is displayed reversed */
    for (i = 0; i < 16; i++) {
        uint8_t tmp = txid[i];
        txid[i] = txid[31 - i];
        txid[31 - i] = tmp;
    }
}

smt_amount_t smt_utxo_get_balance(const smt_utxo_set_t *set) {
    smt_amount_t total = 0;
    int i;
    for (i = 0; i < set->num_utxos; i++) {
        total += set->utxos[i].value;
    }
    return total;
}

int smt_utxo_select(const smt_utxo_set_t *set, smt_amount_t target,
                    smt_amount_t fee_per_byte, int *indices, int max_indices,
                    smt_amount_t *total_selected) {
    /*
     * Simple coin selection: pick UTXOs largest-first until we have enough.
     * A proper implementation would use branch-and-bound, but this works
     * fine for a simple wallet.
     */
    int selected = 0;
    smt_amount_t total = 0;
    smt_amount_t estimated_fee;
    int j;
    int used[SMT_MAX_UTXOS];

    smt_memzero(used, sizeof(used));
    *total_selected = 0;

    while (selected < max_indices) {
        /* Estimate fee for current selection */
        /* ~180 bytes per input, ~34 bytes per output, ~10 overhead, 2 outputs (dest+change) */
        estimated_fee = fee_per_byte * (10 + (selected + 1) * 180 + 2 * 34);

        if (total >= target + estimated_fee) {
            *total_selected = total;
            return selected;
        }

        /* Find largest unused UTXO */
        {
            int best = -1;
            smt_amount_t best_val = 0;
            for (j = 0; j < set->num_utxos; j++) {
                if (!used[j] && set->utxos[j].value > best_val) {
                    best = j;
                    best_val = set->utxos[j].value;
                }
            }
            if (best < 0) break; /* no more UTXOs */

            used[best] = 1;
            indices[selected++] = best;
            total += best_val;
        }
    }

    /* Check if we have enough */
    estimated_fee = fee_per_byte * (10 + selected * 180 + 2 * 34);
    if (total >= target + estimated_fee) {
        *total_selected = total;
        return selected;
    }

    return -1; /* insufficient funds */
}

int smt_tx_build_and_sign(smt_tx_t *tx,
                          const smt_utxo_set_t *utxos,
                          const char *dest_address, smt_amount_t amount,
                          smt_amount_t fee_per_byte,
                          void *keystore_ptr,
                          uint8_t addr_version) {
    smt_keystore_t *ks = (smt_keystore_t *)keystore_ptr;
    int indices[SMT_MAX_TX_INPUTS];
    smt_amount_t total_in;
    smt_amount_t fee, change;
    int num_selected, i;
    const char *change_addr;

    smt_tx_init(tx);

    /* Select UTXOs */
    num_selected = smt_utxo_select(utxos, amount, fee_per_byte,
                                   indices, SMT_MAX_TX_INPUTS, &total_in);
    if (num_selected < 0)
        return -1;

    /* Add inputs */
    for (i = 0; i < num_selected; i++) {
        const smt_utxo_t *u = &utxos->utxos[indices[i]];
        smt_tx_add_input(tx, u->outpoint.txid, u->outpoint.vout);
    }

    /* Calculate fee */
    fee = fee_per_byte * (10 + num_selected * 180 + 2 * 34);
    change = total_in - amount - fee;

    /* Add destination output */
    if (smt_tx_add_output(tx, amount, dest_address, addr_version) < 0)
        return -1;

    /* Add change output if significant (> dust threshold of 1000 satoshis) */
    if (change > 1000) {
        change_addr = smt_keystore_get_change_address(ks);
        if (!change_addr) return -1;
        if (smt_tx_add_output(tx, change, change_addr, addr_version) < 0)
            return -1;
    }

    /* Sign all inputs */
    for (i = 0; i < num_selected; i++) {
        const smt_utxo_t *u = &utxos->utxos[indices[i]];
        int key_idx = u->key_index;

        if (key_idx < 0 || key_idx >= ks->num_keys)
            return -1;

        if (smt_tx_sign_input(tx, i,
                              ks->keys[key_idx].privkey,
                              ks->keys[key_idx].pubkey,
                              u->script_pubkey, u->script_pubkey_len) < 0)
            return -1;
    }

    return 0;
}

void smt_format_amount(smt_amount_t amount, char *buf, size_t buf_size) {
    int64_t whole, frac;
    int neg = 0;
    int i, len;
    char tmp[32];

    if (amount < 0) {
        neg = 1;
        amount = -amount;
    }

    whole = amount / SMT_COIN;
    frac = amount % SMT_COIN;

    /* Format: "[-]N.FFFFFFFF SMT" */
    len = 0;
    if (neg) tmp[len++] = '-';

    /* Integer part */
    {
        char digits[20];
        int nd = 0;
        int64_t w = whole;
        if (w == 0) {
            digits[nd++] = '0';
        } else {
            while (w > 0) {
                digits[nd++] = '0' + (char)(w % 10);
                w /= 10;
            }
        }
        for (i = nd - 1; i >= 0; i--) {
            if ((size_t)len < buf_size - 1)
                tmp[len++] = digits[i];
        }
    }

    tmp[len++] = '.';

    /* Fractional part - 8 digits */
    {
        int64_t f = frac;
        char fdigits[8];
        for (i = 7; i >= 0; i--) {
            fdigits[i] = '0' + (char)(f % 10);
            f /= 10;
        }
        for (i = 0; i < 8; i++) {
            if ((size_t)len < buf_size - 1)
                tmp[len++] = fdigits[i];
        }
    }

    /* " SMT" suffix */
    if ((size_t)(len + 4) < buf_size) {
        tmp[len++] = ' ';
        tmp[len++] = 'S';
        tmp[len++] = 'M';
        tmp[len++] = 'T';
    }
    tmp[len] = '\0';

    smt_memcpy(buf, tmp, (size_t)(len + 1));
}
