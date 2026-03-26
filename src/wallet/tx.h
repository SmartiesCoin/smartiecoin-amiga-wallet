/*
 * Smartiecoin Amiga Wallet - Transaction creation and signing
 */
#ifndef SMT_TX_H
#define SMT_TX_H

#include "../types.h"

#define SMT_MAX_TX_INPUTS   16
#define SMT_MAX_TX_OUTPUTS  16
#define SMT_MAX_SCRIPT_SIZE 256
#define SMT_SIGHASH_ALL     0x01

/* Outpoint: reference to a previous transaction output */
typedef struct {
    hash256_t txid;
    uint32_t  vout;
} smt_outpoint_t;

/* Transaction input */
typedef struct {
    smt_outpoint_t prevout;
    uint8_t        script_sig[SMT_MAX_SCRIPT_SIZE];
    size_t         script_sig_len;
    uint32_t       sequence;
} smt_txin_t;

/* Transaction output */
typedef struct {
    smt_amount_t   value;
    uint8_t        script_pubkey[SMT_MAX_SCRIPT_SIZE];
    size_t         script_pubkey_len;
} smt_txout_t;

/* Complete transaction */
typedef struct {
    int32_t    version;
    smt_txin_t  inputs[SMT_MAX_TX_INPUTS];
    int          num_inputs;
    smt_txout_t  outputs[SMT_MAX_TX_OUTPUTS];
    int          num_outputs;
    uint32_t   locktime;

    /* Extra fields for Dash/Smartiecoin special transactions */
    uint16_t   tx_type;      /* 0 = normal, others = special TX types */
    uint8_t    extra_payload[256];
    size_t     extra_payload_len;
} smt_tx_t;

/* UTXO: unspent transaction output we own */
typedef struct {
    smt_outpoint_t outpoint;
    smt_amount_t   value;
    uint8_t        script_pubkey[SMT_MAX_SCRIPT_SIZE];
    size_t         script_pubkey_len;
    int32_t        confirmations;
    int            key_index;   /* index into keystore */
} smt_utxo_t;

#define SMT_MAX_UTXOS 256

typedef struct {
    smt_utxo_t utxos[SMT_MAX_UTXOS];
    int        num_utxos;
} smt_utxo_set_t;

/* Initialize a transaction */
void smt_tx_init(smt_tx_t *tx);

/* Add an input (unsigned) */
int smt_tx_add_input(smt_tx_t *tx, const hash256_t txid, uint32_t vout);

/* Add a P2PKH output */
int smt_tx_add_output(smt_tx_t *tx, smt_amount_t value, const char *address, uint8_t addr_version);

/* Add a P2PKH output from raw pubkey hash */
int smt_tx_add_output_raw(smt_tx_t *tx, smt_amount_t value, const uint8_t pubkey_hash[20]);

/* Compute the sighash for input at index (SIGHASH_ALL) */
int smt_tx_sighash(const smt_tx_t *tx, int input_index,
                   const uint8_t *prev_script, size_t prev_script_len,
                   uint8_t hash[32]);

/* Sign input at index with the given private key */
int smt_tx_sign_input(smt_tx_t *tx, int input_index,
                      const uint8_t privkey[32], const uint8_t pubkey[33],
                      const uint8_t *prev_script, size_t prev_script_len);

/* Serialize a transaction to raw bytes. Returns length or -1 */
int smt_tx_serialize(const smt_tx_t *tx, uint8_t *buf, size_t buf_size);

/* Deserialize a transaction from raw bytes. Returns bytes consumed or -1 */
int smt_tx_deserialize(smt_tx_t *tx, const uint8_t *buf, size_t buf_len);

/* Compute transaction ID (txid = SHA256d of serialized TX, reversed) */
void smt_tx_txid(const smt_tx_t *tx, hash256_t txid);

/* Get total balance from UTXO set */
smt_amount_t smt_utxo_get_balance(const smt_utxo_set_t *set);

/* Select UTXOs for a target amount. Returns number selected, fills indices[] */
int smt_utxo_select(const smt_utxo_set_t *set, smt_amount_t target,
                    smt_amount_t fee_per_byte, int *indices, int max_indices,
                    smt_amount_t *total_selected);

/* Build a complete transaction: select UTXOs, create outputs, add change, sign */
int smt_tx_build_and_sign(smt_tx_t *tx,
                          const smt_utxo_set_t *utxos,
                          const char *dest_address, smt_amount_t amount,
                          smt_amount_t fee_per_byte,
                          void *keystore, /* smt_keystore_t* */
                          uint8_t addr_version);

/* Format an amount as string: "1.23456789 SMT" */
void smt_format_amount(smt_amount_t amount, char *buf, size_t buf_size);

#endif /* SMT_TX_H */
