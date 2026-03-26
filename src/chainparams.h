/*
 * Smartiecoin Amiga Wallet - Chain parameters
 * Network constants for Smartiecoin mainnet/testnet
 */
#ifndef SMT_CHAINPARAMS_H
#define SMT_CHAINPARAMS_H

#include "types.h"

/* ---- Mainnet ---- */
#define SMT_MAINNET_MAGIC_0     0xE4
#define SMT_MAINNET_MAGIC_1     0xBA
#define SMT_MAINNET_MAGIC_2     0xB3
#define SMT_MAINNET_MAGIC_3     0xC7

#define SMT_MAINNET_PORT        8383
#define SMT_MAINNET_PUBKEY_ADDR 63   /* addresses start with 'S' */
#define SMT_MAINNET_SCRIPT_ADDR 82   /* addresses start with 'T' */
#define SMT_MAINNET_WIF_PREFIX  128
#define SMT_MAINNET_BIP44_TYPE  5

/* ---- Testnet ---- */
#define SMT_TESTNET_MAGIC_0     0xF2
#define SMT_TESTNET_MAGIC_1     0xD3
#define SMT_TESTNET_MAGIC_2     0xB4
#define SMT_TESTNET_MAGIC_3     0xE5

#define SMT_TESTNET_PORT        19383
#define SMT_TESTNET_PUBKEY_ADDR 140  /* addresses start with 'y' */
#define SMT_TESTNET_SCRIPT_ADDR 19   /* addresses start with '8' or '9' */
#define SMT_TESTNET_WIF_PREFIX  239
#define SMT_TESTNET_BIP44_TYPE  1

/* ---- Common ---- */
#define SMT_COIN                100000000LL  /* 1 SMT = 100,000,000 satoshis */
#define SMT_MAX_SUPPLY          100000000LL  /* 100 million SMT */
#define SMT_PROTOCOL_VERSION    70230
#define SMT_USER_AGENT          "/SmartiecoinAmiga:0.1.0/"

/* P2P message size limits */
#define SMT_MAX_MESSAGE_SIZE    (4 * 1024 * 1024)  /* 4 MB */
#define SMT_MAX_HEADERS_BATCH   2000

/* Block header size is always 80 bytes */
#define SMT_BLOCK_HEADER_SIZE   80

/* DNS seeds for peer discovery */
#define SMT_NUM_SEEDS 2
static const char *smt_dns_seeds[SMT_NUM_SEEDS] = {
    "seed1.smartiecoin.com",
    "seed2.smartiecoin.com"
};

/* Well-known fixed seed nodes (IP:port) */
#define SMT_NUM_FIXED_SEEDS 1
static const char *smt_fixed_seeds[SMT_NUM_FIXED_SEEDS] = {
    "207.180.230.125"
};

/* Chain parameters structure */
typedef struct {
    uint8_t  magic[4];
    uint16_t default_port;
    uint8_t  pubkey_addr_prefix;
    uint8_t  script_addr_prefix;
    uint8_t  wif_prefix;
    uint32_t bip44_type;
    const char **dns_seeds;
    int      num_seeds;
} smt_chain_params_t;

static void smt_get_mainnet_params(smt_chain_params_t *params) {
    params->magic[0] = SMT_MAINNET_MAGIC_0;
    params->magic[1] = SMT_MAINNET_MAGIC_1;
    params->magic[2] = SMT_MAINNET_MAGIC_2;
    params->magic[3] = SMT_MAINNET_MAGIC_3;
    params->default_port = SMT_MAINNET_PORT;
    params->pubkey_addr_prefix = SMT_MAINNET_PUBKEY_ADDR;
    params->script_addr_prefix = SMT_MAINNET_SCRIPT_ADDR;
    params->wif_prefix = SMT_MAINNET_WIF_PREFIX;
    params->bip44_type = SMT_MAINNET_BIP44_TYPE;
    params->dns_seeds = smt_dns_seeds;
    params->num_seeds = SMT_NUM_SEEDS;
}

static void smt_get_testnet_params(smt_chain_params_t *params) {
    params->magic[0] = SMT_TESTNET_MAGIC_0;
    params->magic[1] = SMT_TESTNET_MAGIC_1;
    params->magic[2] = SMT_TESTNET_MAGIC_2;
    params->magic[3] = SMT_TESTNET_MAGIC_3;
    params->default_port = SMT_TESTNET_PORT;
    params->pubkey_addr_prefix = SMT_TESTNET_PUBKEY_ADDR;
    params->script_addr_prefix = SMT_TESTNET_SCRIPT_ADDR;
    params->wif_prefix = SMT_TESTNET_WIF_PREFIX;
    params->bip44_type = SMT_TESTNET_BIP44_TYPE;
    params->dns_seeds = smt_dns_seeds;
    params->num_seeds = SMT_NUM_SEEDS;
}

#endif /* SMT_CHAINPARAMS_H */
