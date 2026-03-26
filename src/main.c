/*
 * Smartiecoin Amiga Wallet - Main entry point
 *
 * SPV wallet for AmigaOS 3.x
 * Pure C, no external dependencies beyond AmigaOS system libraries
 *
 * Flow:
 * 1. Initialize platform (network, GUI)
 * 2. Load or create wallet (key store)
 * 3. Connect to P2P network
 * 4. Sync block headers
 * 5. Load bloom filter with our addresses
 * 6. Listen for relevant transactions
 * 7. GUI event loop: send, receive, display balance
 */

#include "types.h"
#include "chainparams.h"
#include "wallet/keys.h"
#include "wallet/address.h"
#include "wallet/tx.h"
#include "net/p2p.h"
#include "spv/headers.h"
#include "spv/bloom.h"
#include "spv/merkle.h"
#include "gui/intuition_gui.h"
#include "platform/amiga_net.h"
#include "crypto/sha256.h"

#ifdef AMIGA
#include <proto/exec.h>
#include <proto/dos.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

/* ---- Global wallet state ---- */
static smt_chain_params_t   g_params;
static smt_keystore_t       g_keystore;
static smt_utxo_set_t       g_utxos;
static smt_header_chain_t   g_headers;
static smt_p2p_manager_t    g_p2p;
static smt_bloom_t          g_bloom;
static smt_bool             g_running = SMT_TRUE;
static int                  g_state = SMT_GUI_STATE_STARTUP;

/* File paths */
#ifdef AMIGA
static const char *WALLET_FILE  = "PROGDIR:wallet.dat";
static const char *HEADERS_FILE = "PROGDIR:headers.dat";
#else
static const char *WALLET_FILE  = "wallet.dat";
static const char *HEADERS_FILE = "headers.dat";
#endif

/* ---- Callbacks from P2P layer ---- */

static void on_headers(smt_block_header_t *headers, int count, void *ctx) {
    int added;
    (void)ctx;

    added = smt_headers_continue_sync(&g_headers, &g_p2p, headers, count);

    /* Update GUI */
    if (g_p2p.num_peers > 0) {
        smt_gui_update_sync_status(g_headers.height,
                                   g_p2p.peers[0].peer_height);
    }

    if (smt_headers_is_synced(&g_headers,
                              g_p2p.num_peers > 0 ? g_p2p.peers[0].peer_height : 0)) {
        smt_gui_update_status("Synced! Ready.");
        g_state = SMT_GUI_STATE_READY;
    }
}

static void on_merkleblock(const smt_msg_merkleblock_t *mb, void *ctx) {
    hash256_t matched[16];
    int num_matches;
    (void)ctx;

    num_matches = smt_merkle_extract_matches(mb, matched, 16);
    if (num_matches > 0) {
        smt_gui_update_status("Received matching transaction!");
        /* Request the actual transaction data */
        {
            smt_inv_t items[16];
            uint8_t msg_buf[1024];
            int msg_len;
            int i;

            for (i = 0; i < num_matches && i < 16; i++) {
                items[i].type = SMT_INV_TX;
                smt_memcpy(items[i].hash, matched[i], 32);
            }

            msg_len = smt_msg_build_getdata(msg_buf, sizeof(msg_buf),
                                            g_params.magic, items, num_matches);
            if (msg_len > 0 && g_p2p.num_peers > 0) {
                smt_p2p_send(&g_p2p.peers[0], msg_buf, (size_t)msg_len);
            }
        }
    }
}

static void on_tx(const uint8_t *tx_data, size_t tx_len, void *ctx) {
    smt_tx_t tx;
    int i;
    smt_bool relevant = SMT_FALSE;
    (void)ctx;

    if (smt_tx_deserialize(&tx, tx_data, tx_len) < 0)
        return;

    /* Check if any outputs pay to our addresses */
    for (i = 0; i < tx.num_outputs; i++) {
        /* P2PKH script: 76 A9 14 <20-byte-hash> 88 AC */
        if (tx.outputs[i].script_pubkey_len == 25 &&
            tx.outputs[i].script_pubkey[0] == 0x76 &&
            tx.outputs[i].script_pubkey[1] == 0xA9 &&
            tx.outputs[i].script_pubkey[2] == 0x14 &&
            tx.outputs[i].script_pubkey[23] == 0x88 &&
            tx.outputs[i].script_pubkey[24] == 0xAC) {

            int key_idx = smt_keystore_find_by_hash160(
                &g_keystore, tx.outputs[i].script_pubkey + 3);

            if (key_idx >= 0) {
                /* This output pays to us! Add as UTXO */
                if (g_utxos.num_utxos < SMT_MAX_UTXOS) {
                    smt_utxo_t *utxo = &g_utxos.utxos[g_utxos.num_utxos];
                    smt_tx_txid(&tx, utxo->outpoint.txid);
                    utxo->outpoint.vout = (uint32_t)i;
                    utxo->value = tx.outputs[i].value;
                    smt_memcpy(utxo->script_pubkey, tx.outputs[i].script_pubkey,
                               tx.outputs[i].script_pubkey_len);
                    utxo->script_pubkey_len = tx.outputs[i].script_pubkey_len;
                    utxo->key_index = key_idx;
                    utxo->confirmations = 0;
                    g_utxos.num_utxos++;
                    relevant = SMT_TRUE;
                }
            }
        }
    }

    /* Check if any inputs spend our UTXOs */
    for (i = 0; i < tx.num_inputs; i++) {
        int j;
        for (j = 0; j < g_utxos.num_utxos; j++) {
            if (smt_memcmp(tx.inputs[i].prevout.txid,
                          g_utxos.utxos[j].outpoint.txid, 32) == 0 &&
                tx.inputs[i].prevout.vout == g_utxos.utxos[j].outpoint.vout) {
                /* Remove spent UTXO */
                int k;
                for (k = j; k < g_utxos.num_utxos - 1; k++)
                    g_utxos.utxos[k] = g_utxos.utxos[k + 1];
                g_utxos.num_utxos--;
                relevant = SMT_TRUE;
                break;
            }
        }
    }

    if (relevant) {
        /* Update balance display */
        char bal[64];
        smt_format_amount(smt_utxo_get_balance(&g_utxos), bal, sizeof(bal));
        smt_gui_update_balance(bal);
    }
}

static void on_inv(const smt_inv_t *items, int count, void *ctx) {
    /*
     * When we receive an inv for a block, request it as a merkleblock
     * (filtered by our bloom filter)
     */
    smt_inv_t requests[64];
    int num_requests = 0;
    int i;
    (void)ctx;

    for (i = 0; i < count && num_requests < 64; i++) {
        if (items[i].type == SMT_INV_BLOCK) {
            requests[num_requests].type = SMT_INV_FILTERED_BLOCK;
            smt_memcpy(requests[num_requests].hash, items[i].hash, 32);
            num_requests++;
        }
        else if (items[i].type == SMT_INV_TX) {
            requests[num_requests].type = SMT_INV_TX;
            smt_memcpy(requests[num_requests].hash, items[i].hash, 32);
            num_requests++;
        }
    }

    if (num_requests > 0 && g_p2p.num_peers > 0) {
        uint8_t msg_buf[4096];
        int msg_len = smt_msg_build_getdata(msg_buf, sizeof(msg_buf),
                                            g_params.magic,
                                            requests, num_requests);
        if (msg_len > 0)
            smt_p2p_send(&g_p2p.peers[0], msg_buf, (size_t)msg_len);
    }
}

/* ---- Send transaction flow ---- */

static int do_send(const char *dest_address, const char *amount_str) {
    smt_tx_t tx;
    smt_amount_t amount;
    uint8_t tx_buf[8192];
    int tx_len;
    char confirm_msg[256];
    char amount_fmt[64];
    int64_t whole = 0, frac = 0;
    int frac_digits = 0;
    const char *p = amount_str;

    /* Parse amount string "1.5" -> 150000000 satoshis */
    while (*p >= '0' && *p <= '9') {
        whole = whole * 10 + (*p - '0');
        p++;
    }
    if (*p == '.') {
        p++;
        int64_t multiplier = 10000000; /* 7 decimal places after first */
        while (*p >= '0' && *p <= '9' && frac_digits < 8) {
            frac += (*p - '0') * multiplier;
            multiplier /= 10;
            frac_digits++;
            p++;
        }
    }
    amount = whole * SMT_COIN + frac;

    if (amount <= 0) {
        smt_gui_show_message("Error", "Invalid amount");
        return -1;
    }

    /* Validate destination address */
    if (!smt_address_validate(dest_address, g_params.pubkey_addr_prefix)) {
        smt_gui_show_message("Error", "Invalid address");
        return -1;
    }

    /* Format for confirmation */
    smt_format_amount(amount, amount_fmt, sizeof(amount_fmt));

    /* Build confirmation message */
    {
        int pos = 0;
        const char *s;
        s = "Send ";
        while (*s) confirm_msg[pos++] = *s++;
        s = amount_fmt;
        while (*s) confirm_msg[pos++] = *s++;
        s = "\nto: ";
        while (*s) confirm_msg[pos++] = *s++;
        s = dest_address;
        while (*s) confirm_msg[pos++] = *s++;
        s = "\n\nConfirm?";
        while (*s) confirm_msg[pos++] = *s++;
        confirm_msg[pos] = '\0';
    }

    if (!smt_gui_show_confirm("Confirm Send", confirm_msg))
        return -1;

    /* Build, sign, and serialize transaction */
    if (smt_tx_build_and_sign(&tx, &g_utxos, dest_address, amount,
                              1, /* 1 sat/byte fee */
                              &g_keystore,
                              g_params.pubkey_addr_prefix) < 0) {
        smt_gui_show_message("Error", "Failed to build transaction.\nInsufficient funds?");
        return -1;
    }

    tx_len = smt_tx_serialize(&tx, tx_buf, sizeof(tx_buf));
    if (tx_len < 0) {
        smt_gui_show_message("Error", "Failed to serialize transaction");
        return -1;
    }

    /* Broadcast via P2P */
    if (g_p2p.num_peers > 0) {
        uint8_t msg_buf[16384];
        int msg_len = smt_msg_build_tx(msg_buf, sizeof(msg_buf),
                                       g_params.magic, tx_buf, (size_t)tx_len);
        if (msg_len > 0) {
            int i;
            for (i = 0; i < g_p2p.num_peers; i++) {
                if (g_p2p.peers[i].connected)
                    smt_p2p_send(&g_p2p.peers[i], msg_buf, (size_t)msg_len);
            }
        }
        smt_gui_show_message("Sent!", "Transaction broadcast to network");
        smt_gui_update_status("Transaction sent!");
    } else {
        smt_gui_show_message("Error", "No peers connected");
        return -1;
    }

    return 0;
}

/* ---- Load bloom filter with our addresses ---- */

static void load_bloom_filter(void) {
    uint8_t msg_buf[36200];
    int msg_len;
    int i;
    uint32_t tweak;

    if (g_keystore.num_keys == 0) return;

    /* Build bloom filter from our pubkey hashes */
    {
        uint8_t hashes[SMT_MAX_KEYS][20];
        for (i = 0; i < g_keystore.num_keys; i++) {
            smt_memcpy(hashes[i], g_keystore.keys[i].pubkey_hash, 20);
        }

        /* Use current time as tweak */
        smt_get_entropy((uint8_t *)&tweak, 4);
        smt_bloom_build_from_wallet(&g_bloom,
                                     (const uint8_t (*)[20])hashes,
                                     g_keystore.num_keys, tweak);
    }

    /* Send filterload to all peers */
    msg_len = smt_msg_build_filterload(msg_buf, sizeof(msg_buf),
                                       g_params.magic,
                                       g_bloom.filter, g_bloom.filter_size,
                                       g_bloom.num_hash_funcs,
                                       g_bloom.tweak,
                                       g_bloom.flags);
    if (msg_len > 0) {
        for (i = 0; i < g_p2p.num_peers; i++) {
            if (g_p2p.peers[i].connected && g_p2p.peers[i].verack_received)
                smt_p2p_send(&g_p2p.peers[i], msg_buf, (size_t)msg_len);
        }
    }
}

/* ---- Main ---- */

int main(int argc, char *argv[]) {
    smt_p2p_callbacks_t callbacks;
    smt_password_dialog_t pwd;
    const char *addr;
    int peer_idx;
    int i;

    (void)argc; (void)argv;

    /* Initialize chain parameters (mainnet) */
    smt_get_mainnet_params(&g_params);

    /* Initialize subsystems */
    if (smt_net_init() < 0) {
#ifdef AMIGA
        /* Can't print easily without dos, but we can try */
#else
        printf("Error: Failed to initialize networking\n");
#endif
        return 1;
    }

    if (smt_gui_init() < 0) {
        smt_net_cleanup();
        return 1;
    }

    if (smt_gui_open_window() < 0) {
        smt_gui_cleanup();
        smt_net_cleanup();
        return 1;
    }

    /* Initialize wallet components */
    smt_keystore_init(&g_keystore, g_params.pubkey_addr_prefix,
                      g_params.wif_prefix);
    smt_memzero(&g_utxos, sizeof(g_utxos));
    smt_headers_init(&g_headers);
    g_headers.filename = HEADERS_FILE;

    /* Try to load existing wallet */
    smt_gui_update_status("Enter wallet passphrase...");
    g_state = SMT_GUI_STATE_PASSWORD;

    if (smt_gui_show_password_dialog(&pwd, "Wallet Passphrase") == 0 && pwd.confirmed) {
        if (smt_keystore_load(&g_keystore, WALLET_FILE, pwd.password) == 0) {
            smt_gui_update_status("Wallet loaded!");
        } else {
            /* New wallet - generate first key */
            smt_gui_update_status("Creating new wallet...");
            smt_keystore_generate(&g_keystore, SMT_FALSE); /* receive key */
            smt_keystore_generate(&g_keystore, SMT_TRUE);  /* change key */
            smt_keystore_save(&g_keystore, WALLET_FILE, pwd.password);
            smt_gui_update_status("New wallet created!");
        }
    }
    smt_memzero(&pwd, sizeof(pwd));

    /* Display initial address */
    addr = smt_keystore_get_receive_address(&g_keystore);
    if (addr) smt_gui_update_address(addr);
    smt_gui_update_balance("0.00000000 SMT");

    /* Load saved headers */
    smt_headers_load(&g_headers, HEADERS_FILE);
    if (g_headers.height >= 0) {
        char status[64];
        int pos = 0;
        const char *s = "Loaded headers: height ";
        while (*s) status[pos++] = *s++;
        {
            char digits[12];
            int nd = 0;
            int32_t h = g_headers.height;
            if (h == 0) digits[nd++] = '0';
            else while (h > 0) { digits[nd++] = '0' + (h % 10); h /= 10; }
            while (nd > 0) status[pos++] = digits[--nd];
        }
        status[pos] = '\0';
        smt_gui_update_status(status);
    }

    /* Set up P2P callbacks */
    smt_memzero(&callbacks, sizeof(callbacks));
    callbacks.on_headers = on_headers;
    callbacks.on_merkleblock = on_merkleblock;
    callbacks.on_tx = on_tx;
    callbacks.on_inv = on_inv;
    callbacks.ctx = NULL;

    smt_p2p_init(&g_p2p, &g_params);
    smt_p2p_set_callbacks(&g_p2p, &callbacks);

    /* Connect to seed node */
    smt_gui_update_status("Connecting to network...");
    peer_idx = smt_p2p_connect(&g_p2p, smt_fixed_seeds[0], g_params.default_port);
    if (peer_idx < 0) {
        smt_gui_update_status("Failed to connect to seed node");
    } else {
        smt_gui_update_peer_count(1);
        smt_gui_update_status("Connected! Syncing headers...");
        g_state = SMT_GUI_STATE_SYNCING;
    }

    /* ---- Main event loop ---- */
    while (g_running) {
        int event;

        /* Process P2P messages */
        for (i = 0; i < g_p2p.num_peers; i++) {
            if (g_p2p.peers[i].connected) {
                smt_p2p_process(&g_p2p, i);

                /* After version handshake, start header sync and load bloom */
                if (g_p2p.peers[i].verack_received && !g_p2p.peers[i].filter_loaded) {
                    g_p2p.peers[i].filter_loaded = SMT_TRUE;
                    load_bloom_filter();
                    smt_headers_start_sync(&g_headers, &g_p2p, i);
                }
            }
        }

        /* Process GUI events */
        event = smt_gui_poll_event();
        switch (event) {
            case SMT_GUI_EVENT_QUIT:
                g_running = SMT_FALSE;
                break;

            case SMT_GUI_EVENT_SEND: {
                smt_send_dialog_t send;
                if (smt_gui_show_send_dialog(&send) == 0 && send.confirmed) {
                    do_send(send.address, send.amount);
                }
                break;
            }

            case SMT_GUI_EVENT_RECEIVE: {
                const char *recv_addr = smt_keystore_get_receive_address(&g_keystore);
                if (recv_addr)
                    smt_gui_show_receive_dialog(recv_addr);
                break;
            }

            case SMT_GUI_EVENT_IMPORT: {
                /* TODO: WIF import dialog */
                smt_gui_show_message("Import", "WIF import not yet implemented");
                break;
            }

            default:
                break;
        }

        /* Small delay to avoid busy-waiting */
#ifdef AMIGA
        Delay(1); /* 1/50th of a second */
#else
        /* On PC testing, use a small sleep */
        {
#ifdef _WIN32
            extern void Sleep(unsigned long);
            Sleep(20);
#else
            struct timespec ts = {0, 20000000}; /* 20ms */
            nanosleep(&ts, NULL);
#endif
        }
#endif
    }

    /* ---- Cleanup ---- */
    smt_gui_update_status("Shutting down...");

    /* Save headers */
    if (g_headers.height >= 0)
        smt_headers_save(&g_headers, HEADERS_FILE);

    /* Disconnect peers */
    for (i = 0; i < g_p2p.num_peers; i++)
        smt_p2p_disconnect(&g_p2p, i);

    /* Free resources */
    smt_headers_free(&g_headers);
    smt_gui_close_window();
    smt_gui_cleanup();
    smt_net_cleanup();

    /* Securely wipe key material */
    smt_memzero(&g_keystore, sizeof(g_keystore));

    return 0;
}
