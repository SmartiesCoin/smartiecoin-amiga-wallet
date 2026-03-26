/*
 * Smartiecoin Amiga Wallet - GUI using Amiga Intuition
 * Creates a native Amiga Workbench window with wallet controls
 */
#ifndef SMT_GUI_H
#define SMT_GUI_H

#include "../types.h"

/* GUI states */
#define SMT_GUI_STATE_STARTUP    0
#define SMT_GUI_STATE_PASSWORD   1
#define SMT_GUI_STATE_SYNCING    2
#define SMT_GUI_STATE_READY      3
#define SMT_GUI_STATE_SENDING    4
#define SMT_GUI_STATE_QUIT       5

/* GUI events */
#define SMT_GUI_EVENT_NONE       0
#define SMT_GUI_EVENT_QUIT       1
#define SMT_GUI_EVENT_SEND       2
#define SMT_GUI_EVENT_RECEIVE    3
#define SMT_GUI_EVENT_IMPORT     4
#define SMT_GUI_EVENT_EXPORT     5
#define SMT_GUI_EVENT_REFRESH    6
#define SMT_GUI_EVENT_PASSWORD   7

/* Send dialog result */
typedef struct {
    char     address[64];
    char     amount[32];
    smt_bool confirmed;
} smt_send_dialog_t;

/* Password dialog result */
typedef struct {
    char     password[64];
    smt_bool confirmed;
} smt_password_dialog_t;

/* Initialize the GUI subsystem */
int smt_gui_init(void);

/* Open the main wallet window */
int smt_gui_open_window(void);

/* Close the main window */
void smt_gui_close_window(void);

/* Shutdown GUI */
void smt_gui_cleanup(void);

/* Update display with current wallet state */
void smt_gui_update_balance(const char *balance_str);
void smt_gui_update_address(const char *address);
void smt_gui_update_sync_status(int32_t current_height, int32_t target_height);
void smt_gui_update_peer_count(int num_peers);
void smt_gui_update_status(const char *message);

/* Add a transaction to the history list */
void smt_gui_add_tx_history(const char *date, const char *type,
                            const char *amount, const char *txid);

/* Process GUI events (non-blocking). Returns event type */
int smt_gui_poll_event(void);

/* Show dialogs */
int smt_gui_show_send_dialog(smt_send_dialog_t *result);
int smt_gui_show_receive_dialog(const char *address);
int smt_gui_show_password_dialog(smt_password_dialog_t *result, const char *title);
void smt_gui_show_message(const char *title, const char *message);
smt_bool smt_gui_show_confirm(const char *title, const char *message);

#endif /* SMT_GUI_H */
