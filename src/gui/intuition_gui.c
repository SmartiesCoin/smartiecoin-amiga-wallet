/*
 * Smartiecoin Amiga Wallet - GUI using Amiga Intuition
 *
 * On AmigaOS: native Intuition window with gadgets
 * On other platforms: simple console UI for testing
 */
#include "intuition_gui.h"

#ifdef AMIGA
#include <proto/intuition.h>
#include <proto/graphics.h>
#include <proto/gadtools.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <intuition/intuition.h>
#include <intuition/gadgetclass.h>
#include <libraries/gadtools.h>
#include <graphics/gfxbase.h>

struct Library *GadToolsBase = NULL;
static struct Screen *screen = NULL;
static struct Window *mainWindow = NULL;
static void *visualInfo = NULL;
static struct Gadget *gadgetList = NULL;
static struct TextFont *font = NULL;

/* Gadget IDs */
#define GAD_BALANCE    1
#define GAD_ADDRESS    2
#define GAD_SEND       3
#define GAD_RECEIVE    4
#define GAD_SYNC       5
#define GAD_STATUS     6
#define GAD_TX_LIST    7
#define GAD_IMPORT     8
#define GAD_EXPORT     9

/* Current display state */
static char g_balance[64] = "0.00000000 SMT";
static char g_address[64] = "";
static char g_status[128] = "Starting...";
static char g_sync[64] = "Not synced";
static char g_peers[16] = "0";

int smt_gui_init(void) {
    GadToolsBase = OpenLibrary("gadtools.library", 39);
    if (!GadToolsBase) return -1;

    screen = LockPubScreen(NULL);
    if (!screen) {
        CloseLibrary(GadToolsBase);
        return -1;
    }

    visualInfo = GetVisualInfo(screen, TAG_END);
    if (!visualInfo) {
        UnlockPubScreen(NULL, screen);
        CloseLibrary(GadToolsBase);
        return -1;
    }

    return 0;
}

int smt_gui_open_window(void) {
    struct NewGadget ng;
    struct Gadget *gad;
    int top = screen->WBorTop + screen->Font->ta_YSize + 1;
    int left = screen->WBorLeft + 8;

    gad = CreateContext(&gadgetList);
    if (!gad) return -1;

    /* Title text - Balance */
    smt_memzero(&ng, sizeof(ng));
    ng.ng_LeftEdge = left;
    ng.ng_TopEdge = top + 8;
    ng.ng_Width = 360;
    ng.ng_Height = 16;
    ng.ng_GadgetText = "Balance:";
    ng.ng_TextAttr = screen->Font;
    ng.ng_GadgetID = GAD_BALANCE;
    ng.ng_VisualInfo = visualInfo;
    ng.ng_Flags = PLACETEXT_LEFT;
    gad = CreateGadget(TEXT_KIND, gad, &ng,
                       GTTX_Text, (ULONG)g_balance,
                       GTTX_Border, TRUE,
                       TAG_END);

    /* Address display */
    ng.ng_TopEdge += 24;
    ng.ng_GadgetText = "Address:";
    ng.ng_GadgetID = GAD_ADDRESS;
    gad = CreateGadget(TEXT_KIND, gad, &ng,
                       GTTX_Text, (ULONG)g_address,
                       GTTX_Border, TRUE,
                       GTTX_CopyText, TRUE,
                       TAG_END);

    /* Sync status */
    ng.ng_TopEdge += 24;
    ng.ng_GadgetText = "Sync:";
    ng.ng_GadgetID = GAD_SYNC;
    ng.ng_Width = 200;
    gad = CreateGadget(TEXT_KIND, gad, &ng,
                       GTTX_Text, (ULONG)g_sync,
                       GTTX_Border, TRUE,
                       TAG_END);

    /* Send button */
    ng.ng_TopEdge += 32;
    ng.ng_Width = 100;
    ng.ng_Height = 20;
    ng.ng_GadgetText = "Send";
    ng.ng_GadgetID = GAD_SEND;
    ng.ng_Flags = PLACETEXT_IN;
    gad = CreateGadget(BUTTON_KIND, gad, &ng, TAG_END);

    /* Receive button */
    ng.ng_LeftEdge += 110;
    ng.ng_GadgetText = "Receive";
    ng.ng_GadgetID = GAD_RECEIVE;
    gad = CreateGadget(BUTTON_KIND, gad, &ng, TAG_END);

    /* Import key button */
    ng.ng_LeftEdge += 110;
    ng.ng_GadgetText = "Import";
    ng.ng_GadgetID = GAD_IMPORT;
    gad = CreateGadget(BUTTON_KIND, gad, &ng, TAG_END);

    /* Status bar */
    ng.ng_LeftEdge = left;
    ng.ng_TopEdge += 28;
    ng.ng_Width = 360;
    ng.ng_Height = 14;
    ng.ng_GadgetText = NULL;
    ng.ng_GadgetID = GAD_STATUS;
    ng.ng_Flags = 0;
    gad = CreateGadget(TEXT_KIND, gad, &ng,
                       GTTX_Text, (ULONG)g_status,
                       GTTX_Border, TRUE,
                       TAG_END);

    if (!gad) {
        FreeGadgets(gadgetList);
        gadgetList = NULL;
        return -1;
    }

    /* Open the window */
    mainWindow = OpenWindowTags(NULL,
        WA_Left, 50,
        WA_Top, 50,
        WA_Width, 420,
        WA_Height, 250,
        WA_Title, (ULONG)"Smartiecoin Wallet v0.1.0",
        WA_Gadgets, (ULONG)gadgetList,
        WA_IDCMP, IDCMP_CLOSEWINDOW | IDCMP_GADGETUP | IDCMP_REFRESHWINDOW,
        WA_Flags, WFLG_DRAGBAR | WFLG_DEPTHGADGET | WFLG_CLOSEGADGET |
                  WFLG_ACTIVATE | WFLG_SMART_REFRESH,
        WA_PubScreen, (ULONG)screen,
        TAG_END);

    if (!mainWindow) {
        FreeGadgets(gadgetList);
        gadgetList = NULL;
        return -1;
    }

    GT_RefreshWindow(mainWindow, NULL);
    UnlockPubScreen(NULL, screen);
    screen = NULL;

    return 0;
}

void smt_gui_close_window(void) {
    if (mainWindow) {
        CloseWindow(mainWindow);
        mainWindow = NULL;
    }
    if (gadgetList) {
        FreeGadgets(gadgetList);
        gadgetList = NULL;
    }
}

void smt_gui_cleanup(void) {
    smt_gui_close_window();
    if (visualInfo) {
        FreeVisualInfo(visualInfo);
        visualInfo = NULL;
    }
    if (screen) {
        UnlockPubScreen(NULL, screen);
        screen = NULL;
    }
    if (GadToolsBase) {
        CloseLibrary(GadToolsBase);
        GadToolsBase = NULL;
    }
}

void smt_gui_update_balance(const char *balance_str) {
    int i;
    for (i = 0; balance_str[i] && i < 63; i++)
        g_balance[i] = balance_str[i];
    g_balance[i] = '\0';

    if (mainWindow) {
        /* Refresh the balance gadget */
        GT_RefreshWindow(mainWindow, NULL);
    }
}

void smt_gui_update_address(const char *address) {
    int i;
    for (i = 0; address[i] && i < 63; i++)
        g_address[i] = address[i];
    g_address[i] = '\0';

    if (mainWindow)
        GT_RefreshWindow(mainWindow, NULL);
}

void smt_gui_update_sync_status(int32_t current_height, int32_t target_height) {
    /* Format: "12345 / 41094" */
    int pos = 0;
    char tmp[16];
    int nd, i;
    int32_t val;

    /* Current */
    val = current_height;
    nd = 0;
    if (val <= 0) { tmp[nd++] = '0'; val = 0; }
    else { while (val > 0) { tmp[nd++] = '0' + (val % 10); val /= 10; } }
    for (i = nd - 1; i >= 0; i--) g_sync[pos++] = tmp[i];

    g_sync[pos++] = ' '; g_sync[pos++] = '/'; g_sync[pos++] = ' ';

    /* Target */
    val = target_height;
    nd = 0;
    if (val <= 0) { tmp[nd++] = '0'; val = 0; }
    else { while (val > 0) { tmp[nd++] = '0' + (val % 10); val /= 10; } }
    for (i = nd - 1; i >= 0; i--) g_sync[pos++] = tmp[i];

    g_sync[pos] = '\0';

    if (mainWindow)
        GT_RefreshWindow(mainWindow, NULL);
}

void smt_gui_update_peer_count(int num_peers) {
    g_peers[0] = '0' + (num_peers % 10);
    g_peers[1] = '\0';
}

void smt_gui_update_status(const char *message) {
    int i;
    for (i = 0; message[i] && i < 127; i++)
        g_status[i] = message[i];
    g_status[i] = '\0';

    if (mainWindow)
        GT_RefreshWindow(mainWindow, NULL);
}

void smt_gui_add_tx_history(const char *date, const char *type,
                            const char *amount, const char *txid) {
    /* TODO: Add to scrollable list gadget */
    (void)date; (void)type; (void)amount; (void)txid;
}

int smt_gui_poll_event(void) {
    struct IntuiMessage *msg;

    if (!mainWindow) return SMT_GUI_EVENT_QUIT;

    while ((msg = GT_GetIMsg(mainWindow->UserPort)) != NULL) {
        ULONG class = msg->Class;
        UWORD code = msg->Code;
        struct Gadget *gad = (struct Gadget *)msg->IAddress;

        GT_ReplyIMsg(msg);

        switch (class) {
            case IDCMP_CLOSEWINDOW:
                return SMT_GUI_EVENT_QUIT;

            case IDCMP_GADGETUP:
                switch (gad->GadgetID) {
                    case GAD_SEND:    return SMT_GUI_EVENT_SEND;
                    case GAD_RECEIVE: return SMT_GUI_EVENT_RECEIVE;
                    case GAD_IMPORT:  return SMT_GUI_EVENT_IMPORT;
                }
                break;

            case IDCMP_REFRESHWINDOW:
                GT_BeginRefresh(mainWindow);
                GT_EndRefresh(mainWindow, TRUE);
                break;
        }
    }

    return SMT_GUI_EVENT_NONE;
}

int smt_gui_show_send_dialog(smt_send_dialog_t *result) {
    /* Simple EasyRequest for address and amount */
    struct EasyStruct es;
    LONG response;

    smt_memzero(result, sizeof(smt_send_dialog_t));

    es.es_StructSize = sizeof(es);
    es.es_Flags = 0;
    es.es_Title = "Send Smartiecoin";
    es.es_TextFormat = "Enter destination address and amount\nin the CLI window";
    es.es_GadgetFormat = "OK|Cancel";

    response = EasyRequest(mainWindow, &es, NULL);
    result->confirmed = (response == 1) ? SMT_TRUE : SMT_FALSE;

    /* For a real implementation, we'd use a string requester */
    /* For now, the user enters address/amount in CLI */
    return result->confirmed ? 0 : -1;
}

int smt_gui_show_receive_dialog(const char *address) {
    struct EasyStruct es;

    es.es_StructSize = sizeof(es);
    es.es_Flags = 0;
    es.es_Title = "Receive Smartiecoin";
    es.es_TextFormat = "Your receive address:\n\n%s\n\nShare this address to receive SMT.";
    es.es_GadgetFormat = "OK";

    EasyRequest(mainWindow, &es, NULL, (ULONG)address);
    return 0;
}

int smt_gui_show_password_dialog(smt_password_dialog_t *result, const char *title) {
    struct EasyStruct es;

    smt_memzero(result, sizeof(smt_password_dialog_t));

    es.es_StructSize = sizeof(es);
    es.es_Flags = 0;
    es.es_Title = (UBYTE *)title;
    es.es_TextFormat = "Enter your wallet passphrase\nin the CLI window:";
    es.es_GadgetFormat = "OK|Cancel";

    result->confirmed = EasyRequest(mainWindow, &es, NULL) ? SMT_TRUE : SMT_FALSE;
    return result->confirmed ? 0 : -1;
}

void smt_gui_show_message(const char *title, const char *message) {
    struct EasyStruct es;

    es.es_StructSize = sizeof(es);
    es.es_Flags = 0;
    es.es_Title = (UBYTE *)title;
    es.es_TextFormat = (UBYTE *)message;
    es.es_GadgetFormat = "OK";

    EasyRequest(mainWindow, &es, NULL);
}

smt_bool smt_gui_show_confirm(const char *title, const char *message) {
    struct EasyStruct es;

    es.es_StructSize = sizeof(es);
    es.es_Flags = 0;
    es.es_Title = (UBYTE *)title;
    es.es_TextFormat = (UBYTE *)message;
    es.es_GadgetFormat = "Yes|No";

    return EasyRequest(mainWindow, &es, NULL) ? SMT_TRUE : SMT_FALSE;
}

#else
/* ---- Console-based testing UI ---- */
#include <stdio.h>
#include <string.h>

static char g_balance[64] = "0.00000000 SMT";
static char g_address[64] = "";
static char g_status[128] = "Starting...";

int smt_gui_init(void) { return 0; }

int smt_gui_open_window(void) {
    printf("=== Smartiecoin Wallet v0.1.0 ===\n");
    printf("Console mode (testing)\n\n");
    return 0;
}

void smt_gui_close_window(void) {
    printf("Window closed.\n");
}

void smt_gui_cleanup(void) {}

void smt_gui_update_balance(const char *balance_str) {
    strncpy(g_balance, balance_str, sizeof(g_balance) - 1);
    printf("[Balance] %s\n", g_balance);
}

void smt_gui_update_address(const char *address) {
    strncpy(g_address, address, sizeof(g_address) - 1);
    printf("[Address] %s\n", g_address);
}

void smt_gui_update_sync_status(int32_t current, int32_t target) {
    printf("[Sync] %d / %d\n", (int)current, (int)target);
}

void smt_gui_update_peer_count(int n) {
    printf("[Peers] %d\n", n);
}

void smt_gui_update_status(const char *message) {
    strncpy(g_status, message, sizeof(g_status) - 1);
    printf("[Status] %s\n", g_status);
}

void smt_gui_add_tx_history(const char *date, const char *type,
                            const char *amount, const char *txid) {
    printf("[TX] %s %s %s %s\n", date, type, amount, txid);
}

int smt_gui_poll_event(void) {
    return SMT_GUI_EVENT_NONE;
}

int smt_gui_show_send_dialog(smt_send_dialog_t *result) {
    memset(result, 0, sizeof(*result));
    printf("Send to address: ");
    if (fgets(result->address, sizeof(result->address), stdin)) {
        result->address[strcspn(result->address, "\n")] = 0;
    }
    printf("Amount (SMT): ");
    if (fgets(result->amount, sizeof(result->amount), stdin)) {
        result->amount[strcspn(result->amount, "\n")] = 0;
    }
    result->confirmed = SMT_TRUE;
    return 0;
}

int smt_gui_show_receive_dialog(const char *address) {
    printf("\nYour receive address:\n  %s\n\n", address);
    return 0;
}

int smt_gui_show_password_dialog(smt_password_dialog_t *result, const char *title) {
    memset(result, 0, sizeof(*result));
    printf("%s: ", title);
    if (fgets(result->password, sizeof(result->password), stdin)) {
        result->password[strcspn(result->password, "\n")] = 0;
    }
    result->confirmed = SMT_TRUE;
    return 0;
}

void smt_gui_show_message(const char *title, const char *message) {
    printf("[%s] %s\n", title, message);
}

smt_bool smt_gui_show_confirm(const char *title, const char *message) {
    char buf[8];
    printf("[%s] %s (y/n): ", title, message);
    if (fgets(buf, sizeof(buf), stdin)) {
        return (buf[0] == 'y' || buf[0] == 'Y') ? SMT_TRUE : SMT_FALSE;
    }
    return SMT_FALSE;
}

#endif /* AMIGA */
