/*
 * Smartiecoin Amiga Wallet - Network abstraction layer
 * Uses bsdsocket.library on AmigaOS, standard sockets elsewhere
 */
#ifndef SMT_AMIGA_NET_H
#define SMT_AMIGA_NET_H

#include "../types.h"

/* Initialize networking. Must be called once at startup */
int smt_net_init(void);

/* Cleanup networking. Call at shutdown */
void smt_net_cleanup(void);

/* Connect to a TCP host. Returns socket fd or -1 on error */
int smt_net_connect(const char *host, uint16_t port);

/* Close a socket */
void smt_net_close(int sock);

/* Send data. Returns bytes sent or -1 on error */
int smt_net_send(int sock, const uint8_t *data, size_t len);

/* Receive data (non-blocking). Returns bytes received, 0 if no data, -1 on error */
int smt_net_recv(int sock, uint8_t *buf, size_t buf_size);

/* Check if socket has data available (non-blocking) */
smt_bool smt_net_has_data(int sock);

/* Resolve hostname to IP address */
int smt_net_resolve(const char *hostname, char *ip_out, size_t ip_size);

#endif /* SMT_AMIGA_NET_H */
