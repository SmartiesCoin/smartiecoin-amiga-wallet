/*
 * Smartiecoin Amiga Wallet - Network abstraction layer
 */
#include "amiga_net.h"

#ifdef AMIGA
/*
 * AmigaOS networking via bsdsocket.library
 * The Amiga's TCP/IP stack provides BSD-compatible sockets
 */
#include <proto/exec.h>
#include <proto/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>

struct Library *SocketBase = NULL;

int smt_net_init(void) {
    SocketBase = OpenLibrary("bsdsocket.library", 4);
    if (!SocketBase) return -1;
    return 0;
}

void smt_net_cleanup(void) {
    if (SocketBase) {
        CloseLibrary(SocketBase);
        SocketBase = NULL;
    }
}

int smt_net_connect(const char *host, uint16_t port) {
    struct sockaddr_in addr;
    struct hostent *he;
    int sock;
    long nonblock = 1;

    if (!SocketBase) return -1;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    smt_memzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = port << 8 | port >> 8; /* htons equivalent */

    /* Try direct IP first */
    {
        uint8_t a, b, c, d;
        uint32_t ip = 0;
        const char *p = host;
        int part = 0, val = 0;
        smt_bool is_ip = SMT_TRUE;

        while (*p) {
            if (*p >= '0' && *p <= '9') {
                val = val * 10 + (*p - '0');
            } else if (*p == '.' && part < 3) {
                ip = (ip << 8) | (val & 0xFF);
                val = 0;
                part++;
            } else {
                is_ip = SMT_FALSE;
                break;
            }
            p++;
        }
        if (is_ip && part == 3) {
            ip = (ip << 8) | (val & 0xFF);
            addr.sin_addr.s_addr = ip;
        } else {
            /* Resolve hostname */
            he = gethostbyname((char *)host);
            if (!he) {
                CloseSocket(sock);
                return -1;
            }
            smt_memcpy(&addr.sin_addr, he->h_addr, 4);
        }
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        CloseSocket(sock);
        return -1;
    }

    /* Set non-blocking */
    IoctlSocket(sock, FIONBIO, (char *)&nonblock);

    return sock;
}

void smt_net_close(int sock) {
    if (sock >= 0 && SocketBase)
        CloseSocket(sock);
}

int smt_net_send(int sock, const uint8_t *data, size_t len) {
    if (!SocketBase) return -1;
    return send(sock, (char *)data, len, 0);
}

int smt_net_recv(int sock, uint8_t *buf, size_t buf_size) {
    int n;
    if (!SocketBase) return -1;
    n = recv(sock, (char *)buf, buf_size, 0);
    if (n < 0) {
        if (Errno() == EWOULDBLOCK) return 0;
        return -1;
    }
    return n;
}

smt_bool smt_net_has_data(int sock) {
    long bytes_available = 0;
    if (!SocketBase) return SMT_FALSE;
    if (IoctlSocket(sock, FIONREAD, (char *)&bytes_available) < 0) return SMT_FALSE;
    return bytes_available > 0 ? SMT_TRUE : SMT_FALSE;
}

int smt_net_resolve(const char *hostname, char *ip_out, size_t ip_size) {
    struct hostent *he;
    uint8_t *addr;

    if (!SocketBase) return -1;

    he = gethostbyname((char *)hostname);
    if (!he) return -1;

    addr = (uint8_t *)he->h_addr;
    {
        /* Format as "a.b.c.d" */
        int i, pos = 0;
        int parts[4];
        parts[0] = addr[0]; parts[1] = addr[1];
        parts[2] = addr[2]; parts[3] = addr[3];

        for (i = 0; i < 4; i++) {
            int val = parts[i];
            if (val >= 100) { if ((size_t)pos < ip_size) ip_out[pos++] = '0' + val / 100; val %= 100; }
            if (val >= 10 || parts[i] >= 100) { if ((size_t)pos < ip_size) ip_out[pos++] = '0' + val / 10; val %= 10; }
            if ((size_t)pos < ip_size) ip_out[pos++] = '0' + val;
            if (i < 3 && (size_t)pos < ip_size) ip_out[pos++] = '.';
        }
        if ((size_t)pos < ip_size) ip_out[pos] = '\0';
    }
    return 0;
}

#else
/* ---- POSIX / testing implementation ---- */
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#define h_addr h_addr_list[0]
#endif

#include <string.h>
#include <stdio.h>

int smt_net_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0 ? 0 : -1;
#else
    return 0;
#endif
}

void smt_net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

int smt_net_connect(const char *host, uint16_t port) {
    struct sockaddr_in addr;
    struct hostent *he;
    int sock;

    sock = (int)socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    he = gethostbyname(host);
    if (!he) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return -1;
    }
    memcpy(&addr.sin_addr, he->h_addr, 4);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return -1;
    }

    /* Set non-blocking */
#ifdef _WIN32
    {
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
    }
#else
    {
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }
#endif

    return sock;
}

void smt_net_close(int sock) {
    if (sock >= 0) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
    }
}

int smt_net_send(int sock, const uint8_t *data, size_t len) {
    return (int)send(sock, (const char *)data, (int)len, 0);
}

int smt_net_recv(int sock, uint8_t *buf, size_t buf_size) {
    int n = (int)recv(sock, (char *)buf, (int)buf_size, 0);
    if (n < 0) {
#ifdef _WIN32
        if (WSAGetLastError() == WSAEWOULDBLOCK) return 0;
#else
        if (errno == EWOULDBLOCK || errno == EAGAIN) return 0;
#endif
        return -1;
    }
    return n;
}

smt_bool smt_net_has_data(int sock) {
#ifdef _WIN32
    u_long bytes = 0;
    ioctlsocket(sock, FIONBIO, &bytes);
    return bytes > 0 ? SMT_TRUE : SMT_FALSE;
#else
    int bytes = 0;
    if (ioctl(sock, FIONREAD, &bytes) < 0) return SMT_FALSE;
    return bytes > 0 ? SMT_TRUE : SMT_FALSE;
#endif
}

int smt_net_resolve(const char *hostname, char *ip_out, size_t ip_size) {
    struct hostent *he = gethostbyname(hostname);
    if (!he) return -1;
    inet_ntop(AF_INET, he->h_addr, ip_out, (int)ip_size);
    return 0;
}

#endif /* AMIGA */
