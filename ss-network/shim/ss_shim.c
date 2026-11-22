/*
 * SS-NETWORK extension (see ss-network/README.md).
 *
 * Socket redirects for moonlight-common-c (Windows and macOS).
 *
 * UDP (video, audio, ENet control, microphone, haptics...) is handled directly
 * on common-c's own sockets: each datagram to a routed host is encrypted to the
 * SS node, and replies are decrypted in the receiving thread, so packets go
 * network -> SS decrypt -> Moonlight receiver with no relay thread or loopback hop.
 * TCP to a routed host (RTSP etc.) is sent through the Rust loopback relay.
 *
 * This file is compiled inside moonlight-common-c, so ss_shim.h was already
 * force-included; drop its redirects here to reach the real socket functions.
 */
#include "ss_shim.h"
#undef connect
#undef sendto
#undef recvfrom
#undef closesocket
#undef WSASendMsg
#undef WSAIoctl
#undef sendmsg
#undef recvmsg
#undef close

#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
typedef SOCKET ss_socket;
typedef SRWLOCK ss_lock;
#define SS_LOCK_INIT SRWLOCK_INIT
#define ss_lock_take(l) AcquireSRWLockExclusive(l)
#define ss_lock_give(l) ReleaseSRWLockExclusive(l)
#else
#include <pthread.h>
typedef int ss_socket;
typedef pthread_mutex_t ss_lock;
#define SS_LOCK_INIT PTHREAD_MUTEX_INITIALIZER
#define ss_lock_take(l) pthread_mutex_lock(l)
#define ss_lock_give(l) pthread_mutex_unlock(l)
#endif

/* Rust side (ss-network/rust). */
extern bool vss_config(const char *json);
extern uint16_t vss_open_tcp(uint32_t ip, uint16_t port, uint16_t source);
extern const void *vss_udp_acquire(uint32_t ip, uint32_t *server_ip, uint16_t *server_port);
extern void vss_udp_release(const void *node);
extern size_t vss_udp_overhead(const void *node);
extern intptr_t vss_udp_encrypt(const void *node, uint32_t ip, uint16_t port, const void *data,
                                size_t len, void *out, size_t cap);
extern intptr_t vss_udp_decrypt(const void *node, void *buf, size_t len, uint32_t *ip,
                                uint16_t *port);

#define MAX_FLOWS 64
#define SCRATCH_SIZE 65536
#define SEND_STACK 2048

struct flow
{
    const void *node;
    uint32_t prefix; /* destination /24 this socket is bound to */
    struct sockaddr_in server;
    size_t overhead;
    ss_lock recv_lock; /* guards scratch; one receiver per socket in practice */
    unsigned char *scratch;
};

static atomic_bool enabled;
static atomic_uint_fast64_t received_bytes;
static atomic_int flow_count;
static atomic_uintptr_t flow_keys[MAX_FLOWS];
static _Atomic(struct flow *) flow_values[MAX_FLOWS];
static ss_lock table_lock = SS_LOCK_INIT;

/* ---- API for the Qt side ------------------------------------------------ */

bool ss_shim_configure(const char *json)
{
    if (json == NULL) {
        atomic_store(&enabled, false);
        return vss_config(NULL);
    }
    bool ok = vss_config(json);
    if (ok)
        atomic_store(&enabled, true);
    return ok;
}

uint64_t ss_shim_received_bytes(void)
{
    return atomic_load(&received_bytes);
}

/* ---- helpers -------------------------------------------------------------- */

static uint32_t routed_prefix(const struct sockaddr *peer, size_t len)
{
    if (!peer || len < sizeof(struct sockaddr_in) || peer->sa_family != AF_INET)
        return 0;
    uint32_t prefix = ntohl(((const struct sockaddr_in *)peer)->sin_addr.s_addr) >> 8;
    return prefix == 0x0a0000 || prefix == 0x0a0101 ? prefix : 0;
}

static struct flow *flow_of(ss_socket s)
{
    if (atomic_load_explicit(&flow_count, memory_order_acquire) == 0)
        return NULL;
    for (int i = 0; i < MAX_FLOWS; i++) {
        if (atomic_load_explicit(&flow_keys[i], memory_order_acquire) == (uintptr_t)s + 1) {
            return atomic_load_explicit(&flow_values[i], memory_order_acquire);
        }
    }
    return NULL;
}

static void free_flow(struct flow *f)
{
    vss_udp_release(f->node);
    free(f->scratch);
    free(f);
}

/* Returns the flow for a routed send, creating it on the socket's first one. */
static struct flow *flow_for_send(ss_socket s, uint32_t prefix, uint32_t ip)
{
    struct flow *f = flow_of(s);
    if (f)
        return f->prefix == prefix ? f : NULL;
    if (!atomic_load(&enabled))
        return NULL;

    ss_lock_take(&table_lock);
    f = flow_of(s);
    if (!f) {
        int slot = -1;
        for (int i = 0; i < MAX_FLOWS && slot < 0; i++) {
            if (atomic_load(&flow_keys[i]) == 0)
                slot = i;
        }
        uint32_t server_ip;
        uint16_t server_port;
        const void *node = slot >= 0 ? vss_udp_acquire(ip, &server_ip, &server_port) : NULL;
        if (node) {
            f = calloc(1, sizeof(*f));
            unsigned char *scratch = malloc(SCRATCH_SIZE);
            if (f && scratch) {
                ss_lock init = SS_LOCK_INIT;
                f->node = node;
                f->prefix = prefix;
                f->server.sin_family = AF_INET;
                f->server.sin_port = htons(server_port);
                f->server.sin_addr.s_addr = htonl(server_ip);
                f->overhead = vss_udp_overhead(node);
                f->recv_lock = init;
                f->scratch = scratch;
                atomic_store(&flow_values[slot], f);
                atomic_store_explicit(&flow_keys[slot], (uintptr_t)s + 1, memory_order_release);
                atomic_fetch_add(&flow_count, 1);
            } else {
                free(f);
                free(scratch);
                vss_udp_release(node);
                f = NULL;
            }
        }
    }
    ss_lock_give(&table_lock);
    return f && f->prefix == prefix ? f : NULL;
}

/* common-c joins every thread using a socket before closing it. */
static void forget_socket(ss_socket s)
{
    if (atomic_load(&flow_count) == 0)
        return;
    ss_lock_take(&table_lock);
    for (int i = 0; i < MAX_FLOWS; i++) {
        if (atomic_load(&flow_keys[i]) == (uintptr_t)s + 1) {
            struct flow *f = atomic_exchange(&flow_values[i], NULL);
            atomic_store(&flow_keys[i], 0);
            atomic_fetch_sub(&flow_count, 1);
            if (f)
                free_flow(f);
        }
    }
    ss_lock_give(&table_lock);
}

static void set_unreachable(void)
{
#ifdef _WIN32
    WSASetLastError(WSAEHOSTUNREACH);
#else
    errno = EHOSTUNREACH;
#endif
}

/* Encrypts plaintext for peer into out; returns the datagram length or -1. */
static intptr_t seal(struct flow *f, const struct sockaddr_in *peer, const void *plain, size_t n,
                     unsigned char *out, size_t cap)
{
    return vss_udp_encrypt(f->node, ntohl(peer->sin_addr.s_addr), ntohs(peer->sin_port), plain, n,
                           out, cap);
}

/* Decrypts scratch[0..n) from `from`; returns plaintext length or -1 to drop. */
static intptr_t unseal(struct flow *f, const struct sockaddr_in *from, size_t fromlen, size_t n,
                       struct sockaddr_in *source)
{
    if (fromlen < sizeof(*from) || from->sin_family != AF_INET ||
        from->sin_port != f->server.sin_port ||
        from->sin_addr.s_addr != f->server.sin_addr.s_addr) {
        return -1;
    }
    uint32_t ip;
    uint16_t port;
    intptr_t plain = vss_udp_decrypt(f->node, f->scratch, n, &ip, &port);
    if (plain < 0)
        return -1;
    memset(source, 0, sizeof(*source));
    source->sin_family = AF_INET;
    source->sin_port = htons(port);
    source->sin_addr.s_addr = htonl(ip);
    atomic_fetch_add_explicit(&received_bytes, (uint64_t)plain, memory_order_relaxed);
    return plain;
}

static void fill_source(const struct sockaddr_in *src, void *peer, void *lenp, bool int_len)
{
    if (!peer || !lenp)
        return;
    size_t cap = int_len ? (size_t)*(int *)lenp : (size_t)*(socklen_t *)lenp;
    memcpy(peer, src, cap < sizeof(*src) ? cap : sizeof(*src));
    if (int_len)
        *(int *)lenp = (int)sizeof(*src);
    else
        *(socklen_t *)lenp = (socklen_t)sizeof(*src);
}

/* ---- TCP: one-shot loopback relay ----------------------------------------- */

static bool is_udp(ss_socket s)
{
    int type = 0;
#ifdef _WIN32
    int size = sizeof(type);
    return getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&type, &size) == 0 && type == SOCK_DGRAM;
#else
    socklen_t size = sizeof(type);
    return getsockopt(s, SOL_SOCKET, SO_TYPE, &type, &size) == 0 && type == SOCK_DGRAM;
#endif
}

/* Binds to loopback if needed and returns the relay address for this socket. */
static bool relay_address(ss_socket s, const struct sockaddr_in *dst, struct sockaddr_in *relay)
{
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
#ifdef _WIN32
    int len = sizeof(local);
#else
    socklen_t len = sizeof(local);
#endif
    if (getsockname(s, (struct sockaddr *)&local, &len) != 0 || local.sin_port == 0) {
        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        len = sizeof(local);
        if (bind(s, (struct sockaddr *)&local, sizeof(local)) != 0 ||
            getsockname(s, (struct sockaddr *)&local, &len) != 0) {
            return false;
        }
    }
    uint16_t port =
        vss_open_tcp(ntohl(dst->sin_addr.s_addr), ntohs(dst->sin_port), ntohs(local.sin_port));
    if (!port) {
        set_unreachable();
        return false;
    }
    memset(relay, 0, sizeof(*relay));
    relay->sin_family = AF_INET;
    relay->sin_port = htons(port);
    relay->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return true;
}

/* ==== Windows ============================================================== */
#ifdef _WIN32

static LPFN_WSARECVMSG real_recvmsg;

int WSAAPI ss_connect(SOCKET s, const struct sockaddr *name, int namelen)
{
    /* UDP connect() to a routed host is only used for local-address discovery. */
    if (!atomic_load(&enabled) || !routed_prefix(name, (size_t)namelen) || is_udp(s))
        return connect(s, name, namelen);
    struct sockaddr_in relay;
    if (!relay_address(s, (const struct sockaddr_in *)name, &relay))
        return SOCKET_ERROR;
    return connect(s, (struct sockaddr *)&relay, sizeof(relay));
}

static int send_direct(SOCKET s, struct flow *f, const struct sockaddr_in *peer, const char *plain,
                       size_t n, int flags, LPWSAMSG ctl, LPDWORD sent)
{
    unsigned char stack[SEND_STACK];
    size_t cap = n + f->overhead;
    unsigned char *out = cap <= sizeof(stack) ? stack : malloc(cap);
    if (!out) {
        WSASetLastError(WSAENOBUFS);
        return SOCKET_ERROR;
    }
    intptr_t len = seal(f, peer, plain, n, out, cap);
    int rc;
    if (len < 0) {
        WSASetLastError(WSAEMSGSIZE);
        rc = SOCKET_ERROR;
    } else if (ctl) {
        /* Keep ancillary data (ENet's IP_PKTINFO source selection). */
        WSABUF buf = { (ULONG)len, (CHAR *)out };
        WSAMSG copy = *ctl;
        copy.name = (LPSOCKADDR)&f->server;
        copy.namelen = sizeof(f->server);
        copy.lpBuffers = &buf;
        copy.dwBufferCount = 1;
        DWORD bytes = 0;
        rc = WSASendMsg(s, &copy, (DWORD)flags, &bytes, NULL, NULL);
        if (rc == 0 && sent)
            *sent = (DWORD)n;
    } else {
        rc = sendto(s, (const char *)out, (int)len, flags, (const struct sockaddr *)&f->server,
                    sizeof(f->server));
        if (rc >= 0)
            rc = (int)n;
    }
    if (out != stack)
        free(out);
    return rc;
}

int WSAAPI ss_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to,
                     int tolen)
{
    uint32_t prefix = routed_prefix(to, (size_t)tolen);
    if (!prefix)
        return sendto(s, buf, len, flags, to, tolen);
    const struct sockaddr_in *dst = (const struct sockaddr_in *)to;
    struct flow *f = flow_of(s);
    if (!f) {
        if (!atomic_load(&enabled))
            return sendto(s, buf, len, flags, to, tolen);
        f = flow_for_send(s, prefix, ntohl(dst->sin_addr.s_addr));
    }
    if (!f || f->prefix != prefix) {
        set_unreachable();
        return SOCKET_ERROR;
    }
    return send_direct(s, f, dst, buf, (size_t)len, flags, NULL, NULL);
}

int WSAAPI ss_WSASendMsg(SOCKET s, LPWSAMSG msg, DWORD flags, LPDWORD sent,
                         LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion)
{
    uint32_t prefix = routed_prefix(msg->name, (size_t)msg->namelen);
    if (!prefix || overlapped || completion)
        return WSASendMsg(s, msg, flags, sent, overlapped, completion);
    const struct sockaddr_in *dst = (const struct sockaddr_in *)msg->name;
    struct flow *f = flow_of(s);
    if (!f) {
        if (!atomic_load(&enabled))
            return WSASendMsg(s, msg, flags, sent, overlapped, completion);
        f = flow_for_send(s, prefix, ntohl(dst->sin_addr.s_addr));
    }
    if (!f || f->prefix != prefix) {
        set_unreachable();
        return SOCKET_ERROR;
    }
    size_t total = 0;
    for (DWORD i = 0; i < msg->dwBufferCount; i++)
        total += msg->lpBuffers[i].len;
    char stack[SEND_STACK];
    char *plain = total <= sizeof(stack) ? stack : malloc(total);
    if (!plain) {
        WSASetLastError(WSAENOBUFS);
        return SOCKET_ERROR;
    }
    size_t off = 0;
    for (DWORD i = 0; i < msg->dwBufferCount; i++) {
        memcpy(plain + off, msg->lpBuffers[i].buf, msg->lpBuffers[i].len);
        off += msg->lpBuffers[i].len;
    }
    int rc = send_direct(s, f, dst, plain, total, (int)flags, msg, sent);
    if (plain != stack)
        free(plain);
    return rc;
}

/* Datagrams that are not valid SS replies are dropped as if they never
 * arrived: callers treat WSAEWOULDBLOCK as "nothing yet" (common-c's
 * SO_RCVTIMEO loop and ENet's non-blocking socket alike). */
int WSAAPI ss_recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen)
{
    struct flow *f = flow_of(s);
    if (!f)
        return recvfrom(s, buf, len, flags, from, fromlen);
    AcquireSRWLockExclusive(&f->recv_lock);
    struct sockaddr_in raw_from, src;
    int raw_len = sizeof(raw_from);
    int n = recvfrom(s, (char *)f->scratch, SCRATCH_SIZE, flags, (struct sockaddr *)&raw_from,
                     &raw_len);
    int rc = n;
    if (n >= 0) {
        intptr_t plain = unseal(f, &raw_from, (size_t)raw_len, (size_t)n, &src);
        if (plain < 0) {
            WSASetLastError(WSAEWOULDBLOCK);
            rc = SOCKET_ERROR;
        } else {
            int copy = plain < len ? (int)plain : len;
            memcpy(buf, f->scratch, (size_t)copy);
            fill_source(&src, from, fromlen, true);
            if (plain > len) {
                WSASetLastError(WSAEMSGSIZE);
                rc = SOCKET_ERROR;
            } else {
                rc = copy;
            }
        }
    }
    ReleaseSRWLockExclusive(&f->recv_lock);
    return rc;
}

static INT PASCAL ss_WSARecvMsg(SOCKET s, LPWSAMSG msg, LPDWORD received,
                                LPWSAOVERLAPPED overlapped,
                                LPWSAOVERLAPPED_COMPLETION_ROUTINE completion)
{
    struct flow *f = flow_of(s);
    if (!f || overlapped || completion)
        return real_recvmsg(s, msg, received, overlapped, completion);
    AcquireSRWLockExclusive(&f->recv_lock);
    struct sockaddr_in raw_from, src;
    WSABUF scratch = { SCRATCH_SIZE, (CHAR *)f->scratch };
    WSAMSG raw = *msg;
    raw.name = (LPSOCKADDR)&raw_from;
    raw.namelen = sizeof(raw_from);
    raw.lpBuffers = &scratch;
    raw.dwBufferCount = 1;
    DWORD n = 0;
    int rc = real_recvmsg(s, &raw, &n, NULL, NULL);
    if (rc == 0) {
        intptr_t plain = unseal(f, &raw_from, (size_t)raw.namelen, n, &src);
        if (plain < 0) {
            WSASetLastError(WSAEWOULDBLOCK);
            rc = SOCKET_ERROR;
        } else {
            size_t off = 0;
            for (DWORD i = 0; i < msg->dwBufferCount && off < (size_t)plain; i++) {
                size_t chunk = msg->lpBuffers[i].len;
                if (chunk > (size_t)plain - off)
                    chunk = (size_t)plain - off;
                memcpy(msg->lpBuffers[i].buf, f->scratch + off, chunk);
                off += chunk;
            }
            msg->Control.len = raw.Control.len;
            msg->dwFlags = raw.dwFlags & ~MSG_TRUNC;
            if (off < (size_t)plain)
                msg->dwFlags |= MSG_TRUNC;
            if (msg->name) {
                int namelen = msg->namelen;
                fill_source(&src, msg->name, &namelen, true);
                msg->namelen = namelen;
            }
            if (received)
                *received = (DWORD)off;
        }
    }
    ReleaseSRWLockExclusive(&f->recv_lock);
    return rc;
}

/* ENet obtains WSARecvMsg through WSAIoctl; hand it the decrypting wrapper. */
int WSAAPI ss_WSAIoctl(SOCKET s, DWORD code, LPVOID in, DWORD inlen, LPVOID out, DWORD outlen,
                       LPDWORD returned, LPWSAOVERLAPPED overlapped,
                       LPWSAOVERLAPPED_COMPLETION_ROUTINE completion)
{
    int rc = WSAIoctl(s, code, in, inlen, out, outlen, returned, overlapped, completion);
    static const GUID recvmsg_guid = WSAID_WSARECVMSG;
    if (rc == 0 && code == SIO_GET_EXTENSION_FUNCTION_POINTER && in && inlen == sizeof(GUID) &&
        out && outlen >= sizeof(LPFN_WSARECVMSG) && memcmp(in, &recvmsg_guid, sizeof(GUID)) == 0) {
        real_recvmsg = *(LPFN_WSARECVMSG *)out;
        *(LPFN_WSARECVMSG *)out = ss_WSARecvMsg;
    }
    return rc;
}

int WSAAPI ss_closesocket(SOCKET s)
{
    forget_socket(s);
    return closesocket(s);
}

/* ==== macOS (POSIX) ======================================================== */
#else

int ss_connect(int fd, const struct sockaddr *peer, socklen_t len)
{
    /* UDP connect() to a routed host is only used for local-address discovery. */
    if (!atomic_load(&enabled) || !routed_prefix(peer, len) || is_udp(fd))
        return connect(fd, peer, len);
    struct sockaddr_in relay;
    if (!relay_address(fd, (const struct sockaddr_in *)peer, &relay))
        return -1;
    return connect(fd, (struct sockaddr *)&relay, sizeof(relay));
}

static ssize_t send_direct(int fd, struct flow *f, const struct sockaddr_in *peer,
                           const void *plain, size_t n, int flags, const struct msghdr *ctl)
{
    unsigned char stack[SEND_STACK];
    size_t cap = n + f->overhead;
    unsigned char *out = cap <= sizeof(stack) ? stack : malloc(cap);
    if (!out) {
        errno = ENOMEM;
        return -1;
    }
    intptr_t len = seal(f, peer, plain, n, out, cap);
    ssize_t rc;
    if (len < 0) {
        errno = EMSGSIZE;
        rc = -1;
    } else if (ctl) {
        /* Keep ancillary data (ENet's IP_PKTINFO source selection). */
        struct iovec iov = { out, (size_t)len };
        struct msghdr copy = *ctl;
        copy.msg_name = (void *)&f->server;
        copy.msg_namelen = sizeof(f->server);
        copy.msg_iov = &iov;
        copy.msg_iovlen = 1;
        rc = sendmsg(fd, &copy, flags);
    } else {
        rc = sendto(fd, out, (size_t)len, flags, (const struct sockaddr *)&f->server,
                    sizeof(f->server));
    }
    if (out != stack)
        free(out);
    return rc < 0 ? rc : (ssize_t)n;
}

ssize_t ss_sendto(int fd, const void *data, size_t n, int flags, const struct sockaddr *peer,
                  socklen_t len)
{
    uint32_t prefix = routed_prefix(peer, len);
    if (!prefix)
        return sendto(fd, data, n, flags, peer, len);
    const struct sockaddr_in *dst = (const struct sockaddr_in *)peer;
    struct flow *f = flow_of(fd);
    if (!f) {
        if (!atomic_load(&enabled))
            return sendto(fd, data, n, flags, peer, len);
        f = flow_for_send(fd, prefix, ntohl(dst->sin_addr.s_addr));
    }
    if (!f || f->prefix != prefix) {
        set_unreachable();
        return -1;
    }
    return send_direct(fd, f, dst, data, n, flags, NULL);
}

ssize_t ss_sendmsg(int fd, const struct msghdr *msg, int flags)
{
    uint32_t prefix = routed_prefix(msg->msg_name, msg->msg_namelen);
    if (!prefix)
        return sendmsg(fd, msg, flags);
    const struct sockaddr_in *dst = msg->msg_name;
    struct flow *f = flow_of(fd);
    if (!f) {
        if (!atomic_load(&enabled))
            return sendmsg(fd, msg, flags);
        f = flow_for_send(fd, prefix, ntohl(dst->sin_addr.s_addr));
    }
    if (!f || f->prefix != prefix) {
        set_unreachable();
        return -1;
    }
    size_t total = 0;
    for (size_t i = 0; i < (size_t)msg->msg_iovlen; i++)
        total += msg->msg_iov[i].iov_len;
    unsigned char stack[SEND_STACK];
    unsigned char *plain = total <= sizeof(stack) ? stack : malloc(total);
    if (!plain) {
        errno = ENOMEM;
        return -1;
    }
    size_t off = 0;
    for (size_t i = 0; i < (size_t)msg->msg_iovlen; i++) {
        memcpy(plain + off, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
        off += msg->msg_iov[i].iov_len;
    }
    ssize_t rc = send_direct(fd, f, dst, plain, total, flags, msg);
    if (plain != stack)
        free(plain);
    return rc;
}

static bool nonblocking(int fd, int flags)
{
    if (flags & MSG_DONTWAIT)
        return true;
    int fl = fcntl(fd, F_GETFL);
    return fl >= 0 && (fl & O_NONBLOCK);
}

/* Receives and decrypts one SS datagram into f->scratch; invalid datagrams are
 * dropped as if they never arrived. Caller holds f->recv_lock. */
static ssize_t recv_direct(int fd, struct flow *f, int flags, struct sockaddr_in *source,
                           void *control, socklen_t *controllen)
{
    flags &= ~MSG_TRUNC;
    for (;;) {
        struct sockaddr_in from;
        struct iovec iov = { f->scratch, SCRATCH_SIZE };
        struct msghdr hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.msg_name = &from;
        hdr.msg_namelen = sizeof(from);
        hdr.msg_iov = &iov;
        hdr.msg_iovlen = 1;
        hdr.msg_control = control;
        hdr.msg_controllen = controllen ? *controllen : 0;
        ssize_t n = recvmsg(fd, &hdr, flags);
        if (n < 0)
            return n;
        intptr_t plain = unseal(f, &from, hdr.msg_namelen, (size_t)n, source);
        if (plain >= 0) {
            if (controllen)
                *controllen = hdr.msg_controllen;
            return plain;
        }
        if (nonblocking(fd, flags)) {
            errno = EAGAIN;
            return -1;
        }
        /* Blocking (possibly SO_RCVTIMEO) socket: wait for the next datagram. */
    }
}

ssize_t ss_recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *peer, socklen_t *len)
{
    struct flow *f = flow_of(fd);
    if (!f)
        return recvfrom(fd, buf, n, flags, peer, len);
    struct sockaddr_in src;
    ss_lock_take(&f->recv_lock);
    ssize_t plain = recv_direct(fd, f, flags, &src, NULL, NULL);
    if (plain >= 0) {
        memcpy(buf, f->scratch, (size_t)plain < n ? (size_t)plain : n);
        fill_source(&src, peer, len, false);
        if (!(flags & MSG_TRUNC) && (size_t)plain > n)
            plain = (ssize_t)n;
    }
    ss_lock_give(&f->recv_lock);
    return plain;
}

ssize_t ss_recvmsg(int fd, struct msghdr *msg, int flags)
{
    struct flow *f = flow_of(fd);
    if (!f)
        return recvmsg(fd, msg, flags);
    struct sockaddr_in src;
    socklen_t controllen = msg->msg_controllen;
    ss_lock_take(&f->recv_lock);
    ssize_t plain = recv_direct(fd, f, flags, &src, msg->msg_control, &controllen);
    if (plain >= 0) {
        msg->msg_controllen = controllen;
        msg->msg_flags = 0;
        size_t off = 0;
        for (size_t i = 0; i < (size_t)msg->msg_iovlen && off < (size_t)plain; i++) {
            size_t chunk = msg->msg_iov[i].iov_len;
            if (chunk > (size_t)plain - off)
                chunk = (size_t)plain - off;
            memcpy(msg->msg_iov[i].iov_base, f->scratch + off, chunk);
            off += chunk;
        }
        if (off < (size_t)plain) {
            msg->msg_flags |= MSG_TRUNC;
            if (!(flags & MSG_TRUNC))
                plain = (ssize_t)off;
        }
        if (msg->msg_name)
            fill_source(&src, msg->msg_name, &msg->msg_namelen, false);
    }
    ss_lock_give(&f->recv_lock);
    return plain;
}

int ss_close(int fd)
{
    forget_socket(fd);
    return close(fd);
}

#endif
