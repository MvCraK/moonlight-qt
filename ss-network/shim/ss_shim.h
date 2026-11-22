/*
 * SS-NETWORK extension (see ss-network/README.md).
 *
 * Force-included into every moonlight-common-c translation unit by
 * ss-network-common-c.pri. It pulls in the platform socket headers first, so
 * their declarations keep the real names, and then redirects the socket calls
 * made by common-c/ENet to the ss_* implementations in ss_shim.c. Function-like
 * macros only rewrite call sites, never struct members with the same name.
 */
#ifndef SS_SHIM_H
#define SS_SHIM_H

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <mswsock.h>
#  include <windows.h>
#else
#  ifndef __APPLE_USE_RFC_3542
#    define __APPLE_USE_RFC_3542 1   /* matches enet/unix.c: IPv6 PKTINFO */
#  endif
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
int WSAAPI ss_connect(SOCKET s, const struct sockaddr *name, int namelen);
int WSAAPI ss_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen);
int WSAAPI ss_recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen);
int WSAAPI ss_closesocket(SOCKET s);
int WSAAPI ss_WSASendMsg(SOCKET s, LPWSAMSG msg, DWORD flags, LPDWORD sent,
                         LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion);
int WSAAPI ss_WSAIoctl(SOCKET s, DWORD code, LPVOID in, DWORD inlen, LPVOID out, DWORD outlen,
                       LPDWORD returned, LPWSAOVERLAPPED overlapped,
                       LPWSAOVERLAPPED_COMPLETION_ROUTINE completion);
#else
int ss_connect(int fd, const struct sockaddr *peer, socklen_t len);
ssize_t ss_sendto(int fd, const void *data, size_t n, int flags, const struct sockaddr *peer, socklen_t len);
ssize_t ss_recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *peer, socklen_t *len);
ssize_t ss_sendmsg(int fd, const struct msghdr *msg, int flags);
ssize_t ss_recvmsg(int fd, struct msghdr *msg, int flags);
int ss_close(int fd);
#endif

#ifdef __cplusplus
}
#endif

#ifndef SS_SHIM_IMPLEMENTATION
#  define connect(...) ss_connect(__VA_ARGS__)
#  define sendto(...) ss_sendto(__VA_ARGS__)
#  define recvfrom(...) ss_recvfrom(__VA_ARGS__)
#  ifdef _WIN32
#    define closesocket(...) ss_closesocket(__VA_ARGS__)
#    define WSASendMsg(...) ss_WSASendMsg(__VA_ARGS__)
#    define WSAIoctl(...) ss_WSAIoctl(__VA_ARGS__)
#  else
#    define sendmsg(...) ss_sendmsg(__VA_ARGS__)
#    define recvmsg(...) ss_recvmsg(__VA_ARGS__)
#    define close(...) ss_close(__VA_ARGS__)
#  endif
#endif

#endif /* SS_SHIM_H */
