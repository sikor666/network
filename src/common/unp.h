#pragma once

#if defined _WIN32
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <afunix.h>

#include <cstdio>

#define bzero(ptr,n)        memset(ptr, 0, n)
#define close               closesocket
#define ssize_t             size_t
#else
#include <sys/socket.h>     // basic socket definitions
#include <netinet/in.h>     // sockaddr_in{} and other Internet defns
#include <netinet/tcp.h>    // for TCP_xxx defines
#include <arpa/inet.h>      // inet(3) functions
#include <netdb.h>
#include <net/if.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#endif

/* Miscellaneous constants */
#define	MAXLINE		4096	/* max text line length */
#define	BUFFSIZE	8192	/* buffer size for reads and writes */

int		 Socket(int, int, int);

void	 err_dump(const char *, ...);
void	 err_msg(const char *, ...);
void	 err_quit(const char *, ...);
void	 err_ret(const char *, ...);
void	 err_sys(const char *, ...);

// Winsock
void init();
void clean();
int error();
