#include	"unp.h"

void init()
{
#if defined _WIN32
    // Initialize Winsock
    WSADATA wsaData;

    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
    {
        err_sys("Initialize Winsock failed: ", result);
    }
#endif
}

void clean()
{
#if defined _WIN32
    WSACleanup();
#endif
}
