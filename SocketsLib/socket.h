#pragma once

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsockdef.h>
#include <MSWSock.h>
#else
#include <sys/socket.h>
#endif

#ifndef DEFAULT_PORT
#define DEFAULT_PORT "8080"
#endif

#ifndef DEFAULT_BUFLEN
#define DEFAULT_BUFLEN 1024 * 64
#endif

#ifndef DEFAULT_BUFFERS
#define DEFAULT_BUFFERS 128
#endif

enum class ESocketErrorReason {
  E_NONE = -1,
  E_REASON_STARTUP,
  E_REASON_PORT,
  E_REASON_RESOURCES,
  E_REASON_SOCKET,
  E_REASON_BIND,
  E_REASON_LISTEN,
  E_REASON_THREADS,
  E_REASON_SEND,
  E_REASON_ADDRESS,
  E_COUNT,
};

struct SocketInterface {
#ifdef _WIN32
  WSAData wsa_data;
  RIO_EXTENSION_FUNCTION_TABLE rio;
  struct {
    LPFN_ACCEPTEX AcceptEx;
    LPFN_GETACCEPTEXSOCKADDRS GetAcceptExSockAddrs;
  } exio;
#else
#endif
};


bool sockets_initialize();
void sockets_deinitialize();

int receive_message(SOCKET socket, char* recvbuf, int buflen);
bool send_message(SOCKET socket, const char* sendbuf, int buflen);