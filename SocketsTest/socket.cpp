#include "network.h"
#include "socket.h"

#include <iostream>

#ifdef _WIN32

#pragma comment(lib, "ws2_32.lib")
#include <MSWSock.h>

static WSADATA wsa_data;

bool sockets_initialize() {
  // Initialize Winsock
  return WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0;
}

void sockets_deinitialize() {
  WSACleanup();
}

int receive_message(SOCKET socket, char* recvbuf, int buflen) {
#if 1
  return recv(socket, recvbuf, buflen, 0);
#else
#endif
}

bool send_message(SOCKET socket, const char* sendbuf, int buflen) {
#if 1
  return send(socket, sendbuf, buflen, 0) != SOCKET_ERROR;
#else
#endif
}

#else

bool sockets_initialize() {
  return true;
}

void sockets_deinitialize() {
}

void* __sockets_interface()
{
  return nullptr;
}

#endif
