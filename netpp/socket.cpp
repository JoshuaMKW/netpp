#include "network.h"
#include "socket.h"

#include <iostream>

#ifdef _WIN32

#pragma comment(lib, "ws2_32.lib")
#include <MSWSock.h>

namespace netpp {

  static WSADATA wsa_data;

  bool sockets_initialize() {
    // Initialize Winsock
    return WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0;
  }

  void sockets_deinitialize() {
    WSACleanup();
  }

}  // namespace netpp

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
