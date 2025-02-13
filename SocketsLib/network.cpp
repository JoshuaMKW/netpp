#include "network.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif

static bool get_ip_address(const char* hostname, char* ipv4, int ipv4_len, char* ipv6, int ipv6_len) {
#ifdef _WIN32
  struct addrinfo hints, * res;
  struct sockaddr_in* ipv4_addr;
  struct sockaddr_in6* ipv6_addr;
  char ipstr[INET6_ADDRSTRLEN];

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
    return false;
  }

  for (struct addrinfo* p = res; p != NULL; p = p->ai_next) {
    if (p->ai_family == AF_INET) {
      ipv4_addr = (struct sockaddr_in*)p->ai_addr;
      inet_ntop(p->ai_family, &ipv4_addr->sin_addr, ipstr, sizeof ipstr);
      strncpy_s(ipv4, ipv4_len, ipstr, ipv4_len);
    }
    else {
      ipv6_addr = (struct sockaddr_in6*)p->ai_addr;
      inet_ntop(p->ai_family, &ipv6_addr->sin6_addr, ipstr, sizeof ipstr);
      strncpy_s(ipv6, ipv6_len, ipstr, ipv6_len);
    }
  }

  freeaddrinfo(res);
  return true;
#else
  return false;
#endif
}

static char s_ipv4_address[INET_ADDRSTRLEN];
static char s_ipv6_address[INET6_ADDRSTRLEN];

const char* network_ipv4() {
  if (get_ip_address("localhost", s_ipv4_address, INET_ADDRSTRLEN, s_ipv6_address, INET6_ADDRSTRLEN)) {
    return s_ipv4_address;
  }
  return nullptr;
}

const char* network_ipv6() {
  if (get_ip_address("localhost", s_ipv4_address, INET_ADDRSTRLEN, s_ipv6_address, INET6_ADDRSTRLEN)) {
    return s_ipv6_address;
  }
  return nullptr;
}
