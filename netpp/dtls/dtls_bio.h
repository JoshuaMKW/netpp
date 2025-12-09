#pragma once

#include <openssl/ssl.h>

# ifndef OPENSSL_NO_SOCK
union bio_addr_st {
  struct sockaddr sa;
# if OPENSSL_USE_IPV6
  struct sockaddr_in6 s_in6;
# endif
  struct sockaddr_in s_in;
};
#endif

namespace netpp {

  typedef struct bio_dgram_data_st {
    BIO_ADDR peer;
    unsigned int connected;
    unsigned int _errno;
    unsigned int mtu;
    struct timeval next_timeout;
    struct timeval socket_timeout;
    unsigned int peekmode;
  } bio_dgram_data;



}