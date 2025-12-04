#pragma once

#include "network.h"

#define SERVER_IPV4 network_ipv4()
#define SERVER_PORT "8080"

#define SERVER_USE_TLS true

#if SERVER_USE_TLS
#define SERVER_CERT "./cert/localhost.crt"
#define SERVER_KEY "./cert/localhost.key"
#define SERVER_CACERT "./cert/rootCA.pem"
#define SERVER_CERT_PASSWD ""
#else
#define SERVER_CERT nullptr
#define SERVER_KEY nullptr
#define SERVER_CACERT nullptr
#define SERVER_CERT_PASSWD nullptr
#endif

#define SERVER_CERT_PASSWD "password"