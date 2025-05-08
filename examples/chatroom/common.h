#pragma once

#include "network.h"

#define SERVER_IPV4 network_ipv4()
#define SERVER_PORT "8080"

#define SERVER_USE_TLS true

#if SERVER_USE_TLS
#define SERVER_CERT "./cert/cert.pem"
#define SERVER_KEY "./cert/key.pem"
#else
#define SERVER_CERT nullptr
#define SERVER_KEY nullptr
#endif

#define SERVER_CERT_PASSWD "password"