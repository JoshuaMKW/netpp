#pragma once

#include "network.h"

#define SERVER_IPV4 host_ipv4()
#define SERVER_PORT "8080"

#define SERVER_USE_DTLS false

#if SERVER_USE_DTLS
#define SERVER_CERT "./cert/cert.pem"
#define SERVER_KEY "./cert/key.pem"
#else
#define SERVER_CERT nullptr
#define SERVER_KEY nullptr
#endif

#define SERVER_CERT_PASSWD "password"

#define APPSYNC_MAX_CLIENTS 32

struct SyncClientPacket {
  uint64_t m_peer_id;
  float m_cursor_x, m_cursor_y;
  float m_window_x, m_window_y;
};

struct SyncServerPacket {
  size_t m_peer_count;
  SyncClientPacket m_peer_infos[APPSYNC_MAX_CLIENTS];
};
