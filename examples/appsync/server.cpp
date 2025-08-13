
#include <chrono>
#include <iostream>
#include <fstream>
#include <thread>

#include "socket.h"
#include "http/router.h"
#include "dtls/security.h"
#include "server.h"

#include "common.h"

using namespace netpp;

int main(int argc, char** argv) {
  if (!sockets_initialize()) {
    fprintf(stderr, "Failed to initialize sockets interface\n");
    return 1;
  }

  std::ofstream history_file("./_chat_history.txt", std::ios_base::app);
  if (!history_file.is_open()) {
    fprintf(stderr, "Failed to open history file\n");
    return 1;
  }

#if SERVER_USE_TLS
  DTLSSecurityFactory* security = new DTLSSecurityFactory(true, SERVER_KEY, SERVER_CERT, "", "localhost", SERVER_CERT_PASSWD,
    ETLSVerifyFlags::VERIFY_PEER);
#else
  DTLSSecurityFactory* security = nullptr;
#endif

  UDP_Server server(security, 1024);

  if (server.start(SERVER_IPV4, SERVER_PORT)) {
    printf("Server started on %s:%s\n", server.hostname().c_str(), server.port().c_str());
  }
  else {
    fprintf(stderr, "Failed to start the server\n");
    return 1;
  }


  SyncServerPacket pckt_state = {};

  server.on_raw_receive([&](const ISocketPipe* source, const RawPacket* packet) {
    SyncClientPacket* msg = (SyncClientPacket*)packet->message();

    bool updated = false;
    for (size_t i = 0; i < pckt_state.m_peer_count; ++i) {
      if (pckt_state.m_peer_infos[i].m_peer_id == msg->m_peer_id) {
        pckt_state.m_peer_infos[i] = msg;
        updated = true;
        break;
      }
    }

    // No logic for removing peers currently
    if (!updated) {
      pckt_state.m_peer_infos[pckt_state.m_peer_count++] = msg;
    }

    return nullptr;
    });

  while (server.is_running()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(16));
    
    RawPacket* pckt = RawPacket::create((void*)pckt_state, sizeof(pckt_state));
    server.send_all(pckt);
    delete pckt;
  }

  delete security;

  sockets_deinitialize();
  return 0;
}
