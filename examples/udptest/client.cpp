// **************************************************************
// * netpp C++ Networking Library (webfetch example)
// * Copyright (C) 2024-2025 Joshua Alston
// *
// * This program is free software; you can redistribute it and/or
// * modify it under the terms of the GNU General Public License
// * as published by the Free Software Foundation; either version 2
// * of the License, or (at your option) any later version.
// **************************************************************

#include <iostream>
#include <string>

#include "client.h"
#include "socket.h"
#include "protocol.h"
#include "dtls/security.h"

using namespace netpp;

#define CLIENT_HOST "8.8.8.8"
#define CLIENT_KEY "cert/client_key.pem"
#define CLIENT_USE_DTLS 0

int main(int argc, char** argv) {
  if (!sockets_initialize()) {
    fprintf(stderr, "Failed to initialize sockets interface\n");
    return 1;
  }

#if CLIENT_USE_DTLS
  if (!std::filesystem::exists(CLIENT_KEY)) {
    std::filesystem::create_directories(std::filesystem::path(CLIENT_KEY).parent_path());
    if (!netpp::generate_client_key_rsa_4096(
      CLIENT_KEY,
      "",
      "US",
      "netpp webfetch")) {
      fprintf(stderr, "Failed to generate self-signed certificate\n");
      return 1;
    }
  }

  DTLSSecurityFactory* security
      = new DTLSSecurityFactory(false, CLIENT_KEY, "", "", CLIENT_HOST, "", EDTLSVerifyFlags::VERIFY_PEER);
#else
  DTLSSecurityFactory* security = nullptr;
#endif

  UDP_Client client(security);
  if (!client.start()) {
    fprintf(stderr, "Failed to start the client\n");
    return 1;
  }

  const char* hostname = get_ip_address_info(CLIENT_HOST).m_ipv4;
  if (!client.connect(hostname, "53")) {
    fprintf(stderr, "Failed to connect to the server\n");
    return 1;
  }

  printf("Connected to server (%s:%s)!\n\n", client.hostname().c_str(), client.port().c_str());

  RawPacket* msg = RawPacket::create("Ping", 4);

  std::mutex send_mutex;
  std::condition_variable send_cv;

  client.on_raw_receive([](const ISocketPipe* source, const RawPacket* packet) -> RawPacket* {
      std::string msg = std::string(packet->message(), packet->length());
      fprintf(stdout, "Received a raw packet! (%s)\n", msg.c_str());
      return RawPacket::create("Ping", 4);
  });

  if (!client.send(msg)) {
    fprintf(stderr, "Failed to send message\n");
    return 1;
  }

  std::unique_lock lock(send_mutex);
  send_cv.wait(lock);

  client.stop();

  sockets_deinitialize();
  return 0;
}