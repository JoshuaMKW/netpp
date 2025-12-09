// **************************************************************
// * netpp C++ Networking Library (appsync example)
// * Copyright (C) 2024-2025 Joshua Alston
// *
// * This program is free software; you can redistribute it and/or
// * modify it under the terms of the GNU General Public License
// * as published by the Free Software Foundation; either version 2
// * of the License, or (at your option) any later version.
// **************************************************************

#include <iostream>

#include "client.h"
#include "socket.h"
#include "http/router.h"
#include "dtls/security.h"

#include "common.h"
#include "inputhandler.h"

using namespace netpp;

#define REQUEST_IP_AND_PORT 0

static void enable_ansi_escape() {
#ifdef _WIN32
  // Enable ANSI escape codes for Windows
  HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
  if (hOut == INVALID_HANDLE_VALUE) {
    return;
  }

  DWORD dwMode = 0;
  if (!GetConsoleMode(hOut, &dwMode)) {
    return;
  }

  dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
  if (!SetConsoleMode(hOut, dwMode)) {
    return;
  }
#endif
}

int main(int argc, char** argv) {
  if (!sockets_initialize()) {
    fprintf(stderr, "Failed to initialize sockets interface\n");
    return 1;
  }

  enable_ansi_escape();

#if REQUEST_IP_AND_PORT
  std::string server_ipv4;
  printf("Enter the server IPv4 address: ");
  std::getline(std::cin, server_ipv4);

  std::string server_port;
  printf("Enter the server port: ");
  std::getline(std::cin, server_port);
#endif

  std::string client_name;
  printf("Enter your name: ");
  std::getline(std::cin, client_name);

#if SERVER_USE_DTLS
  DTLSSecurityFactory* security
    = new DTLSSecurityFactory(false, SERVER_KEY, SERVER_CERT, "", "localhost", "", ETLSVerifyFlags::VERIFY_PEER);
#else
  DTLSSecurityFactory* security = nullptr;
#endif

  UDP_Client client(security);

  client.on_raw_receive([&](const ISocketPipe* source, const RawPacket* packet) {
    SyncServerPacket* msg = (SyncServerPacket*)packet->message();

    printf("== Packet Data ==\n");
    for (size_t i = 0; i < msg->m_peer_count; ++i) {
      SyncClientPacket pck = msg->m_peer_infos[i];
      printf("ClientID(%ul): Cur(%f, %f), Win(%f, %f)\n",
        pck.m_peer_id, pck.m_cursor_x, pck.m_cursor_y, pck.m_window_x, pck.m_window_y);
    }
    printf("\n");

    return nullptr;
    });

  if (!client.start()) {
    fprintf(stderr, "Failed to start the client\n");
    return 1;
  }

#if REQUEST_IP_AND_PORT
  if (!client.connect(server_ipv4.c_str(), server_port.c_str())) {
    fprintf(stderr, "Failed to connect to the server\n");
    return 1;
  }
#else
  if (!client.connect(SERVER_IPV4, SERVER_PORT)) {
    fprintf(stderr, "Failed to connect to the server\n");
    return 1;
  }
#endif

  printf("Connected to server (%s:%s)!\n\n", client.hostname().c_str(), client.port().c_str());

#ifdef WIN32
  const DWORD peer_id = GetProcessIdOfThread(GetCurrentThread());

  while (client.is_running()) {
    if (!client.is_connected()) {
      fprintf(stderr, "Attempting to reconnect...\n");
#if REQUEST_IP_AND_PORT
      client.connect(server_ipv4.c_str(), server_port.c_str());
#else
      client.connect(SERVER_IPV4, SERVER_PORT);
#endif
      continue;
    }

    POINT cursor_pos;
    if (!GetCursorPos(&cursor_pos)) {
      fprintf(stderr, "Failed to get the cursor pos...\n");
      continue;
    }

    SyncClientPacket pck = {};
    pck.m_peer_id = peer_id;
    pck.m_cursor_x = cursor_pos.x;
    pck.m_cursor_y = cursor_pos.y;
    pck.m_window_x = 0;
    pck.m_window_y = 0;

    RawPacket *raw_pck = RawPacket::create((char*)(&pck), sizeof(SyncClientPacket));
    client.send(raw_pck);
    delete raw_pck;
  }
#endif

  delete security;

  sockets_deinitialize();
  return 0;
}