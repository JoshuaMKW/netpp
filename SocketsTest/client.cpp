#include <iostream>
#include "socket.h"
#include "client.h"

#pragma comment(lib, "SocketsLib.lib")

int main(int argc, char** argv) {
  if (!sockets_initialize()) {
    fprintf(stderr, "Failed to initialize sockets interface\n");
    return 1;
  }

  TCP_Client client;

  client.on_response([](IClient* client, const HTTP_Response* response) -> HTTP_Request* {
    printf("Received response: %d\n", (int)response->status_code());
    printf("Version: %s\n", response->version().c_str());
    for (int i = 0; i < response->headers_count(); i++) {
      std::string header = response->headers()[i];
      printf("Header: %s\n", header.c_str());
    }
    printf("Body: %s\n", response->body().c_str());
    return nullptr;
  });

  client.on_receive([](IClient* client, const RawPacket* packet) -> RawPacket* {
    std::string packet_str(packet->m_message, packet->m_length);
    printf("[CLIENT (%d)] Server (%s:%s) responded: %s\n", client->socket(), client->host_name(), client->host_port(), packet_str.c_str());
    return nullptr;
  });

  if (!client.start()) {
    fprintf(stderr, "Failed to start the client\n");
    return 1;
  }

  if (!client.connect(network_ipv4(), DEFAULT_PORT)) {
    fprintf(stderr, "Failed to connect to the server\n");
    return 1;
  }

  while (client.is_running()) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    if (client.error() != EClientError::E_NONE) {
      fprintf(stderr, "Fatal error: %s\n", client_error(client.error(), client.reason()));
      fprintf(stderr, "Forcefully stopping the client...\n");
      client.stop();
    }

    RawPacket packet = { "Ping", 4 };
    client.send(&packet);
  }

  sockets_deinitialize();
  return 0;
}