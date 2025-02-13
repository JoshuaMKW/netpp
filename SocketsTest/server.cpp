
#include <chrono>
#include <iostream>
#include <fstream>
#include <thread>

#include "socket.h"
#include "server.h"

#pragma comment(lib, "SocketsLib.lib")

int main(int argc, char** argv) {
  if (!sockets_initialize()) {
    fprintf(stderr, "Failed to initialize sockets interface\n");
    return 1;
  }

  TCP_Server server;

  server.on_request([](const HTTP_Request* request) {
    printf("Received request: %d for URL %s\n", (int)request->method(), request->path().c_str());

    std::ifstream html_file("./index.html");
    std::string html_content((std::istreambuf_iterator<char>(html_file)), std::istreambuf_iterator<char>());

    HTTP_Response *response = HTTP_Response::create(EHTTP_ResponseStatusCode::E_STATUS_OK);
    response->set_version("1.1");
    response->add_header("Content-Type: text/html; charset=UTF-8");
    response->add_header("Content-Length: " + std::to_string(html_content.length()));
    response->add_header("Connection: keep-alive");
    response->set_body(html_content);
    return response;
  });


  server.on_receive([](const RawPacket* packet) {
    std::string packet_str(packet->m_message, packet->m_length);
    printf("[SERVER] Client said: %s\n", packet_str.c_str());

    RawPacket *response = new RawPacket();
    response->m_message = "Pong";
    response->m_length = 4;
    return response;
  });

  if (server.start(network_ipv4(), DEFAULT_PORT)) {
    printf("Server started on %s:%s\n", server.hostname(), server.port());
  } else {
    fprintf(stderr, "Failed to start the server\n");
    return 1;
  }

  while (server.is_running()) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    if (server.error() != EServerError::E_NONE) {
      fprintf(stderr, "Fatal error: %s\n", server_error(server.error(), server.reason()));
      fprintf(stderr, "Forcefully stopping the server...\n");
      server.stop();
    }
  }

  // NONE is -1 and errors are 0-based
  return (int)server.error() + 1;
}
