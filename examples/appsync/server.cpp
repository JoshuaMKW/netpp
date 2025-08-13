
#include <chrono>
#include <iostream>
#include <fstream>
#include <thread>

#include "socket.h"
#include "http/router.h"
#include "tls/security.h"
#include "server.h"

#include "common.h"

using namespace netpp;

struct MessagePacket {
  size_t m_client_name_len;
  size_t m_message_len;

  bool validate(uint32_t packet_len) const {
    if (m_client_name_len == 0 || m_message_len == 0) {
      return false;
    }
    return packet_len >= sizeof(MessagePacket) + m_client_name_len + m_message_len + 2;
  }

  char* get_client_name() const {
    return (char*)(this + 1);
  }

  char* get_message() const {
    return get_client_name() + m_client_name_len + 1;
  }
};

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
  TLSSecurityFactory* security = new TLSSecurityFactory(true, SERVER_KEY, SERVER_CERT, "", "localhost", SERVER_CERT_PASSWD,
    ETLSVerifyFlags::VERIFY_PEER);
#else
  TLSSecurityFactory* security = nullptr;
#endif

  TCP_Server server(security, 1024);

  if (server.start(SERVER_IPV4, SERVER_PORT)) {
    printf("Server started on %s:%s\n", server.hostname().c_str(), server.port().c_str());
  }
  else {
    fprintf(stderr, "Failed to start the server\n");
    return 1;
  }

  HTTP_Router router;

  router.on_get("/history", [](const HTTP_Request* request) -> HTTP_Response* {
    std::ifstream history_file("./_chat_history.txt");
    if (history_file.is_open()) {
      std::string history_content((std::istreambuf_iterator<char>(history_file)), std::istreambuf_iterator<char>());

      HTTP_Response* response = HTTP_Response::create(EHTTP_ResponseStatusCode::E_STATUS_OK);
      response->set_version("1.1");
      response->add_header("Content-Type: text/plain; charset=UTF-8");
      response->add_header("Connection: keep-alive");
      response->set_body(history_content);
      return response;
    }

    HTTP_Response* response = HTTP_Response::create(EHTTP_ResponseStatusCode::E_STATUS_NOT_FOUND);
    response->set_version("1.1");
    return response;
    });

  router.on_unhandled([](const HTTP_Request* request) -> HTTP_Response* {
    HTTP_Response* response = HTTP_Response::create(EHTTP_ResponseStatusCode::E_STATUS_METHOD_NOT_ALLOWED);
    response->set_version("1.1");
    response->add_header("Content-Type: text/plain; charset=UTF-8");
    response->add_header("Connection: keep-alive");
    return response;
    });

  server.on_http_request([&router](const ISocketPipe* source, const HTTP_Request* request) {
    return router.signal_method(request);
    });


  server.on_raw_receive([&](const ISocketPipe* source, const RawPacket* packet) {
    MessagePacket* msg = (MessagePacket*)packet->message();
    if (!msg->validate(packet->length())) {
      fprintf(stderr, "Invalid message packet received\n");
      return nullptr;
    }

    const char* client_name = msg->get_client_name();
    const char* message = msg->get_message();

    history_file << "Client (" << client_name << "): " << message << "\n";
    history_file.flush();

    printf("Client (%s): %s\n", client_name, message);
    server.send_all(packet);
    return nullptr;
    });

  while (server.is_running()) { std::this_thread::sleep_for(std::chrono::seconds(1)); }

  delete security;

  sockets_deinitialize();
  return 0;
}
