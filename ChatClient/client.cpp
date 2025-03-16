#include <iostream>

#include "inputhandler.h"
#include "socket.h"
#include "client.h"

#pragma comment(lib, "netpp.lib")

//#define SERVER_IPV4 "47.222.169.75"
#define SERVER_IPV4 network_ipv4()
#define SERVER_PORT "8080"

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

  TCP_Client client;
  InputHandler msg_handler(client_name);

  bool sent_message = false;
  bool history_received = false;
  bool history_failed = false;

  client.on_http_response([&](const ISocketPipe* source, const HTTP_Response* response) {
    if (response->status_code() != EHTTP_ResponseStatusCode::E_STATUS_OK) {
      fprintf(stderr, "Failed to get history from server\n");
      history_failed = true;
      return nullptr;
    }

    printf("%s", response->body().c_str());
    history_received = true;

    return nullptr;
    });

  client.on_raw_receive([&](const ISocketPipe* source, const RawPacket* packet) {
    MessagePacket* msg = (MessagePacket*)packet->m_message;
    if (!msg->validate(packet->m_length)) {
      return nullptr;
    }

    // Clear line on the console
    if (sent_message) {
      printf("\x1b[1F"); // Move to beginning of previous line
      printf("\x1b[2K"); // Clear entire line
      printf("\x1b[1F"); // Move to beginning of previous line
      printf("\x1b[2K"); // Clear entire line
      printf("\x1b[1F"); // Move to beginning of previous line
      printf("\x1b[2K"); // Clear entire line
      printf("Client (%s): %s\n", msg->get_client_name(), msg->get_message());
      msg_handler.flag_processed();
      sent_message = false;
    }
    else {
      printf("\x1b[s"); // Save cursor position
      printf("\x1b[2K"); // Clear entire line
      printf("\x1b[1F"); // Move to beginning of previous line
      printf("\x1b[2K"); // Clear entire line
      printf("\x1b[1F"); // Move to beginning of previous line
      printf("\x1b[2K"); // Clear entire line
      //printf("\x1b[1E"); // Move to beginning of next line
      printf("Client (%s): %s\n", msg->get_client_name(), msg->get_message());
      msg_handler.print_prompt();
      printf("\x1b[u"); // Restore cursor position
      printf("\x1b[1B"); // Move to next line
    }

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

  HTTP_Request* request = HTTP_Request::create(EHTTP_RequestMethod::E_REQUEST_GET);
  if (!request) {
    fprintf(stderr, "Failed to create HTTP request\n");
    return 1;
  }

  request->set_version("1.1");
  request->add_header("Host: " + client.server_hostname());
  request->add_header("Connection: keep-alive");
  request->set_path("/history");
  if (!client.send(request)) {
    fprintf(stderr, "Failed to send HTTP request\n");
    return 1;
  }

  while (!history_received) {
    if (!client.is_connected() || history_failed) {
      fprintf(stderr, "Failed to keep connection during history call\n");
      return 1;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  msg_handler.on_message_submit([&](const std::string& message) -> bool {
    size_t packet_len = sizeof(MessagePacket) + client_name.length() + message.length() + 2;
    MessagePacket* msg = (MessagePacket*)malloc(packet_len);
    if (!msg) {
      fprintf(stderr, "Failed to allocate message packet\n");
      return 1;
    }

    if (message == "/exit") {
      printf("\n\n> Exiting...\n");
      client.disconnect();
      return false;
    }

    sent_message = true;

    memset(msg, 0, packet_len);

    msg->m_client_name_len = client_name.length();
    msg->m_message_len = message.length();
    memcpy(msg->get_client_name(), client_name.c_str(), client_name.length());
    memcpy(msg->get_message(), message.c_str(), message.length());

    RawPacket packet = { (char*)msg, (uint32_t)packet_len };
    client.send(&packet);

    free(msg);
    return true;
    });
  msg_handler.start();

  while (client.is_running()) {
    if (!client.is_connected()) {
      fprintf(stderr, "Attempting to reconnect...\n");
#if REQUEST_IP_AND_PORT
      client.connect(server_ipv4.c_str(), server_port.c_str());
#else
      client.connect(SERVER_IPV4, SERVER_PORT);
#endif
    }
  }

  msg_handler.stop();

  sockets_deinitialize();
  return 0;
}