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

#include "client.h"
#include "socket.h"
#include "http/router.h"
#include "tls/security.h"

using namespace netpp;

#define CLIENT_HOST "api.github.com"
#define CLIENT_KEY "cert/client_key.pem"
#define CLIENT_USE_TLS 1

static netpp::HTTP_Request* BounceTheRequest(const netpp::HTTP_Response* response, netpp::HTTP_Request* request) {
  if (!response->has_header("Location")) {
    return nullptr;
  }

  std::string location = response->get_header_value("Location");

  char hostname_buf[64];
  char pathname_buf[256];
  http_get_hostname_and_path_from_str(
    location.c_str(), hostname_buf, sizeof(hostname_buf), pathname_buf, sizeof(pathname_buf));

  std::string hostname(hostname_buf);
  std::string pathname(pathname_buf);

  request->set_header("Host", hostname);
  request->set_path(pathname);
  return request;
}

int main(int argc, char** argv) {
  if (!sockets_initialize()) {
    fprintf(stderr, "Failed to initialize sockets interface\n");
    return 1;
  }

#if CLIENT_USE_TLS
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

  TLSSecurityFactory* security
    = new TLSSecurityFactory(false, CLIENT_KEY, "", "", CLIENT_HOST, "", ETLSVerifyFlags::VERIFY_PEER);
#else
  TLSSecurityFactory* security = nullptr;
#endif

  TCP_Client client(security);
  if (!client.start()) {
    fprintf(stderr, "Failed to start the client\n");
    return 1;
  }

  const char* hostname = get_ip_address_info(CLIENT_HOST).m_ipv4;
  if (!client.connect(hostname, "443")) {
    fprintf(stderr, "Failed to connect to the server\n");
    return 1;
  }

  printf("Connected to server (%s:%s)!\n\n", client.hostname().c_str(), client.port().c_str());

  HTTP_Request* request = HTTP_Request::create(EHTTP_RequestMethod::E_REQUEST_GET);
  if (!request) {
    fprintf(stderr, "Failed to create HTTP request\n");
    return 1;
  }

  std::mutex send_mutex;
  std::condition_variable send_cv;

  client.on_http_response([&](const ISocketPipe* source, const HTTP_Response* response) -> HTTP_Request* {
    if (response->status_code() == EHTTP_ResponseStatusCode::E_STATUS_MOVED_PERMANENTLY || response->status_code() == EHTTP_ResponseStatusCode::E_STATUS_FOUND) {
      HTTP_Request* bounced = BounceTheRequest(response, request);
      if (!bounced) {
        fprintf(stderr, "Failed to bounce HTTP request\n");
        send_cv.notify_one();
        return nullptr;
      }
      return bounced;
    }

    printf(response->body().c_str());
    send_cv.notify_one();
    return nullptr;
    });

  request->set_version("1.1");
  request->set_path("/repos/JoshuaMKW/netpp");
  request->set_header("Host", CLIENT_HOST);
  request->set_header("Connection", "keep-alive");
  request->set_header("Accept", "application/vnd.github+json");
  request->set_header("X-GitHub-Api-Version", "2022-11-28");
  request->set_header("Upgrade-Insecure-Requests", "1");
  request->set_header("User-Agent", "netpp::webfetch/1.0.0");

  if (!client.send(request)) {
    fprintf(stderr, "Failed to send HTTP request\n");
    return 1;
  }

  std::unique_lock lock(send_mutex);
  send_cv.wait(lock);

  client.stop();

  sockets_deinitialize();
  return 0;
}