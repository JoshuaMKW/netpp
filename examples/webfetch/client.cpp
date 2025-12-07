#include <iostream>

#include "client.h"
#include "socket.h"
#include "http/router.h"
#include "tls/security.h"

using namespace netpp;

#define CLIENT_KEY "certs/client_key.pem"
#define CLIENT_USE_TLS 1

static netpp::HTTP_Request* BounceTheRequest(const netpp::HTTP_Response* response, netpp::HTTP_Request* request) {
  if (!response->has_header("Location")) {
    return nullptr;
  }

  std::string location = response->get_header_value("Location");
  size_t com_ofs = location.find(".com/", 0);
  std::string route = location.substr(com_ofs + 4);
  request->set_path(route);

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
    if (!netpp::generate_client_key_rsa_2048(
      CLIENT_KEY,
      "",
      "US",
      "netpp webfetch")) {
      fprintf(stderr, "Failed to generate self-signed certificate\n");
      return 1;
    }
  }

  TLSSecurityFactory* security
    = new TLSSecurityFactory(false, CLIENT_KEY, "", "", "github.com", "", ETLSVerifyFlags::VERIFY_PEER);
#else
  TLSSecurityFactory* security = nullptr;
#endif

  TCP_Client client(security);

  HTTP_Request* request = HTTP_Request::create(EHTTP_RequestMethod::E_REQUEST_GET);
  if (!request) {
    fprintf(stderr, "Failed to create HTTP request\n");
    return 1;
  }


  client.on_http_response([&](const ISocketPipe* source, const HTTP_Response* response) -> HTTP_Request * {
    if (response->status_code() == EHTTP_ResponseStatusCode::E_STATUS_MOVED_PERMANENTLY || response->status_code() == EHTTP_ResponseStatusCode::E_STATUS_FOUND) {
      return BounceTheRequest(response, request);
    }

    if (response->status_code() != EHTTP_ResponseStatusCode::E_STATUS_OK) {
      fprintf(stderr, "Failed to get response from host\n");
      return nullptr;
    }

    printf(response->body().c_str());
    return nullptr;
    });

  if (!client.start()) {
    fprintf(stderr, "Failed to start the client\n");
    return 1;
  }

  const char* hostname = get_ip_address_info("github.com").m_ipv4;
  if (!client.connect(hostname, "443")) {
    fprintf(stderr, "Failed to connect to the server\n");
    return 1;
  }

  printf("Connected to server (%s:%s)!\n\n", client.hostname().c_str(), client.port().c_str());

  request->set_version("1.1");
  request->set_path("/JoshuaMKW/JuniorsToolbox/releases");
  request->add_header("Host: github.com");
  request->add_header("Connection: close");
  request->add_header(
    "Accept: */*");
  //request->add_header("Upgrade-Insecure-Requests: 1");
  request->add_header("User-Agent: JuniorsToolbox/0.0.1");
  if (!client.send(request)) {
    fprintf(stderr, "Failed to send HTTP request\n");
    return 1;
  }

  while (client.is_running()) {
    if (!client.is_connected()) {
      break;
    }
  }

  sockets_deinitialize();
  return 0;
}