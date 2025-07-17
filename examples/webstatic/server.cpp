
#include <chrono>
#include <iostream>
#include <fstream>
#include <thread>

#include "socket.h"
#include "server.h"
#include "tls/controller.h"

#include "network.h"

using namespace netpp;
using namespace std::chrono_literals;

#define SERVER_IPV4 "0.0.0.0"

#define SERVER_USE_TLS true

#if SERVER_USE_TLS
#define SERVER_CERT "./cert/localhost.crt"
#define SERVER_KEY "./cert/localhost.key"
#define SERVER_CACERT "./cert/rootCA.pem"
#define SERVER_CERT_PASSWD ""

#define SERVER_PORT "443"
#else
#define SERVER_CERT nullptr
#define SERVER_KEY nullptr
#define SERVER_CERT_PASSWD "password"

#define SERVER_PORT "8080"
#endif

static HTTP_Response* get_response(const std::string& content_type, const std::string& body) {
  HTTP_Response* response = HTTP_Response::create(EHTTP_ResponseStatusCode::E_STATUS_OK);
  response->set_version("1.1");
  response->add_header("Content-Type: " + content_type + "; charset=UTF-8");
  response->add_header("Connection: keep-alive");
  response->set_body(body);
  return response;
}

static HTTP_Response* not_found_response() {
  HTTP_Response* response = HTTP_Response::create(EHTTP_ResponseStatusCode::E_STATUS_NOT_FOUND);
  response->set_version("1.1");
  return response;
}

static HTTP_Response* method_not_allowed_response() {
  HTTP_Response* response = HTTP_Response::create(EHTTP_ResponseStatusCode::E_STATUS_METHOD_NOT_ALLOWED);
  response->set_version("1.1");
  response->add_header("Content-Type: text/plain; charset=UTF-8");
  response->add_header("Connection: keep-alive");
  return response;
}

int main(int argc, char** argv) {
  if (!sockets_initialize()) {
    fprintf(stderr, "Failed to initialize sockets interface\n");
    return 1;
  }

#if SERVER_USE_TLS
  TLSSecurityFactory* security
    = new TLSSecurityFactory(true, SERVER_KEY, SERVER_CERT, SERVER_CACERT, "localhost", SERVER_CERT_PASSWD,
      ETLSVerifyFlags::VERIFY_PEER | ETLSVerifyFlags::VERIFY_FAIL_IF_NO_PEER_CERT);
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

  server.on_http_request([](const ISocketPipe* source, const HTTP_Request* request) {
    //printf("Received request: %d for URL %s\n", (int)request->method(), request->path().c_str());

    if (request->method() != EHTTP_RequestMethod::E_REQUEST_GET) {
      return method_not_allowed_response();
    }

    if (request->path() == "/") {
      std::ifstream html_file("./webdata/index.html");

      if (!html_file.is_open()) {
        return not_found_response();
      }

      std::string html_content((std::istreambuf_iterator<char>(html_file)), std::istreambuf_iterator<char>());

      return get_response("text/html", html_content);
    }

    if (request->path() == "/index.css") {
      std::ifstream css_file("./webdata/index.css");
      if (!css_file.is_open()) {
        return not_found_response();
      }

      std::string css_content((std::istreambuf_iterator<char>(css_file)), std::istreambuf_iterator<char>());

      return get_response("text/css", css_content);
    }

    if (request->path() == "/favicon.ico") {
      std::ifstream favicon_file("./webdata/favicon.ico");
      if (!favicon_file.is_open()) {
        return not_found_response();
      }

      std::string favicon_content((std::istreambuf_iterator<char>(favicon_file)), std::istreambuf_iterator<char>());

      return get_response("image/x-icon", favicon_content);
    }

    return not_found_response();
    });

  while (server.is_running()) {
    std::this_thread::sleep_for(100ms);
  }

  sockets_deinitialize();
  return 0;
}
