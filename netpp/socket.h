#pragma once

#include <functional>
#include <string>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsockdef.h>
#include <MSWSock.h>
#else
#include <sys/socket.h>
#endif

#include "network.h"
#include "request.h"
#include "response.h"

#ifndef DEFAULT_PORT
#define DEFAULT_PORT "8080"
#endif

#ifndef DEFAULT_BUFLEN
#define DEFAULT_BUFLEN 1024 * 256
#endif

#ifndef DEFAULT_BUFFERS
#define DEFAULT_BUFFERS 128
#endif

namespace netpp {

  struct SocketInterface {
#ifdef _WIN32
    WSAData wsa_data;
    RIO_EXTENSION_FUNCTION_TABLE rio;
    struct {
      LPFN_ACCEPTEX AcceptEx;
      LPFN_GETACCEPTEXSOCKADDRS GetAcceptExSockAddrs;
    } exio;
#else
#endif
  };

  enum class ESocketErrorReason {
    E_NONE = -1,
    E_REASON_STARTUP,
    E_REASON_PORT,
    E_REASON_RESOURCES,
    E_REASON_SOCKET,
    E_REASON_BIND,
    E_REASON_LISTEN,
    E_REASON_THREADS,
    E_REASON_SEND,
    E_REASON_ADDRESS,
    E_COUNT,
  };

  enum class EPipeOperation {
    E_RECV,
    E_SEND,
    E_BOTH,
  };

  struct ISocketPipe {
    using close_callback = std::function<void(ISocketPipe*)>;
    using request_callback = std::function<HTTP_Response* (const ISocketPipe* source, const HTTP_Request* request)>;
    using response_callback = std::function<HTTP_Request* (const ISocketPipe* source, const HTTP_Response* response)>;
    using receive_callback = std::function<RawPacket* (const ISocketPipe* source, const RawPacket* packet)>;

    virtual ~ISocketPipe() = default;

    virtual uint64_t socket() const = 0;

    virtual const std::string& hostname() const = 0;
    virtual const std::string& port() const = 0;

    virtual bool is_busy(EPipeOperation op) const = 0;

    virtual bool open(const char* hostname, const char* port) = 0;
    virtual void close() = 0;
    virtual void error(ESocketErrorReason reason) = 0;

    virtual bool recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) = 0;
    virtual bool send(const char* data, uint32_t size, uint32_t* flags) = 0;
    virtual bool send(const HTTP_Request* request) = 0;
    virtual bool send(const HTTP_Response* response) = 0;
    virtual bool send(const RawPacket* packet) = 0;

    virtual void on_close(close_callback callback) = 0;
    virtual void on_receive(receive_callback callback) = 0;
    virtual void on_request(request_callback callback) = 0;
    virtual void on_response(response_callback callback) = 0;
  };

  bool sockets_initialize();
  void sockets_deinitialize();

}  // namespace netpp
