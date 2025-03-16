#pragma once

#include <functional>
#include <mutex>
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

#include "allocator.h"
#include "network.h"
#include "protocol.h"
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
    E_REASON_ACCEPT,
    E_REASON_CONNECT,
    E_REASON_RECV,
    E_REASON_SENDTO,
    E_REASON_RECVFROM,
    E_REASON_CORRUPT,
    E_REASON_ADAPTER_UNKNOWN,
    E_REASON_ADAPTER_FAIL,
    E_COUNT,
  };

  enum class EPipeOperation {
    E_RECV,
    E_SEND,
    E_RECV_SEND,
    E_CLOSE,
  };

  enum class ESocketHint {
    E_NONE,
    E_SERVER,
    E_CLIENT,
  };

  class DNS_Request;
  class DNS_Response;
  class HTTP_Request;
  class HTTP_Response;
  class RawPacket;
  class RTP_Packet;
  class RTCP_Packet;
  class SIP_Request;
  class SIP_Response;

  class ISocketOSSupportLayer;

  class ISocketIOResult {
  public:
    struct OperationData {
      EPipeOperation m_operation;
      uint32_t m_bytes_transferred;
    };

    using each_fn = std::function<bool(ISocketOSSupportLayer* pipe, const OperationData& info)>;

    virtual ~ISocketIOResult() = default;

    virtual bool is_valid() const = 0;
    virtual bool for_each(each_fn cb) = 0;
  };

  class ISocketOSSupportLayer {
  public:
    using close_cb = std::function<bool(ISocketOSSupportLayer*)>;
    using error_cb = std::function<bool(ISocketOSSupportLayer*, ESocketErrorReason reason)>;

    virtual ~ISocketOSSupportLayer() = default;

    virtual uint64_t socket() const = 0;
    virtual ETransportLayerProtocol protocol() const = 0;

    virtual bool is_busy(EPipeOperation op) const = 0;
    virtual void set_busy(EPipeOperation op, bool busy) = 0;

    virtual bool open(const char* hostname, const char* port) = 0;
    virtual bool open(uint64_t socket) = 0;

    virtual void close() = 0;
    virtual void error(ESocketErrorReason reason) = 0;

    virtual bool notify_all() = 0;

    virtual bool sync(uint64_t wait_time = 0) = 0;

    virtual bool bind_and_listen(const char* addr = nullptr, uint32_t backlog = 0x7FFFFFFF) = 0;
    virtual bool connect(uint64_t timeout = 0, const NetworkFlowSpec* recv_flowspec = nullptr, const NetworkFlowSpec* send_flowspec = nullptr) = 0;

    // Blocking call to check for alive connection
    virtual bool ping() = 0;
    virtual bool recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) = 0;

    // Application surrenders ownership of the buffer
    virtual bool send(const char* data, uint32_t size, uint32_t* flags) = 0;

    // --------------------

    virtual char* recv_buf() const = 0;
    virtual uint32_t recv_buf_size() const = 0;
    virtual char* send_buf() const = 0;
    virtual uint32_t send_buf_size() const = 0;

    virtual void set_recv_buf(char* buf) = 0;
    virtual void set_recv_buf_size(uint32_t size) = 0;
    virtual void set_send_buf(const char* buf) = 0;
    virtual void set_send_buf_size(uint32_t size) = 0;

    virtual ISocketIOResult *wait_results() = 0;

    virtual void* sys_data() const = 0;
    virtual void* user_data() const = 0;

    // --------------------

    virtual void on_close(close_cb cb) = 0;
    virtual void on_error(error_cb cb) = 0;
  };

  class SocketOSSupportLayerFactory {
  public:
    static bool initialize(uint64_t socket);
    static ISocketOSSupportLayer* create(netpp::ISocketOSSupportLayer* owner_socker_layer,
      netpp::StaticBlockAllocator* recv_allocator, netpp::StaticBlockAllocator* send_allocator,
      ETransportLayerProtocol protocol, ESocketHint hint);
    static bool deinitialize();
  };

  class IServer;

  class ISocketPipe {
  public:
    using close_callback = std::function<bool(ISocketPipe*)>;
    using error_callback = std::function<bool(ISocketPipe*, ESocketErrorReason reason)>;
    using dns_request_callback = std::function<DNS_Response* (const ISocketPipe* source, const DNS_Request* request)>;
    using dns_response_callback = std::function<DNS_Request* (const ISocketPipe* source, const DNS_Response* response)>;
    using http_request_callback = std::function<HTTP_Response* (const ISocketPipe* source, const HTTP_Request* request)>;
    using http_response_callback = std::function<HTTP_Request* (const ISocketPipe* source, const HTTP_Response* response)>;
    using raw_receive_callback = std::function<RawPacket* (const ISocketPipe* source, const RawPacket* packet)>;
    using rtp_packet_callback = std::function<void(const ISocketPipe* source, const RTP_Packet* packet)>;
    using rtcp_packet_callback = std::function<void(const ISocketPipe* source, const RTCP_Packet* packet)>;
    using sip_request_callback = std::function<SIP_Response* (const ISocketPipe* source, const SIP_Request* request)>;
    using sip_response_callback = std::function<SIP_Request* (const ISocketPipe* source, const SIP_Response* response)>;

    virtual ~ISocketPipe() = default;

    virtual uint64_t socket() const = 0;

    virtual const std::string& hostname() const = 0;
    virtual const std::string& port() const = 0;

    virtual bool is_busy(EPipeOperation op) const = 0;

    virtual bool open(const char* hostname, const char* port) = 0;
    virtual bool open(uint64_t sockets) = 0;
    virtual void close() = 0;
    virtual void error(ESocketErrorReason reason) = 0;

    virtual bool notify_all() = 0;

    // Not recommended, only use if absolutely necessary.
    // Favor async programming instead.
    virtual bool sync(uint64_t wait_time = 0) = 0;

    virtual bool bind_and_listen(const char* addr = nullptr, uint32_t backlog = 0x7FFFFFFF) = 0;
    virtual bool connect(uint64_t timeout = 0, const NetworkFlowSpec* recv_flowspec = nullptr, const NetworkFlowSpec* send_flowspec = nullptr) = 0;

    // Blocking call to check for alive connection
    virtual bool ping() = 0;
    virtual bool recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) = 0;

    // Application surrenders ownership of the buffer
    virtual bool send(const char* data, uint32_t size, uint32_t* flags) = 0;
    virtual bool send(const HTTP_Request* request) = 0;
    virtual bool send(const HTTP_Response* response) = 0;

    // Application surrenders ownership of the buffer
    virtual bool send(const RawPacket* packet) = 0;

    virtual bool proc_post_recv(char* out_data, uint32_t out_size, const char* in_data, uint32_t in_size) = 0;

    virtual void on_close(close_callback cb) = 0;
    virtual void on_error(error_callback cb) = 0;
    virtual void on_dns_request(dns_request_callback cb) = 0;
    virtual void on_dns_response(dns_response_callback cb) = 0;
    virtual void on_http_request(http_request_callback cb) = 0;
    virtual void on_http_response(http_response_callback cb) = 0;
    virtual void on_raw_receive(raw_receive_callback cb) = 0;
    virtual void on_rtp_packet(rtp_packet_callback) = 0;
    virtual void on_rtcp_packet(rtcp_packet_callback) = 0;
    virtual void on_sip_request(sip_request_callback) = 0;
    virtual void on_sip_response(sip_response_callback) = 0;
    virtual void clone_callbacks_from(ISocketPipe* other) = 0;

    virtual const DNS_Response* signal_dns_request(const DNS_Request* request) = 0;
    virtual const DNS_Request* signal_dns_response(const DNS_Response* response) = 0;
    virtual const HTTP_Response* signal_http_request(const HTTP_Request* request) = 0;
    virtual const HTTP_Request* signal_http_response(const HTTP_Response* response) = 0;
    virtual const RawPacket* signal_raw_receive(const RawPacket* packet) = 0;
    virtual void signal_rtp_packet(const RTP_Packet* packet) = 0;
    virtual void signal_rtcp_packet(const RTCP_Packet* packet) = 0;
    virtual const SIP_Response* signal_sip_request(const SIP_Request* request) = 0;
    virtual const SIP_Request* signal_sip_response(const SIP_Response* response) = 0;

    virtual ISocketIOResult* wait_results() = 0;

    virtual void* sys_data() const = 0;
    virtual void* user_data() const = 0;

    virtual ISocketOSSupportLayer* get_os_layer() const = 0;

    static inline bool is_ping_packet(const char* buf, size_t size) {
      return *(uint64_t*)buf == *(uint64_t*)"\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF";
    }
  };

  /// <summary>
  /// Implements TCP socket functionality
  /// </summary>
  class TCP_Socket : public ISocketPipe {
  public:
    TCP_Socket(ISocketOSSupportLayer* owner_socket_layer,
      StaticBlockAllocator* recv_allocator, StaticBlockAllocator* send_allocator, ESocketHint hint = ESocketHint::E_NONE);

    ~TCP_Socket() override {}

    uint64_t socket() const override { return m_socket_layer->socket(); }

    const std::string& hostname() const override { return m_host_name; }
    const std::string& port() const override { return m_port; }

    bool is_busy(EPipeOperation op) const override { return m_socket_layer->is_busy(op); }

    bool open(const char* hostname, const char* port) override;
    bool open(uint64_t socket) override;

    void close() override;
    void error(ESocketErrorReason reason) override { m_socket_layer->error(reason); }

    bool notify_all() override { return m_socket_layer->notify_all(); }

    bool sync(uint64_t wait_time = 0) override { return m_socket_layer->sync(); }

    bool bind_and_listen(const char* addr = nullptr, uint32_t backlog = 0x7FFFFFFF) override {
      return m_socket_layer->bind_and_listen(addr, backlog);
    }

    bool connect(uint64_t timeout = 0, const NetworkFlowSpec* recv_flowspec = nullptr, const NetworkFlowSpec* send_flowspec = nullptr) override {
      return m_socket_layer->connect(timeout, recv_flowspec, send_flowspec);
    }

    // Blocking call to check for alive connection
    bool ping() override;
    bool recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) override;

    // Application surrenders ownership of the buffer
    bool send(const char* data, uint32_t size, uint32_t* flags) override { return m_socket_layer->send(data, size, flags); }
    bool send(const HTTP_Request* request) override;
    bool send(const HTTP_Response* response) override;

    // Application surrenders ownership of the buffer
    bool send(const RawPacket* packet) override;

    bool proc_post_recv(char* out_data, uint32_t out_size, const char* in_data, uint32_t in_size) override { return true; }

    void on_close(close_callback cb) override {
      m_socket_layer->on_close([this, cb](ISocketOSSupportLayer*) {
        return cb(this);
        });
    }
    void on_error(error_callback cb) override {
      m_socket_layer->on_error([this, cb](ISocketOSSupportLayer*, ESocketErrorReason reason) {
        return cb(this, reason);
        });
    }

    void on_dns_request(dns_request_callback cb) override { m_signal_dns_request = cb; }
    void on_dns_response(dns_response_callback cb) override { m_signal_dns_response = cb; }
    void on_http_request(http_request_callback cb) override { m_signal_http_request = cb; }
    void on_http_response(http_response_callback cb) override { m_signal_http_response = cb; }
    void on_raw_receive(raw_receive_callback cb) override { m_signal_raw_receive = cb; }
    void on_rtp_packet(rtp_packet_callback cb) override { m_signal_rtp_packet = cb; }
    void on_rtcp_packet(rtcp_packet_callback cb) override { m_signal_rtcp_packet = cb; }
    void on_sip_request(sip_request_callback cb) override { m_signal_sip_request = cb; }
    void on_sip_response(sip_response_callback cb) override { m_signal_sip_response = cb; }
    void clone_callbacks_from(ISocketPipe* other) override;

    const DNS_Response* signal_dns_request(const DNS_Request* request) override { return m_signal_dns_request(this, request); }
    const DNS_Request* signal_dns_response(const DNS_Response* response) override { return m_signal_dns_response(this, response); }
    const HTTP_Response* signal_http_request(const HTTP_Request* request) override { return m_signal_http_request(this, request); }
    const HTTP_Request* signal_http_response(const HTTP_Response* response) override { return m_signal_http_response(this, response); }
    const RawPacket* signal_raw_receive(const RawPacket* packet) override { return m_signal_raw_receive(this, packet); }
    void signal_rtp_packet(const RTP_Packet* packet) override { m_signal_rtp_packet(this, packet); }
    void signal_rtcp_packet(const RTCP_Packet* packet) override { m_signal_rtcp_packet(this, packet); }
    const SIP_Response* signal_sip_request(const SIP_Request* request) override { return m_signal_sip_request(this, request); }
    const SIP_Request* signal_sip_response(const SIP_Response* response) override { return m_signal_sip_response(this, response); }

    ISocketIOResult* wait_results() override { return m_socket_layer->wait_results(); }

    void* sys_data() const override { return m_socket_layer->sys_data(); }
    void* user_data() const override { return m_socket_layer->user_data(); }

    ISocketOSSupportLayer* get_os_layer() const { return m_socket_layer; }

  private:
    std::string m_host_name;
    std::string m_port;

    dns_request_callback m_signal_dns_request;
    dns_response_callback m_signal_dns_response;
    http_request_callback m_signal_http_request;
    http_response_callback m_signal_http_response;
    raw_receive_callback m_signal_raw_receive;
    rtp_packet_callback m_signal_rtp_packet;
    rtcp_packet_callback m_signal_rtcp_packet;
    sip_request_callback m_signal_sip_request;
    sip_response_callback m_signal_sip_response;

    std::mutex m_mutex;

    uint32_t m_recv_buf_block;
    uint32_t m_send_buf_block;

    ESocketHint m_hint = ESocketHint::E_NONE;
    ISocketOSSupportLayer* m_socket_layer;
  };

  /// <summary>
  /// Implements UDP socket functionality
  /// </summary>
  class UDP_Socket : public ISocketPipe {
  public:
    UDP_Socket(ISocketOSSupportLayer* owner_socket_layer,
      StaticBlockAllocator* recv_allocator, StaticBlockAllocator* send_allocator, ESocketHint hint = ESocketHint::E_NONE);

    ~UDP_Socket() override {}

    uint64_t socket() const override { return m_socket_layer->socket(); }

    const std::string& hostname() const override { return m_host_name; }
    const std::string& port() const override { return m_port; }

    bool is_busy(EPipeOperation op) const override { return m_socket_layer->is_busy(op); }

    bool open(const char* hostname, const char* port) override;
    void close() override;
    void error(ESocketErrorReason reason) override { m_socket_layer->error(reason); }

    bool notify_all() override { return m_socket_layer->notify_all(); }

    bool sync(uint64_t wait_time = 0) override { return m_socket_layer->sync(); }

    bool bind_and_listen(const char* addr = nullptr, uint32_t backlog = 0x7FFFFFFF) override {
      return m_socket_layer->bind_and_listen(addr, backlog);
    }

    bool connect(uint64_t timeout = 0, const NetworkFlowSpec* recv_flowspec = nullptr, const NetworkFlowSpec* send_flowspec = nullptr) override {
      return m_socket_layer->connect(timeout, recv_flowspec, send_flowspec);
    }

    // Blocking call to check for alive connection
    bool ping() override;
    bool recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) override;

    // Application surrenders ownership of the buffer
    bool send(const char* data, uint32_t size, uint32_t* flags) override { return m_socket_layer->send(data, size, flags); }
    bool send(const HTTP_Request* request) override;
    bool send(const HTTP_Response* response) override;

    // Application surrenders ownership of the buffer
    bool send(const RawPacket* packet) override;

    bool proc_post_recv(char* out_data, uint32_t out_size, const char* in_data, uint32_t in_size) override { return true; }

    void on_close(close_callback cb) override {
      m_socket_layer->on_close([this, cb](ISocketOSSupportLayer*) {
        return cb(this);
        });
    }
    void on_error(error_callback cb) override {
      m_socket_layer->on_error([this, cb](ISocketOSSupportLayer*, ESocketErrorReason reason) {
        return cb(this, reason);
        });
    }

    void on_dns_request(dns_request_callback cb) override { m_signal_dns_request = cb; }
    void on_dns_response(dns_response_callback cb) override { m_signal_dns_response = cb; }
    void on_http_request(http_request_callback cb) override { m_signal_http_request = cb; }
    void on_http_response(http_response_callback cb) override { m_signal_http_response = cb; }
    void on_raw_receive(raw_receive_callback cb) override { m_signal_raw_receive = cb; }
    void on_rtp_packet(rtp_packet_callback cb) override { m_signal_rtp_packet = cb; }
    void on_rtcp_packet(rtcp_packet_callback cb) override { m_signal_rtcp_packet = cb; }
    void on_sip_request(sip_request_callback cb) override { m_signal_sip_request = cb; }
    void on_sip_response(sip_response_callback cb) override { m_signal_sip_response = cb; }
    void clone_callbacks_from(ISocketPipe* other) override;

    const DNS_Response* signal_dns_request(const DNS_Request* request) override { return m_signal_dns_request(this, request); }
    const DNS_Request* signal_dns_response(const DNS_Response* response) override { return m_signal_dns_response(this, response); }
    const HTTP_Response* signal_http_request(const HTTP_Request* request) override { return m_signal_http_request(this, request); }
    const HTTP_Request* signal_http_response(const HTTP_Response* response) override { return m_signal_http_response(this, response); }
    const RawPacket* signal_raw_receive(const RawPacket* packet) override { return m_signal_raw_receive(this, packet); }
    void signal_rtp_packet(const RTP_Packet* packet) override { m_signal_rtp_packet(this, packet); }
    void signal_rtcp_packet(const RTCP_Packet* packet) override { m_signal_rtcp_packet(this, packet); }
    const SIP_Response* signal_sip_request(const SIP_Request* request) override { return m_signal_sip_request(this, request); }
    const SIP_Request* signal_sip_response(const SIP_Response* response) override { return m_signal_sip_response(this, response); }

    ISocketIOResult* wait_results() override { return m_socket_layer->wait_results(); }

    void* sys_data() const override { return m_socket_layer->sys_data(); }
    void* user_data() const override { return m_socket_layer->user_data(); }

    ISocketOSSupportLayer* get_os_layer() const { return m_socket_layer; }

  private:
    std::string m_host_name;
    std::string m_port;

    dns_request_callback m_signal_dns_request;
    dns_response_callback m_signal_dns_response;
    http_request_callback m_signal_http_request;
    http_response_callback m_signal_http_response;
    raw_receive_callback m_signal_raw_receive;
    rtp_packet_callback m_signal_rtp_packet;
    rtcp_packet_callback m_signal_rtcp_packet;
    sip_request_callback m_signal_sip_request;
    sip_response_callback m_signal_sip_response;

    std::mutex m_mutex;

    uint32_t m_recv_buf_block;
    uint32_t m_send_buf_block;

    ESocketHint m_hint = ESocketHint::E_NONE;
    ISocketOSSupportLayer* m_socket_layer;
  };

  /// <summary>
  /// Uses AES-256 standard AES-GCM encryption for the TLS layer.
  /// It also acts as a proxy layer for an internal socket provided by the constructor argument.
  /// </summary>
  class TLS_SocketProxy : public ISocketPipe {
  public:
    inline static const size_t key_size = 32;  // AES-256
    inline static const size_t iv_size = 12;   // IV size for AES-GCM
    inline static const size_t tag_size = 16;  // Auth tag size

    TLS_SocketProxy(ISocketPipe* pipe, uint8_t* aes_key = nullptr) : m_pipe(pipe) {
      if (aes_key) {
        memmove(m_aes_key, aes_key, key_size);
      }
    }

    ~TLS_SocketProxy() override { delete m_pipe; }

    uint64_t socket() const override { return m_pipe->socket(); }

    const std::string& hostname() const override { return m_pipe->hostname(); }
    const std::string& port() const override { return m_pipe->port(); }

    bool is_busy(EPipeOperation op) const override { return m_pipe->is_busy(op); }

    bool open(const char* hostname, const char* port) override;
    void close() override;
    void error(ESocketErrorReason reason) override { m_pipe->error(reason); }

    bool sync(uint64_t wait_time = 0) override { return m_pipe->sync(); }

    bool recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) override;

    // Application surrenders ownership of the buffer
    bool send(const char* data, uint32_t size, uint32_t* flags) override;
    bool send(const HTTP_Request* request) override;
    bool send(const HTTP_Response* response) override;

    // Application surrenders ownership of the buffer
    bool send(const RawPacket* packet) override;

    bool proc_post_recv(char* out_data, uint32_t out_size, const char* in_data, uint32_t in_size) override;

    void on_close(close_callback cb) override { m_pipe->on_close(cb); }
    void on_error(error_callback cb) override { m_pipe->on_error(cb); }
    void on_dns_request(dns_request_callback cb) override { m_pipe->on_dns_request(cb); }
    void on_dns_response(dns_response_callback cb) override { m_pipe->on_dns_response(cb); }
    void on_http_request(http_request_callback cb) override { m_pipe->on_http_request(cb); }
    void on_http_response(http_response_callback cb) override { m_pipe->on_http_response(cb); }
    void on_raw_receive(raw_receive_callback cb) override { m_pipe->on_raw_receive(cb); }
    void on_rtp_packet(rtp_packet_callback cb) override { m_pipe->on_rtp_packet(cb); }
    void on_rtcp_packet(rtcp_packet_callback cb) override { m_pipe->on_rtcp_packet(cb); }
    void on_sip_request(sip_request_callback cb) override { m_pipe->on_sip_request(cb); }
    void on_sip_response(sip_response_callback cb) override { m_pipe->on_sip_response(cb); }

    const DNS_Response* signal_dns_request(const DNS_Request* request) override { return m_pipe->signal_dns_request(request); }
    const DNS_Request* signal_dns_response(const DNS_Response* response) override { return m_pipe->signal_dns_response(response); }
    const HTTP_Response* signal_http_request(const HTTP_Request* request) override { return m_pipe->signal_http_request(request); }
    const HTTP_Request* signal_http_response(const HTTP_Response* response) override { return m_pipe->signal_http_response(response); }
    const RawPacket* signal_raw_receive(const RawPacket* packet) override { return m_pipe->signal_raw_receive(packet); }
    void signal_rtp_packet(const RTP_Packet* packet) override { m_pipe->signal_rtp_packet(packet); }
    void signal_rtcp_packet(const RTCP_Packet* packet) override { m_pipe->signal_rtcp_packet(packet); }
    const SIP_Response* signal_sip_request(const SIP_Request* request) override { return m_pipe->signal_sip_request(request); }
    const SIP_Request* signal_sip_response(const SIP_Response* response) override { return m_pipe->signal_sip_response(response); }

    void* sys_data() const override { return m_pipe->sys_data(); }
    void* user_data() const override { return m_pipe->user_data(); }

    ISocketOSSupportLayer* get_os_layer() const { return m_pipe->get_os_layer(); }

  private:
    ISocketPipe* m_pipe;
    uint8_t m_aes_key[key_size] = {};
  };

  bool sockets_initialize();
  void sockets_deinitialize();

}  // namespace netpp
