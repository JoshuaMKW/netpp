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

#include "netpp.h"
#include "allocator.h"
#include "network.h"
#include "protocol.h"
#include "security.h"
#include "http/request.h"
#include "http/response.h"
#include "platform/socket.h"

namespace netpp {

  class ISocketPipe;
  class ISecurityController;
  class ISecurityFactory;

  struct SocketIOInfo {
    ISocketPipe* m_pipe;

    SocketIOState m_recv_state;
    SocketIOState m_send_state;

    EPipeOperation m_last_op;

    bool m_proc_handshake;
  };

  struct SocketProcData {
    SocketProcData() {
      m_pipe = nullptr;
      m_proc_buf = nullptr;
      m_bytes_total = 0;
      m_bytes_processed = 0;
    }

    SocketProcData(ISocketPipe* pipe) {
      m_pipe = pipe;
      m_proc_buf = nullptr;
      m_bytes_total = 0;
      m_bytes_processed = 0;
    }

    ISocketPipe* m_pipe;
    char* m_proc_buf;
    uint32_t m_bytes_processed;
    uint32_t m_bytes_total;
  };

  class NETPP_API ISocketPipe {
  public:
    using close_cb = std::function<bool(ISocketPipe*)>;
    using error_cb = std::function<bool(ISocketPipe*, ESocketErrorReason reason)>;
    using dns_request_cb = std::function<DNS_Response* (const ISocketPipe* source, const DNS_Request* request)>;
    using dns_response_cb = std::function<DNS_Request* (const ISocketPipe* source, const DNS_Response* response)>;
    using http_request_cb = std::function<HTTP_Response* (const ISocketPipe* source, const HTTP_Request* request)>;
    using http_response_cb = std::function<HTTP_Request* (const ISocketPipe* source, const HTTP_Response* response)>;
    using raw_receive_cb = std::function<RawPacket* (const ISocketPipe* source, const RawPacket* packet)>;
    using rtp_packet_cb = std::function<void(const ISocketPipe* source, const RTP_Packet* packet)>;
    using rtcp_packet_cb = std::function<void(const ISocketPipe* source, const RTCP_Packet* packet)>;
    using sip_request_cb = std::function<SIP_Response* (const ISocketPipe* source, const SIP_Request* request)>;
    using sip_response_cb = std::function<SIP_Request* (const ISocketPipe* source, const SIP_Response* response)>;

    using accept_cb = ISocketOSSupportLayer::accept_cb;
    using accept_cond_cb = ISocketOSSupportLayer::accept_cond_cb;

    virtual ~ISocketPipe() = default;

    virtual uint64_t socket() const = 0;

    virtual const std::string& hostname() const = 0;
    virtual const std::string& port() const = 0;

    // Cast to ESecurityProtocol when using defaults
    virtual int security() const = 0;

    virtual bool is_server() const = 0;
    virtual bool is_ready(EPipeOperation op) const = 0;
    virtual bool is_busy(EPipeOperation op) const = 0;

    virtual bool open(const char* hostname, const char* port) = 0;
    virtual bool open(uint64_t sockets) = 0;
    virtual void close() = 0;
    virtual void error(ESocketErrorReason reason) = 0;

    virtual bool notify_all() = 0;

    // Not recommended, only use if absolutely necessary.
    // Favor async programming instead.
    // Return value is how many bytes were transferred or -1 on error.
    virtual int64_t sync(EPipeOperation op = EPipeOperation::E_RECV_SEND, uint64_t wait_time = 0) = 0;

    virtual SocketLock acquire_lock() = 0;

    virtual bool accept(accept_cond_cb accept_cond, accept_cb accept_routine) = 0;
    virtual bool bind(const char* addr = nullptr) = 0;
    virtual bool listen(uint32_t backlog = 0x7FFFFFFF) = 0;
    virtual bool connect(uint64_t timeout = 0, const NetworkFlowSpec* recv_flowspec = nullptr, const NetworkFlowSpec* send_flowspec = nullptr) = 0;

    virtual EIOState recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) = 0;

    virtual EIOState send(const char* data, uint32_t size, uint32_t* flags) = 0;
    virtual EIOState send(const HTTP_Request* request) = 0;
    virtual EIOState send(const HTTP_Response* response) = 0;
    virtual EIOState send(const RawPacket* packet) = 0;

    virtual void on_close(close_cb cb) = 0;
    virtual void on_error(error_cb cb) = 0;
    virtual void on_dns_request(dns_request_cb cb) = 0;
    virtual void on_dns_response(dns_response_cb cb) = 0;
    virtual void on_http_request(http_request_cb cb) = 0;
    virtual void on_http_response(http_response_cb cb) = 0;
    virtual void on_raw_receive(raw_receive_cb cb) = 0;
    virtual void on_rtp_packet(rtp_packet_cb) = 0;
    virtual void on_rtcp_packet(rtcp_packet_cb) = 0;
    virtual void on_sip_request(sip_request_cb) = 0;
    virtual void on_sip_response(sip_response_cb) = 0;
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

    virtual EAuthState proc_pending_auth(EPipeOperation last_op, int32_t post_transferred) = 0;
    virtual int32_t proc_post_recv(char** out_data, const char* in_data, uint32_t in_size) = 0;

    virtual const SocketIOInfo& get_io_info() const = 0;
    virtual ISocketOSSupportLayer* get_os_layer() const = 0;

    static inline bool is_ping_packet(const char* buf, size_t size) {
      return *(uint64_t*)buf == *(uint64_t*)"\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF";
    }
  };

  /// <summary>
  /// Implements TCP socket functionality
  /// </summary>
  class NETPP_API TCP_Socket : public ISocketPipe {
  public:
    TCP_Socket(ISocketPipe* root_socket,
      StaticBlockAllocator* recv_allocator, StaticBlockAllocator* send_allocator,
      ISecurityController* security = nullptr, ESocketHint hint = ESocketHint::E_NONE);

    ~TCP_Socket() override {}

    uint64_t socket() const override { return m_socket_layer->socket(); }

    const std::string& hostname() const override { return m_host_name; }
    const std::string& port() const override { return m_port; }

    int security() const override { return m_security->protocol(); }

    bool is_server() const override { return m_socket_layer->is_server(); }
    bool is_ready(EPipeOperation op) const override { return m_socket_layer->is_ready(op); }
    bool is_busy(EPipeOperation op) const override { return m_socket_layer->is_busy(op); }

    bool open(const char* hostname, const char* port) override;
    bool open(uint64_t socket) override;

    void close() override;
    void error(ESocketErrorReason reason) override { m_socket_layer->error(reason); }

    bool notify_all() override { return m_socket_layer->notify_all(); }

    int64_t sync(EPipeOperation op = EPipeOperation::E_RECV_SEND, uint64_t wait_time = 0) override { return m_socket_layer->sync(op, wait_time); }

    SocketLock acquire_lock() override { return m_socket_layer->acquire_lock(); }

    bool accept(accept_cond_cb accept_cond, accept_cb accept_routine) override;

    bool bind(const char* addr = nullptr) override {
      return m_socket_layer->bind(addr);
    }

    bool listen(uint32_t backlog = 0x7FFFFFFF) override {
      return m_socket_layer->listen(backlog);
    }

    bool connect(uint64_t timeout = 0, const NetworkFlowSpec* recv_flowspec = nullptr, const NetworkFlowSpec* send_flowspec = nullptr) override;

    EIOState recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) override;

    EIOState send(const char* data, uint32_t size, uint32_t* flags) override;
    EIOState send(const HTTP_Request* request) override;
    EIOState send(const HTTP_Response* response) override;
    EIOState send(const RawPacket* packet) override;

    void on_close(close_cb cb) override {
      m_socket_layer->on_close([this, cb](ISocketOSSupportLayer* os_layer) {
        TCP_Socket* the_socket = reinterpret_cast<TCP_Socket*>(os_layer->user_data());
        return cb(the_socket);
        });
    }
    void on_error(error_cb cb) override {
      m_socket_layer->on_error([this, cb](ISocketOSSupportLayer* os_layer, ESocketErrorReason reason) {
        TCP_Socket* the_socket = reinterpret_cast<TCP_Socket*>(os_layer->user_data());
        return cb(the_socket, reason);
        });
    }

    void on_dns_request(dns_request_cb cb) override { m_signal_dns_request = cb; }
    void on_dns_response(dns_response_cb cb) override { m_signal_dns_response = cb; }
    void on_http_request(http_request_cb cb) override { m_signal_http_request = cb; }
    void on_http_response(http_response_cb cb) override { m_signal_http_response = cb; }
    void on_raw_receive(raw_receive_cb cb) override { m_signal_raw_receive = cb; }
    void on_rtp_packet(rtp_packet_cb cb) override { m_signal_rtp_packet = cb; }
    void on_rtcp_packet(rtcp_packet_cb cb) override { m_signal_rtcp_packet = cb; }
    void on_sip_request(sip_request_cb cb) override { m_signal_sip_request = cb; }
    void on_sip_response(sip_response_cb cb) override { m_signal_sip_response = cb; }
    void clone_callbacks_from(ISocketPipe* other) override;

    const DNS_Response* signal_dns_request(const DNS_Request* request) override { return m_signal_dns_request ? m_signal_dns_request(this, request) : nullptr; }
    const DNS_Request* signal_dns_response(const DNS_Response* response) override {
      return m_signal_dns_response ? m_signal_dns_response(this, response) : nullptr;
    }
    const HTTP_Response* signal_http_request(const HTTP_Request* request) override { return m_signal_http_request ? m_signal_http_request(this, request) : nullptr; }
    const HTTP_Request* signal_http_response(const HTTP_Response* response) override { return m_signal_http_response ? m_signal_http_response(this, response) : nullptr; }
    const RawPacket* signal_raw_receive(const RawPacket* packet) override { return m_signal_raw_receive ? m_signal_raw_receive(this, packet) : nullptr; }
    void signal_rtp_packet(const RTP_Packet* packet) override { if (m_signal_rtp_packet) m_signal_rtp_packet(this, packet); }
    void signal_rtcp_packet(const RTCP_Packet* packet) override { if (m_signal_rtcp_packet) m_signal_rtcp_packet(this, packet); }
    const SIP_Response* signal_sip_request(const SIP_Request* request) override { return m_signal_sip_request ? m_signal_sip_request(this, request) : nullptr; }
    const SIP_Request* signal_sip_response(const SIP_Response* response) override { return m_signal_sip_response ? m_signal_sip_response(this, response) : nullptr; }

    ISocketIOResult* wait_results() override { return m_socket_layer->wait_results(); }

    void* sys_data() const override { return m_socket_layer->sys_data(); }
    void* user_data() const override { return m_socket_layer->user_data(); }

    EAuthState proc_pending_auth(EPipeOperation last_op, int32_t post_transferred) override;
    int32_t proc_post_recv(char** out_data, const char* in_data, uint32_t in_size) override;

    const SocketIOInfo& get_io_info() const override { return m_io_info; }
    ISocketOSSupportLayer* get_os_layer() const { return m_socket_layer; }

  private:
    std::string m_host_name;
    std::string m_port;

    dns_request_cb m_signal_dns_request;
    dns_response_cb m_signal_dns_response;
    http_request_cb m_signal_http_request;
    http_response_cb m_signal_http_response;
    raw_receive_cb m_signal_raw_receive;
    rtp_packet_cb m_signal_rtp_packet;
    rtcp_packet_cb m_signal_rtcp_packet;
    sip_request_cb m_signal_sip_request;
    sip_response_cb m_signal_sip_response;

    std::mutex m_mutex;

    SocketIOInfo m_io_info;
    uint32_t m_recv_buf_block;
    uint32_t m_send_buf_block;

    ESocketHint m_hint = ESocketHint::E_NONE;
    ISocketOSSupportLayer* m_socket_layer;

    ISecurityController* m_security;
  };

  /// <summary>
  /// Implements UDP socket functionality
  /// </summary>
  class NETPP_API UDP_Socket : public ISocketPipe {
  public:
    UDP_Socket(ISocketPipe* root_socket,
      StaticBlockAllocator* recv_allocator, StaticBlockAllocator* send_allocator,
      ISecurityController* security = nullptr, ESocketHint hint = ESocketHint::E_NONE);

    ~UDP_Socket() override {}

    uint64_t socket() const override { return m_socket_layer->socket(); }

    const std::string& hostname() const override { return m_host_name; }
    const std::string& port() const override { return m_port; }

    int security() const override { return m_security->protocol(); }

    bool is_server() const override { return m_socket_layer->is_server(); }
    bool is_ready(EPipeOperation op) const override { return m_socket_layer->is_ready(op); }
    bool is_busy(EPipeOperation op) const override { return m_socket_layer->is_busy(op); }

    bool open(const char* hostname, const char* port) override;
    bool open(uint64_t socket) override;
    void close() override;
    void error(ESocketErrorReason reason) override { m_socket_layer->error(reason); }

    bool notify_all() override { return m_socket_layer->notify_all(); }

    int64_t sync(EPipeOperation op = EPipeOperation::E_RECV_SEND, uint64_t wait_time = 0) override { return m_socket_layer->sync(op, wait_time); }

    SocketLock acquire_lock() override { return m_socket_layer->acquire_lock(); }

    bool accept(accept_cond_cb accept_cond, accept_cb accept_routine) override;

    bool bind(const char* addr = nullptr) override {
      return m_socket_layer->bind(addr);
    }

    bool listen(uint32_t backlog = 0x7FFFFFFF) override {
      return m_socket_layer->listen(backlog);
    }

    bool connect(uint64_t timeout = 0, const NetworkFlowSpec* recv_flowspec = nullptr, const NetworkFlowSpec* send_flowspec = nullptr) override;

    EIOState recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) override;

    // Application surrenders ownership of the buffer
    EIOState send(const char* data, uint32_t size, uint32_t* flags) override;
    EIOState send(const HTTP_Request* request) override;
    EIOState send(const HTTP_Response* response) override;

    // Application surrenders ownership of the buffer
    EIOState send(const RawPacket* packet) override;

    void on_close(close_cb cb) override {
      m_socket_layer->on_close([this, cb](ISocketOSSupportLayer*) {
        return cb(this);
        });
    }
    void on_error(error_cb cb) override {
      m_socket_layer->on_error([this, cb](ISocketOSSupportLayer*, ESocketErrorReason reason) {
        return cb(this, reason);
        });
    }

    void on_dns_request(dns_request_cb cb) override { m_signal_dns_request = cb; }
    void on_dns_response(dns_response_cb cb) override { m_signal_dns_response = cb; }
    void on_http_request(http_request_cb cb) override { m_signal_http_request = cb; }
    void on_http_response(http_response_cb cb) override { m_signal_http_response = cb; }
    void on_raw_receive(raw_receive_cb cb) override { m_signal_raw_receive = cb; }
    void on_rtp_packet(rtp_packet_cb cb) override { m_signal_rtp_packet = cb; }
    void on_rtcp_packet(rtcp_packet_cb cb) override { m_signal_rtcp_packet = cb; }
    void on_sip_request(sip_request_cb cb) override { m_signal_sip_request = cb; }
    void on_sip_response(sip_response_cb cb) override { m_signal_sip_response = cb; }
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

    EAuthState proc_pending_auth(EPipeOperation last_op, int32_t post_transferred) override;
    int32_t proc_post_recv(char** out_data, const char* in_data, uint32_t in_size) override;

    const SocketIOInfo& get_io_info() const override { return m_io_info; }
    ISocketOSSupportLayer* get_os_layer() const { return m_socket_layer; }

  private:
    std::string m_host_name;
    std::string m_port;

    dns_request_cb m_signal_dns_request;
    dns_response_cb m_signal_dns_response;
    http_request_cb m_signal_http_request;
    http_response_cb m_signal_http_response;
    raw_receive_cb m_signal_raw_receive;
    rtp_packet_cb m_signal_rtp_packet;
    rtcp_packet_cb m_signal_rtcp_packet;
    sip_request_cb m_signal_sip_request;
    sip_response_cb m_signal_sip_response;

    std::mutex m_mutex;

    SocketIOInfo m_io_info;
    uint32_t m_recv_buf_block;
    uint32_t m_send_buf_block;

    ESocketHint m_hint = ESocketHint::E_NONE;
    ISocketOSSupportLayer* m_socket_layer;

    ISecurityController* m_security;
  };

  bool sockets_initialize();
  void sockets_deinitialize();

}  // namespace netpp
