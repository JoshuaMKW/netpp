#pragma once

#include <functional>
#include <mutex>
#include <string>

#include "netpp.h"
#include "allocator.h"
#include "network.h"
#include "protocol.h"
#include "http/request.h"
#include "http/response.h"
#include "security.h"
#include "socket.h"

#include <openssl\ssl.h>

namespace netpp {

  /// <summary>
  /// Uses AES-256 standard AES-GCM encryption for the TLS layer.
  /// It also acts as a proxy layer for an internal socket provided by the constructor argument.
  /// </summary>
  class NETPP_API TLS_SocketProxy : public ISocketPipe {
  public:
    inline static const size_t key_size = 32;  // AES-256
    inline static const size_t iv_size = 12;   // IV size for AES-GCM
    inline static const size_t tag_size = 16;  // Auth tag size
    inline static const size_t record_size = 5;  // TLS-record size

    TLS_SocketProxy(ISocketPipe* pipe, const ISecurityController* security);
    ~TLS_SocketProxy() override { delete m_pipe; }

    uint64_t socket() const override { return m_pipe->socket(); }

    const std::string& hostname() const override { return m_pipe->hostname(); }
    const std::string& port() const override { return m_pipe->port(); }

    bool is_server() const override { return m_pipe->is_server(); }
    bool is_ready(EPipeOperation op) const override { return m_pipe->is_ready(op); }
    bool is_busy(EPipeOperation op) const override { return m_pipe->is_busy(op); }

    bool open(const char* hostname, const char* port) override;
    bool open(uint64_t socket) override;

    void close() override;
    void error(ESocketErrorReason reason) override { m_pipe->error(reason); }

    bool notify_all() override { return m_pipe->notify_all(); }

    int64_t sync(EPipeOperation op = EPipeOperation::E_RECV_SEND, uint64_t wait_time = 0) override { return m_pipe->sync(op, wait_time); }

    SocketLock acquire_lock() override { return m_pipe->acquire_lock(); }

    bool accept(accept_cond_cb accept_cond, accept_cb accept_routine) override;

    bool bind_and_listen(const char* addr = nullptr, uint32_t backlog = 0x7FFFFFFF) override {
      return m_pipe->bind_and_listen(addr, backlog);
    }

    bool connect(uint64_t timeout = 0, const NetworkFlowSpec* recv_flowspec = nullptr, const NetworkFlowSpec* send_flowspec = nullptr) override;

    EIOState recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) override;

    EIOState send(const char* data, uint32_t size, uint32_t* flags) override;
    EIOState send(const HTTP_Request* request) override;
    EIOState send(const HTTP_Response* response) override;
    EIOState send(const RawPacket* packet) override;

    void on_close(close_cb cb) override { m_pipe->on_close(cb); }
    void on_error(error_cb cb) override { m_pipe->on_error(cb); }
    void on_dns_request(dns_request_cb cb) override { m_pipe->on_dns_request(cb); }
    void on_dns_response(dns_response_cb cb) override { m_pipe->on_dns_response(cb); }
    void on_http_request(http_request_cb cb) override { m_pipe->on_http_request(cb); }
    void on_http_response(http_response_cb cb) override { m_pipe->on_http_response(cb); }
    void on_raw_receive(raw_receive_cb cb) override { m_pipe->on_raw_receive(cb); }
    void on_rtp_packet(rtp_packet_cb cb) override { m_pipe->on_rtp_packet(cb); }
    void on_rtcp_packet(rtcp_packet_cb cb) override { m_pipe->on_rtcp_packet(cb); }
    void on_sip_request(sip_request_cb cb) override { m_pipe->on_sip_request(cb); }
    void on_sip_response(sip_response_cb cb) override { m_pipe->on_sip_response(cb); }
    void clone_callbacks_from(ISocketPipe* other) override { m_pipe->clone_callbacks_from(static_cast<TLS_SocketProxy*>(other)->m_pipe); }

    const DNS_Response* signal_dns_request(const DNS_Request* request) override { return m_pipe->signal_dns_request(request); }
    const DNS_Request* signal_dns_response(const DNS_Response* response) override { return m_pipe->signal_dns_response(response); }
    const HTTP_Response* signal_http_request(const HTTP_Request* request) override { return m_pipe->signal_http_request(request); }
    const HTTP_Request* signal_http_response(const HTTP_Response* response) override { return m_pipe->signal_http_response(response); }
    const RawPacket* signal_raw_receive(const RawPacket* packet) override { return m_pipe->signal_raw_receive(packet); }
    void signal_rtp_packet(const RTP_Packet* packet) override { m_pipe->signal_rtp_packet(packet); }
    void signal_rtcp_packet(const RTCP_Packet* packet) override { m_pipe->signal_rtcp_packet(packet); }
    const SIP_Response* signal_sip_request(const SIP_Request* request) override { return m_pipe->signal_sip_request(request); }
    const SIP_Request* signal_sip_response(const SIP_Response* response) override { return m_pipe->signal_sip_response(response); }

    ISocketIOResult* wait_results() override { return m_pipe->wait_results(); }

    void* sys_data() const override { return m_pipe->sys_data(); }
    void* user_data() const override { return m_pipe->user_data(); }

    EAuthState proc_pending_auth(EPipeOperation last_op, int32_t post_transferred) override;
    int32_t proc_post_recv(char* out_data, uint32_t out_size, const char* in_data, uint32_t in_size) override;

    const SocketIOInfo& get_io_info() const override { return m_pipe->get_io_info(); }
    ISocketOSSupportLayer* get_os_layer() const { return m_pipe->get_os_layer(); }

    /*
    Suite of protocols used in the TLS handshake

    Internally uses OpenSSL
    */

    EAuthState ssl_advance_handshake(EPipeOperation last_op, int32_t post_transferred);

    enum class EProcState {
      E_FAILED,
      E_WAITING,
      E_READY,
    };

    EProcState handshake_send_state(int32_t post_transferred, int32_t* out_transferring);
    EProcState handshake_recv_state(int32_t post_transferred);

    bool set_accept_state();
    bool set_connect_state();

  private:
    ISocketPipe* m_pipe;
    uint8_t m_aes_key[key_size] = {};
    SSL_CTX* m_tls_ctx;
    SSL* m_ssl;
    BIO* m_in_bio;
    BIO* m_out_bio;
    std::atomic<bool> m_handshake_initiated;
    std::atomic<EAuthState> m_handshake_state;
  };

}