#pragma once

#include <functional>
#include <queue>
#include <mutex>
#include <vector>
#include <unordered_map>

#include "netpp.h"
#include "allocator.h"
#include "network.h"
#include "response.h"
#include "request.h"
#include "socket.h"

#define CLIENT_USE_WSA 0

namespace netpp {

  enum class EClientError {
    E_NONE = -1,
    E_ERROR_SOCKET,
    E_COUNT,
  };

  NETPP_API const char* client_error(EClientError error, int reason);

  class NETPP_API IClient {
  public:
    using receive_cb = std::function<RawPacket* (const ISocketPipe* source, const RawPacket* packet)>;
    using request_cb = std::function<HTTP_Response* (const ISocketPipe* source, const HTTP_Request* request)>;
    using response_cb = std::function<HTTP_Request* (const ISocketPipe* source, const HTTP_Response* response)>;

    virtual ~IClient() = default;

    virtual bool is_running() const = 0;
    virtual bool is_connected() const = 0;

    // Start the client to listen on the specified port
    virtual bool start() = 0;
    virtual void stop() = 0;

    virtual bool connect(const char* hostname, const char* port, uint64_t timeout = 0) = 0;
    virtual void disconnect() = 0;

    virtual const std::string& hostname() const = 0;
    virtual const std::string& port() const = 0;

    virtual const std::string& server_hostname() const = 0;
    virtual const std::string& server_port() const = 0;

    // Get the last error that occured
    virtual EClientError error() const = 0;

    // Get the reason for the last error
    virtual int reason() const = 0;

    // Set these before starting the client
    virtual void on_close(ISocketPipe::close_cb cb) = 0;
    virtual void on_dns_request(ISocketPipe::dns_request_cb cb) = 0;
    virtual void on_dns_response(ISocketPipe::dns_response_cb cb) = 0;
    virtual void on_http_request(ISocketPipe::http_request_cb cb) = 0;
    virtual void on_http_response(ISocketPipe::http_response_cb cb) = 0;
    virtual void on_raw_receive(ISocketPipe::raw_receive_cb cb) = 0;
    virtual void on_rtp_packet(ISocketPipe::rtp_packet_cb cb) = 0;
    virtual void on_rtcp_packet(ISocketPipe::rtcp_packet_cb cb) = 0;
    virtual void on_sip_request(ISocketPipe::sip_request_cb cb) = 0;
    virtual void on_sip_response(ISocketPipe::sip_response_cb cb) = 0;

    virtual bool send(const HTTP_Request*) = 0;
    virtual bool send(const RawPacket*) = 0;

  protected:
    virtual void emit_error(ISocketPipe* pipe, EClientError error, int reason) = 0;
  };

  class NETPP_API TCP_Client final : public IClient {
  public:
    TCP_Client(bool use_tls_ssl, uint32_t bufsize = 4096);
    ~TCP_Client();

    bool is_running() const override;
    bool is_connected() const override;

    bool start() override;
    void stop() override;

    bool connect(const char* hostname, const char* port, uint64_t timeout = 0) override;
    void disconnect() override;

    const std::string& hostname() const override { return m_server_socket.m_pipe->hostname(); }
    const std::string& port() const override { return m_server_socket.m_pipe->port(); }

    const std::string& server_hostname() const override { return m_server_socket.m_pipe->hostname(); }
    const std::string& server_port() const override { return m_server_socket.m_pipe->port(); }

    EClientError error() const override { return m_error; }
    int reason() const override { return m_reason; }

    // Set these before starting the server
    void on_close(ISocketPipe::close_cb cb) override { m_server_socket.m_pipe->on_close(cb); }
    void on_dns_request(ISocketPipe::dns_request_cb cb) override { m_server_socket.m_pipe->on_dns_request(cb); }
    void on_dns_response(ISocketPipe::dns_response_cb cb) override { m_server_socket.m_pipe->on_dns_response(cb); }
    void on_http_request(ISocketPipe::http_request_cb cb) override { m_server_socket.m_pipe->on_http_request(cb); }
    void on_http_response(ISocketPipe::http_response_cb cb) override { m_server_socket.m_pipe->on_http_response(cb); }
    void on_raw_receive(ISocketPipe::raw_receive_cb cb) override { m_server_socket.m_pipe->on_raw_receive(cb); }
    void on_rtp_packet(ISocketPipe::rtp_packet_cb cb) override { m_server_socket.m_pipe->on_rtp_packet(cb); }
    void on_rtcp_packet(ISocketPipe::rtcp_packet_cb cb) override { m_server_socket.m_pipe->on_rtcp_packet(cb); }
    void on_sip_request(ISocketPipe::sip_request_cb cb) override { m_server_socket.m_pipe->on_sip_request(cb); }
    void on_sip_response(ISocketPipe::sip_response_cb cb) override { m_server_socket.m_pipe->on_sip_response(cb); }

    bool send(const HTTP_Request*) override;
    bool send(const RawPacket*) override;

    void set_send_flow_spec(const NetworkFlowSpec* flow_spec) { m_send_spec = flow_spec; }
    void set_recv_flow_spec(const NetworkFlowSpec* flow_spec) { m_recv_spec = flow_spec; }

  protected:
    void emit_error(ISocketPipe* pipe, EClientError error, int reason) override;

    bool is_startup_thread_cur() const;

    bool initialize();
    void deinitialize();
    
    IApplicationLayerAdapter* handle_inproc_recv(SocketData& data, const ISocketIOResult::OperationData& info, bool& inproc);

#ifdef _WIN32
    static uint64_t client_iocp_thread_win32(void* param);
#endif

    static uint64_t client_connect_thread(void* param);

  private:
    EClientError m_error;
    int m_reason;

    StaticBlockAllocator m_recv_allocator;
    StaticBlockAllocator m_send_allocator;
    SocketData m_server_socket;

    std::thread::id m_startup_thread;

    std::thread m_connect_thread;
    std::thread m_iocp_thread;

    char* m_sendbuf;
    uint32_t m_sendbuflen;

    char* m_recvbuf;
    uint32_t m_recvbuflen;

    const NetworkFlowSpec *m_send_spec;
    const NetworkFlowSpec *m_recv_spec;

    std::mutex m_mutex;
    bool m_stop_flag;

    bool m_tls_ssl;
  };

}  // namespace netpp
