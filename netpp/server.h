#pragma once

#include <functional>
#include <queue>
#include <mutex>
#include <vector>
#include <unordered_map>

#include "netpp.h"
#include "allocator.h"
#include "network.h"
#include "http/request.h"
#include "http/response.h"
#include "security.h"
#include "socket.h"

namespace netpp {

  enum class EServerError {
    E_NONE = -1,
    E_ERROR_SOCKET,
    E_COUNT,
  };

  const char* server_error(EServerError error, int reason);

  class NETPP_API IServer {
  public:
    virtual ~IServer() = default;

    virtual bool is_running() const = 0;

    // Start the server to listen on the specified port
    virtual bool start(const char* hostname, const char* port) = 0;
    virtual void stop() = 0;

    virtual const std::string& hostname() const = 0;
    virtual const std::string& port() const = 0;

    // Get the last error that occured
    virtual EServerError error() const = 0;

    // Get the reason for the last error
    virtual int reason() const = 0;

    // Set these before starting the server
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

    virtual bool send_all(const HTTP_Request*) = 0;
    virtual bool send_all(const HTTP_Response*) = 0;
    virtual bool send_all(const RawPacket*) = 0;

    virtual uint64_t socket(const char* hostname, const char* port) = 0;

    virtual bool send(uint64_t socket, const HTTP_Request*) = 0;
    virtual bool send(uint64_t socket, const HTTP_Response*) = 0;
    virtual bool send(uint64_t socket, const RawPacket*) = 0;

  protected:
    virtual void emit_error(ISocketPipe* pipe, EServerError error, int reason) = 0;
  };

  class NETPP_API TCP_Server final : public IServer {
  public:
    TCP_Server() = delete;
    TCP_Server(ISecurityController *security, uint32_t bufcount, uint32_t desired_bufsize = 0, int max_threads = -1);
    ~TCP_Server();

    bool is_running() const override;

    bool start(const char* hostname, const char* port) override;
    void stop() override;

    const std::string& hostname() const override { return m_server_socket->hostname(); }
    const std::string& port() const override { return m_server_socket->port(); }

    EServerError error() const override { return m_error; }
    int reason() const override { return m_reason; }

    // Set these before starting the server
    void on_close(ISocketPipe::close_cb cb) override { m_server_socket->on_close(cb); }
    void on_dns_request(ISocketPipe::dns_request_cb cb) override { m_server_socket->on_dns_request(cb); }
    void on_dns_response(ISocketPipe::dns_response_cb cb) override { m_server_socket->on_dns_response(cb); }
    void on_http_request(ISocketPipe::http_request_cb cb) override { m_server_socket->on_http_request(cb); }
    void on_http_response(ISocketPipe::http_response_cb cb) override { m_server_socket->on_http_response(cb); }
    void on_raw_receive(ISocketPipe::raw_receive_cb cb) override { m_server_socket->on_raw_receive(cb); }
    void on_rtp_packet(ISocketPipe::rtp_packet_cb cb) override { m_server_socket->on_rtp_packet(cb); }
    void on_rtcp_packet(ISocketPipe::rtcp_packet_cb cb) override { m_server_socket->on_rtcp_packet(cb); }
    void on_sip_request(ISocketPipe::sip_request_cb cb) override { m_server_socket->on_sip_request(cb); }
    void on_sip_response(ISocketPipe::sip_response_cb cb) override { m_server_socket->on_sip_response(cb); }

    bool send_all(const HTTP_Request*) override;
    bool send_all(const HTTP_Response*) override;
    bool send_all(const RawPacket*) override;

    uint64_t socket(const char* hostname, const char* port) override;

    bool send(uint64_t socket, const HTTP_Request*) override;
    bool send(uint64_t socket, const HTTP_Response*) override;
    bool send(uint64_t socket, const RawPacket*) override;

  protected:
    void emit_error(ISocketPipe* pipe, EServerError error, int reason) override;

  protected:
    bool is_startup_thread_cur() const;

    bool initialize(const char* hostname, const char* port);
    void deinitialize();

    ISocketPipe* get_socket_pipe(uint64_t socket);
    void close_socket(ISocketPipe* pipe);

    IApplicationLayerAdapter* handle_inproc_recv(SocketProcData& data, const ISocketIOResult::OperationData& info, bool& inproc);

#ifdef _WIN32
    static uint64_t server_process_thread(void* param);
#endif

    bool handle_auth_operations(SocketProcData& data, const ISocketIOResult::OperationData& info);
    bool handle_client_operations(SocketProcData& data, const ISocketIOResult::OperationData& info);

    void integrate_pending_sockets();
    void proc_auth_on_sockets();
    void receive_on_sockets();
    void cleanup_sockets();

    static uint64_t server_accept_thread(void* param);
    static uint64_t server_update_thread(void* param);
    static uint64_t server_cleanup_thread(void* param);

  private:
    EServerError m_error;
    int m_reason;

    StaticBlockAllocator m_recv_allocator;
    StaticBlockAllocator m_send_allocator;
    ISocketPipe* m_server_socket;

    std::unordered_map<uint64_t, SocketProcData> m_pending_auth_sockets;
    std::unordered_map<uint64_t, SocketProcData> m_client_sockets;

    std::queue<uint64_t> m_awaiting_sockets;
    std::queue<uint64_t> m_purgatory_sockets;

    std::thread::id m_startup_thread;

    std::thread m_accept_thread;
    std::thread m_update_thread;
    std::thread m_process_thread;

    uint32_t m_max_threads;

    char* m_sendbuf;
    uint32_t m_sendbuflen;

    char* m_recvbuf;
    uint32_t m_recvbuflen;

    std::recursive_mutex m_mutex;
    bool m_stop_flag;

    ISecurityController* m_security;
  };

  class NETPP_API UDP_Server final : public IServer {
  public:
    UDP_Server() = delete;
    UDP_Server(ISecurityController* security, uint32_t bufcount, uint32_t desired_bufsize = 0, int max_threads = -1);
    ~UDP_Server();

    bool is_running() const override;

    bool start(const char* hostname, const char* port) override;
    void stop() override;

    const std::string& hostname() const override { return m_server_socket->hostname(); }
    const std::string& port() const override { return m_server_socket->port(); }

    EServerError error() const override { return m_error; }
    int reason() const override { return m_reason; }

    // Set these before starting the server
    void on_close(ISocketPipe::close_cb cb) override { m_server_socket->on_close(cb); }
    void on_dns_request(ISocketPipe::dns_request_cb cb) override { m_server_socket->on_dns_request(cb); }
    void on_dns_response(ISocketPipe::dns_response_cb cb) override { m_server_socket->on_dns_response(cb); }
    void on_http_request(ISocketPipe::http_request_cb cb) override { m_server_socket->on_http_request(cb); }
    void on_http_response(ISocketPipe::http_response_cb cb) override { m_server_socket->on_http_response(cb); }
    void on_raw_receive(ISocketPipe::raw_receive_cb cb) override { m_server_socket->on_raw_receive(cb); }
    void on_rtp_packet(ISocketPipe::rtp_packet_cb cb) override { m_server_socket->on_rtp_packet(cb); }
    void on_rtcp_packet(ISocketPipe::rtcp_packet_cb cb) override { m_server_socket->on_rtcp_packet(cb); }
    void on_sip_request(ISocketPipe::sip_request_cb cb) override { m_server_socket->on_sip_request(cb); }
    void on_sip_response(ISocketPipe::sip_response_cb cb) override { m_server_socket->on_sip_response(cb); }

    bool send_all(const HTTP_Request*) override;
    bool send_all(const HTTP_Response*) override;
    bool send_all(const RawPacket*) override;

    uint64_t socket(const char* hostname, const char* port) override;

    bool send(uint64_t socket, const HTTP_Request*) override;
    bool send(uint64_t socket, const HTTP_Response*) override;
    bool send(uint64_t socket, const RawPacket*) override;

  protected:
    void emit_error(ISocketPipe* pipe, EServerError error, int reason) override;

  protected:
    bool is_startup_thread_cur() const;

    bool initialize(const char* hostname, const char* port);
    void deinitialize();

    ISocketPipe* get_socket_pipe(uint64_t socket);
    void close_socket(ISocketPipe* pipe);

    IApplicationLayerAdapter* handle_inproc_recv(SocketProcData& data, const ISocketIOResult::OperationData& info, bool& inproc);

    bool handle_auth_operations(SocketProcData& data, const ISocketIOResult::OperationData& info);
    bool handle_client_operations(SocketProcData& data, const ISocketIOResult::OperationData& info);

    void integrate_pending_sockets();
    void proc_auth_on_sockets();
    void receive_on_sockets();
    void cleanup_sockets();

    static uint64_t server_accept_thread(void* param);
    static uint64_t server_update_thread(void* param);
    static uint64_t server_process_thread(void* param);

  private:
    EServerError m_error;
    int m_reason;

    StaticBlockAllocator m_recv_allocator;
    StaticBlockAllocator m_send_allocator;
    ISocketPipe* m_server_socket;

    std::unordered_map<uint64_t, SocketProcData> m_pending_auth_sockets;
    std::unordered_map<uint64_t, SocketProcData> m_client_sockets;
    std::unordered_map<uint64_t, std::thread> m_socket_threads;

    std::queue<uint64_t> m_awaiting_sockets;
    std::queue<uint64_t> m_purgatory_sockets;

    std::thread::id m_startup_thread;

    std::thread m_accept_thread;
    std::thread m_update_thread;
    std::thread m_process_thread;

    uint32_t m_max_threads;

    char* m_sendbuf;
    uint32_t m_sendbuflen;

    char* m_recvbuf;
    uint32_t m_recvbuflen;

    std::recursive_mutex m_mutex;
    bool m_stop_flag;

    ISecurityController* m_security;
  };

} // namespace netpp
