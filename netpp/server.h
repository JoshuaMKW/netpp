#pragma once

#include <functional>
#include <queue>
#include <mutex>
#include <vector>
#include <unordered_map>

#include "allocator.h"
#include "network.h"
#include "response.h"
#include "request.h"
#include "socket.h"

namespace netpp {

enum class EServerError {
  E_NONE = -1,
  E_ERROR_SOCKET,
  E_COUNT,
};

const char* server_error(EServerError error, int reason);

class IServer {
public:
  using receive_callback = std::function<RawPacket* (const ISocketPipe* source, const RawPacket* packet)>;
  using request_callback = std::function<HTTP_Response* (const ISocketPipe* source, const HTTP_Request* request)>;
  using response_callback = std::function<void(const ISocketPipe* source, const HTTP_Response* response)>;

  virtual ~IServer() = 0;

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
  virtual void on_receive(receive_callback callback) = 0;
  virtual void on_request(request_callback callback) = 0;
  virtual void on_response(response_callback callback) = 0;

  virtual bool send_all(const HTTP_Request*) = 0;
  virtual bool send_all(const HTTP_Response*) = 0;
  virtual bool send_all(const RawPacket*) = 0;

  virtual uint64_t socket(const char *hostname, const char *port) = 0;

  virtual bool send(uint64_t socket, const HTTP_Request*) = 0;
  virtual bool send(uint64_t socket, const HTTP_Response*) = 0;
  virtual bool send(uint64_t socket, const RawPacket*) = 0;

  virtual const ISocketOSSupportLayer* get_os_layer() const = 0;

protected:
  virtual void emit_error(ISocketPipe* pipe, EServerError error, int reason) = 0;
};

class TCP_Server final : public IServer {
public:
  TCP_Server(uint32_t desired_bufsize = 0, uint32_t bufcount = 128, int worker_threads = -1);
  ~TCP_Server();

  bool is_running() const override;

  bool start(const char* hostname, const char* port) override;
  void stop() override;

  const std::string& hostname() const override { return m_server_pipe->hostname(); }
  const std::string& port() const override { return m_server_pipe->port(); }

  EServerError error() const override { return m_error; }
  int reason() const override { return m_reason; }

  // Set these before starting the server
  void on_receive(receive_callback callback) override { m_receive_callback = callback; }
  void on_request(request_callback callback) override { m_request_callback = callback; }
  void on_response(response_callback callback) override { m_response_callback = callback; }

  bool send_all(const HTTP_Request*) override;
  bool send_all(const HTTP_Response*) override;
  bool send_all(const RawPacket*) override;

  uint64_t socket(const char *hostname, const char *port) override;

  bool send(uint64_t socket, const HTTP_Request*) override;
  bool send(uint64_t socket, const HTTP_Response*) override;
  bool send(uint64_t socket, const RawPacket*) override;

protected:
  void emit_error(ISocketPipe* pipe, EServerError error, int reason) override;

protected:
  friend struct Win32SocketPipe;

  using pipe_request_callback = request_callback;
  using pipe_receive_callback = receive_callback;

#ifdef _WIN32

  enum class ESocketOperation : DWORD {
    E_SEND,
    E_RECV,
    E_CLOSE,
  };


  struct Win32SocketPipe : ISocketPipe {

    uint64_t socket() const override { return (uint64_t)m_socket; }

    const std::string& hostname() const override { return m_host_name; }
    const std::string& port() const override { return m_port; }

    bool is_busy(EPipeOperation op) const override;

    bool open(const char* hostname, const char* port);
    void close() override;
    void error(ESocketErrorReason reason) override;
    bool recv(uint32_t offset, uint32_t* flags, uint32_t* unused) override;
    bool send(const char* data, uint32_t size, uint32_t* flags) override;
    bool send(const HTTP_Response* response) override;
    bool send(const HTTP_Request* request) override;
    bool send(const RawPacket* packet) override;

    void on_close(close_callback cb) override { m_on_close = cb; }
    void on_dns_request(dns_request_callback cb) override { m_on_dns_request = cb; }
    void on_dns_response(dns_response_callback cb) override { m_on_dns_response = cb; }
    void on_http_request(http_request_callback cb) override { m_on_http_request = cb; }
    void on_http_response(http_response_callback cb) override { m_on_http_response = cb; }
    void on_raw_receive(raw_receive_callback cb) override { m_on_raw_receive = cb; }
    void on_rtp_packet(rtp_packet_callback cb) override { m_on_rtp_packet = cb; }
    void on_rtcp_packet(rtcp_packet_callback cb) override { m_on_rtcp_packet = cb; }
    void on_sip_request(sip_request_callback cb) override { m_on_sip_request = cb; }
    void on_sip_response(sip_response_callback cb) override { m_on_sip_response = cb; }

    bool open(uint64_t socket);

  protected:
    char* recv_buf();
    uint32_t recv_buf_size();
    char* send_buf();
    uint32_t send_buf_size();

    std::string m_host_name;
    std::string m_port;

    close_callback m_on_close;
    dns_request_callback m_on_dns_request;
    dns_response_callback m_on_dns_response;
    http_request_callback m_on_http_request;
    http_response_callback m_on_http_response;
    raw_receive_callback m_on_raw_receive;
    rtp_packet_callback m_on_rtp_packet;
    rtcp_packet_callback m_on_rtcp_packet;
    sip_request_callback m_on_sip_request;
    sip_response_callback m_on_sip_response;

    SOCKET m_socket;
    std::mutex m_mutex;

    uint32_t m_recv_buf_block;
    Tag_RIO_BUF* m_recv_buffer;

    uint32_t m_send_buf_block;
    Tag_RIO_BUF* m_send_buffer;

    RIO_CQ m_completion_queue;
    RIO_RQ m_request_queue;
    HANDLE m_iocp;
    OVERLAPPED m_overlapped;

    TCP_Server* m_server;

    // For chunking data into the buffer
    const char* m_send_data;
    uint32_t m_send_size;
    uint32_t m_send_offset;
  };

#else
  using close_callback = std::function<void(int socket)>;
  using pipe_request_callback = request_callback;
  using pipe_receive_callback = receive_callback;
  using send_response_fn = std::function<bool(int socket, const HTTP_Response* request)>;
  using send_packet_fn = std::function<bool(int socket, const RawPacket* packet)>;
  using error_fn = std::function<void(int socket, EServerError error, int reason)>;

  struct SocketPipe {
    int m_socket;
    std::mutex m_mutex;

    // Pipe interface
    close_callback on_close;
    pipe_request_callback on_request;
    pipe_receive_callback on_receive;
    send_response_fn send_response;
    send_packet_fn send_packet;
  };
#endif

  bool is_startup_thread_cur() const;

  bool initialize(const char* hostname, const char* port);
  void deinitialize();

  ISocketPipe* get_socket_pipe(uint64_t socket);
  void close_socket(ISocketPipe* pipe);

#ifdef _WIN32
  static uint64_t server_iocp_thread_win32(void* param);
#endif

  void integrate_pending_sockets();
  void receive_on_sockets();

  static uint64_t server_accept_thread(void* param);
  static uint64_t server_process_thread(void* param);
  static uint64_t server_cleanup_thread(void* param);

private:
  EServerError m_error;
  int m_reason;

  StaticBlockAllocator m_recv_allocator;
  StaticBlockAllocator m_send_allocator;
  ISocketPipe* m_server_pipe;
  SocketInterface m_socket_io;

  std::unordered_map<uint64_t, ISocketPipe*> m_client_pipes;
  std::unordered_map<uint64_t, std::thread> m_socket_threads;

  std::queue<uint64_t> m_awaiting_sockets;
  std::queue<uint64_t> m_purgatory_sockets;

  std::thread::id m_startup_thread;

  std::thread m_accept_thread;
  std::thread m_process_thread;
  std::thread m_iocp_thread;
  std::thread m_cleanup_thread;

  uint32_t m_max_threads;

  char* m_sendbuf;
  uint32_t m_sendbuflen;

  char* m_recvbuf;
  uint32_t m_recvbuflen;

  receive_callback m_receive_callback;
  request_callback m_request_callback;
  response_callback m_response_callback;

  std::mutex m_mutex;
  bool m_stop_flag;
};

} // namespace netpp
