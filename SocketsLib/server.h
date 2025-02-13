#pragma once

#include <functional>
#include <queue>
#include <mutex>
#include <vector>
#include <unordered_map>

#include "network.h"
#include "response.h"
#include "request.h"
#include "socket.h"

enum class EServerError {
  E_NONE = -1,
  E_ERROR_SOCKET,
  E_COUNT,
};

const char* server_error(EServerError error, int reason);

class StaticBlockAllocator {
public:
  StaticBlockAllocator() = default;
  StaticBlockAllocator(void *buffer, size_t block_size, size_t block_count);

  ~StaticBlockAllocator();

  // Invalid block
  static const size_t INVALID_BLOCK = -1;

  bool initialize(void *buffer, size_t block_size, size_t block_count);

  size_t allocate();
  void deallocate(size_t block);

  size_t get_block_size() const { return m_block_size; }

  void* get_ptr(size_t block) const;
  size_t get_ofs(size_t block) const;
  size_t block(void* ptr) const;

private:
  void* m_buffer;
  size_t m_block_size;
  size_t m_block_count;

  std::vector<bool> m_block_used;
};

class IServer {
public:
  using request_callback = std::function<HTTP_Response* (const HTTP_Request* request)>;
  using receive_callback = std::function<RawPacket* (const RawPacket* packet)>;

  virtual ~IServer() = default;

  virtual bool is_running() const = 0;
  virtual const char* hostname() const = 0;
  virtual const char* port() const = 0;

  virtual EServerError error() const = 0;
  virtual int reason() const = 0;

  // Set these before starting the server
  virtual void on_receive(receive_callback callback) = 0;
  virtual void on_request(request_callback callback) = 0;

  // Start the server to listen on the specified port
  virtual bool start(const char* hostname, const char* port) = 0;
  virtual void stop() = 0;

  // Blocking calls
  virtual bool send(int socket, const HTTP_Response*) = 0;
  virtual bool send(int socket, const RawPacket*) = 0;
};

class TCP_Server final : public IServer {
public:
  TCP_Server(int bufsize = -1, int max_threads = -1);
  ~TCP_Server();

  bool is_running() const override;

  const char* hostname() const override { return m_host_name; }
  const char* port() const override { return m_port; }

  EServerError error() const override { return m_error; }
  int reason() const override { return m_reason; }

  // Set these before starting the server
  void on_receive(receive_callback callback) override { m_receive_callback = callback; }
  void on_request(request_callback callback) override { m_request_callback = callback; }

  bool start(const char* hostname, const char* port) override;
  void stop() override;

  // Blocking calls
  bool send(int socket, const HTTP_Response*) override;
  bool send(int socket, const RawPacket*) override;

protected:
  struct SocketPipe;
  friend struct SocketPipe;

  using close_callback = std::function<void(SocketPipe*)>;
  using pipe_request_callback = request_callback;
  using pipe_receive_callback = receive_callback;
  using emit_error_fn = std::function<void(EServerError error, int reason)>;

#ifdef _WIN32

  using send_response_fn = std::function<bool(RIO_RQ* io_rq, const HTTP_Response* request)>;
  using send_packet_fn = std::function<bool(RIO_RQ* io_rq, const RawPacket* packet)>;

  enum class ESocketOperation : DWORD {
    E_SEND,
    E_RECV,
    E_CLOSE,
  };

  enum class ECompletionKey : DWORD {
    E_STOP,
    E_START,
  };

  struct Tag_RIO_BUF : public RIO_BUF {
    Tag_RIO_BUF(RIO_BUFFERID buffer_id, DWORD offset, DWORD length, ESocketOperation operation) {
      this->BufferId = buffer_id;
      this->Offset = offset;
      this->Length = length;
      this->Operation = operation;
    }

    ESocketOperation Operation;
  };

  struct SocketPipe {
    SocketPipe() {
      m_socket = INVALID_SOCKET;
      m_recv_buf_block = StaticBlockAllocator::INVALID_BLOCK;
      m_recv_buffer = new Tag_RIO_BUF {
        RIO_BUFFERID{ RIO_INVALID_BUFFERID },
        0,
        0,
        ESocketOperation::E_RECV
      };
      m_send_buf_block = StaticBlockAllocator::INVALID_BLOCK;
      m_send_buffer = new Tag_RIO_BUF {
        RIO_BUFFERID{ RIO_INVALID_BUFFERID },
        0,
        0,
        ESocketOperation::E_SEND
      };
      m_send_completion_queue = RIO_INVALID_CQ;
      m_recv_completion_queue = RIO_INVALID_CQ;
      m_request_queue = RIO_INVALID_RQ;
      m_iocp = INVALID_HANDLE_VALUE;
      m_overlapped = { 0 };
      m_server = nullptr;
    }

    ~SocketPipe() {
      delete m_recv_buffer;
      delete m_send_buffer;

      if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
      }
    }

    char* recv_buf();
    size_t recv_buf_size();
    char* send_buf();
    size_t send_buf_size();

    int recv(DWORD* flags);
    int send(const char* data, size_t size, DWORD* flags);
    bool send_response(const HTTP_Response* response);
    bool send_packet(const RawPacket* packet);

    // Calling on_close will close the socket and remove it from the server
    // DO NOT USE THE SOCKET AFTER CALLING on_close
    close_callback on_close;
    pipe_request_callback on_request;
    pipe_receive_callback on_receive;
    emit_error_fn emit_error;

    SOCKET m_socket;
    std::mutex m_mutex;

    size_t m_recv_buf_block;
    Tag_RIO_BUF *m_recv_buffer;

    size_t m_send_buf_block;
    Tag_RIO_BUF *m_send_buffer;

    RIO_CQ m_send_completion_queue;
    RIO_CQ m_recv_completion_queue;
    RIO_RQ m_request_queue;
    HANDLE m_iocp;
    OVERLAPPED m_overlapped;

    TCP_Server* m_server;
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

  bool initialize_win32();
  void deinitialize_win32();

  bool initialize_unix();
  void deinitialize_unix();

  void close_socket(SocketPipe* pipe);

#ifdef _WIN32
  size_t recv_win32(SOCKET socket, char* recvbuf, size_t* recvmax, LPWSAOVERLAPPED overlapped, bool blocking);
  void send_win32(SOCKET socket, const HTTP_Response* response, LPWSAOVERLAPPED overlapped, bool blocking);
  void send_win32(SOCKET socket, const RawPacket* packet, LPWSAOVERLAPPED overlapped, bool blocking);
#else
  void send_unix(int socket, const HTTP_Response* response, bool blocking);
  void send_unix(int socket, const RawPacket* packet, bool blocking);
#endif

  static unsigned long __stdcall server_listen_thread_win32(void* param);
  static unsigned long __stdcall server_cleanup_thread_win32(void* param);
  static unsigned long __stdcall iocp_thread_win32(void* param);

private:
  const char* m_host_name;
  const char* m_port;

  EServerError m_error;
  int m_reason;

  StaticBlockAllocator m_recv_allocator;
  StaticBlockAllocator m_send_allocator;
  SocketPipe m_server_pipe;
  SocketInterface m_socket_io;

  std::unordered_map<unsigned long, SocketPipe*> m_client_pipes;
  std::unordered_map<unsigned long, std::thread> m_socket_threads;
  std::queue<unsigned long> m_purgatory_sockets;

  std::thread::id m_startup_thread;
  std::thread m_server_thread;
  std::thread m_cleanup_thread;

  size_t m_max_threads;
  int* m_open_threads;

  char* m_sendbuf;
  size_t m_sendbuflen;

  char* m_recvbuf;
  size_t m_recvbuflen;

  request_callback m_request_callback;
  receive_callback m_receive_callback;

  std::mutex m_mutex;
};

class UDP_Server final : public IServer {
public:
  UDP_Server();
  ~UDP_Server();

  bool is_running() const override;

  const char* hostname() const override { return m_host_name; }
  const char* port() const override { return m_port; }

  // Set these before starting the server
  void on_receive(receive_callback callback) override { m_receive_callback = callback; }
  void on_request(request_callback callback) override { m_request_callback = callback; }

  bool start(const char* hostname, const char* port) override;
  void stop() override;

  // Blocking calls
  bool send(int socket, const HTTP_Response*) override;
  bool send(int socket, const RawPacket*) override;

protected:
  friend struct SocketPipe;

  struct SocketPipe {
    int m_socket;
    UDP_Server* m_server;
    receive_callback m_callback;
  };

  bool initialize_win32();
  void deinitialize_win32();

  bool initialize_unix();
  void deinitialize_unix();

  static unsigned long __stdcall server_thread_win32(void* param);

private:
  const char* m_host_name;
  const char* m_port;

  EServerError m_error;
  int m_reason;

  int m_open_socket_count;
  SocketPipe* m_open_sockets;

  int* m_open_threads;

  char* m_recvbuf;
  int m_recvbuflen;

  request_callback m_request_callback;
  receive_callback m_receive_callback;

  std::mutex m_mutex;
};