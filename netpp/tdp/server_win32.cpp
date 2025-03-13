#include "server.h"

#include <cassert>
#include <execution>
#include <thread>

#ifdef _WIN32

#define DEFAULT_THREAD_MAX 4
#define RIO_PENDING_MAX 5
#define RIO_MAX_BUFFERS 1024

#define SKIP_BUF_INIT_FLAG 0x80000000

namespace netpp {

  template <typename TV, typename TM>
  inline TV RoundDown(TV Value, TM Multiple) {
    return (Value / Multiple) * Multiple;
  }

  template <typename TV, typename TM>
  inline TV RoundUp(TV Value, TM Multiple) {
    return RoundDown(Value, Multiple) + (((Value % Multiple) > 0) ? Multiple : 0);
  }

  TCP_Server::TCP_Server(uint32_t desired_bufsize, uint32_t bufcount, int max_threads) {
    m_error = EServerError::E_NONE;
    m_reason = -1;

    uint32_t granularity = 0;

#ifdef _WIN32
    SYSTEM_INFO sysinfo;
    ::GetSystemInfo(&sysinfo);

    granularity = sysinfo.dwAllocationGranularity;
#else
    granularity = sysconf(_SC_PAGESIZE);
#endif

    if (desired_bufsize == 0) {
      desired_bufsize = granularity;
    }

    uint32_t desired_size = desired_bufsize * bufcount;
    desired_size = RoundUp(desired_size, granularity);

#ifdef _WIN32
    m_recvbuf = (char*)VirtualAlloc(NULL, desired_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    m_recvbuflen = desired_size;
    m_sendbuf = (char*)VirtualAlloc(NULL, desired_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    m_sendbuflen = desired_size;
#else
    m_recvbuf = new char[bufsize];
    m_recvbuflen = bufsize;
    m_sendbuf = new char[bufsize];
    m_sendbuflen = bufsize;
#endif

    m_recv_allocator.initialize(m_recvbuf, desired_bufsize, bufcount);
    m_send_allocator.initialize(m_sendbuf, desired_bufsize, bufcount);

    if (max_threads > 0) {
      m_max_threads = max_threads;
    }
    else {
#ifdef _WIN32
      m_max_threads = sysinfo.dwNumberOfProcessors * 2;
#else
      m_max_threads = sysconf(_SC_NPROCESSORS_ONLN) * 2;
#endif
    }

    if (m_max_threads == 0) {
      m_max_threads = DEFAULT_THREAD_MAX;
    }

    m_startup_thread = std::this_thread::get_id();
    m_server_socket.m_pipe = nullptr;
    m_server_socket.m_state = { 0, 0 };
    m_stop_flag = false;
  }

  TCP_Server::~TCP_Server() {
    assert(is_startup_thread_cur() && "Server must be destroyed on the same thread it was created on.");
    if (is_running()) {
      stop();
    }

#ifdef _WIN32
    if (m_recvbuf) {
      VirtualFree(m_recvbuf, 0, MEM_RELEASE);
      m_recvbuf = nullptr;
    }

    if (m_sendbuf) {
      VirtualFree(m_sendbuf, 0, MEM_RELEASE);
      m_sendbuf = nullptr;
    }
#else 
    if (m_recvbuf) {
      delete[] m_recvbuf;
      m_recvbuf = nullptr;
    }

    if (m_sendbuf) {
      delete[] m_sendbuf;
      m_sendbuf = nullptr;
    }
#endif
  }

  bool TCP_Server::is_running() const {
    return m_server_socket.m_pipe && m_server_socket.m_pipe->socket() != INVALID_SOCKET && !m_stop_flag;
  }

  bool TCP_Server::start(const char* hostname, const char* port) {
    if (is_running()) {
      m_error = EServerError::E_ERROR_SOCKET;
      m_reason = (int)ESocketErrorReason::E_REASON_STARTUP;
      return false;
    }

    return initialize(hostname, port);
  }

  void TCP_Server::stop() {
    assert(is_startup_thread_cur() && "Server must be stopped on the same thread it was created on.");
    {
      std::unique_lock<std::mutex> lock(m_mutex);
      m_stop_flag = true;
    }
    deinitialize();
  }

  bool TCP_Server::send_all(const HTTP_Request* request) {
    bool result = true;
    std::for_each(std::execution::par_unseq, m_client_sockets.begin(), m_client_sockets.end(), [&result, request](auto& kv) {
      if (!kv.second->send(request)) {
        result = false;
      }
      });
    return result;
  }

  bool TCP_Server::send_all(const HTTP_Response* response) {
    bool result = true;
    std::for_each(std::execution::par_unseq, m_client_sockets.begin(), m_client_sockets.end(), [&result, response](auto& kv) {
      if (!kv.second->send(response)) {
        result = false;
      }
      });
    return result;
  }

  bool TCP_Server::send_all(const RawPacket* packet) {
    bool result = true;
    std::for_each(std::execution::par_unseq, m_client_sockets.begin(), m_client_sockets.end(), [&result, packet](auto& kv) {
      if (!kv.second->send(packet)) {
        result = false;
      }
      });
    return result;
  }

  uint64_t TCP_Server::socket(const char* hostname, const char* port) {
    return 0;
  }

  bool TCP_Server::send(uint64_t socket, const HTTP_Request* request) {
    ISocketPipe* pipe = get_socket_pipe(socket);
    if (!pipe) {
      return false;
    }

    if (!pipe->send(request)) {
      emit_error(pipe, EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_SEND);
    }

    return m_error != EServerError::E_NONE;
  }

  bool TCP_Server::send(uint64_t socket, const HTTP_Response* response) {
    ISocketPipe* pipe = get_socket_pipe(socket);
    if (!pipe) {
      return false;
    }

    if (!pipe->send(response)) {
      emit_error(pipe, EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_SEND);
    }

    return m_error != EServerError::E_NONE;
  }

  bool TCP_Server::send(uint64_t socket, const RawPacket* packet) {
    ISocketPipe* pipe = get_socket_pipe(socket);
    if (!pipe) {
      return false;
    }

    if (!pipe->send(packet)) {
      emit_error(pipe, EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_SEND);
    }

    return m_error != EServerError::E_NONE;
  }

  void TCP_Server::emit_error(ISocketPipe* pipe, EServerError error, int reason) {
    m_error = error;
    m_reason = reason;

    const char* error_str = server_error(error, reason);

    if (pipe) {
      if (pipe == m_server_socket.m_pipe) {
        fprintf(stderr, "[SERVER] ERROR: Port %s:%s (SERVER) failed with reason: %s\n", pipe->hostname().c_str(), pipe->port().c_str(), error_str);
      }
      else {
        fprintf(stderr, "[SERVER] ERROR: Port %s:%s (CLIENT: %llu) failed with reason: %s\n", pipe->hostname().c_str(), pipe->port().c_str(), pipe->socket(), error_str);
      }
    }
    else {
      fprintf(stderr, "[SERVER] ERROR: Server (PROCESS) failed with reason: %s\n", error_str);
    }
  }

  bool TCP_Server::is_startup_thread_cur() const {
    return m_startup_thread == std::this_thread::get_id();
  }

  bool TCP_Server::initialize(const char* hostname, const char* port) {
    if (is_running()) {
      emit_error(nullptr, EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_STARTUP);
      return false;
    }

    m_server_socket.m_pipe = new TCP_Socket(nullptr, &m_recv_allocator, &m_send_allocator, ESocketHint::E_SERVER);

    m_server_socket.m_pipe->on_close([this](ISocketPipe* pipe) {
      m_purgatory_sockets.push(pipe->socket());
      return false;
      });

    m_server_socket.m_pipe->on_error([this](ISocketPipe* pipe, ESocketErrorReason reason) {
      emit_error(pipe, EServerError::E_ERROR_SOCKET, (int)reason);
      return true;
      });

    if (!m_server_socket.m_pipe->open(hostname, port)) {
      deinitialize();
      return false;
    }

    if (!m_server_socket.m_pipe->bind_and_listen()) {
      deinitialize();
      return false;
    }

    m_accept_thread = std::thread(server_accept_thread, this);
    m_process_thread = std::thread(server_process_thread, this);
    m_iocp_thread = std::thread(server_iocp_thread_win32, this);
    m_cleanup_thread = std::thread(server_cleanup_thread, this);

    return true;
  }

  void TCP_Server::deinitialize() {
    std::unique_lock<std::mutex> lock(m_mutex);

    if (m_process_thread.joinable()) {
      m_process_thread.join();
    }

    if (m_cleanup_thread.joinable()) {
      m_cleanup_thread.join();
    }

    if (m_accept_thread.joinable()) {
      m_accept_thread.join();
    }

    if (m_iocp_thread.joinable()) {
      m_iocp_thread.join();
    }

    m_server_socket.m_pipe->close();
    delete m_server_socket.m_pipe;

    m_server_socket.m_pipe = nullptr;

    for (auto& pipe : m_client_sockets) {
      delete pipe.second.m_pipe;
    }

    m_client_sockets.clear();
  }

  ISocketPipe* TCP_Server::get_socket_pipe(uint64_t socket) {
    return m_client_sockets[socket].m_pipe;
  }

  void TCP_Server::close_socket(ISocketPipe* pipe) {
    m_purgatory_sockets.push(pipe->socket());
  }

  void TCP_Server::integrate_pending_sockets() {
    while (!m_awaiting_sockets.empty()) {
      uint64_t socket = m_awaiting_sockets.front();
      m_awaiting_sockets.pop();

      ISocketPipe* client_pipe = new TCP_Socket(m_server_socket.m_pipe->get_os_layer(), &m_recv_allocator, &m_send_allocator, ESocketHint::E_SERVER);
      client_pipe->open(socket);
      client_pipe->clone_callbacks_from(m_server_socket.m_pipe);

      m_client_sockets[socket] = {
        client_pipe, {0, 0}
      };
    }
  }

  void TCP_Server::receive_on_sockets() {
    for (auto& socket : m_client_sockets) {
      ISocketPipe* pipe = socket.second.m_pipe;
      if (pipe->is_busy(EPipeOperation::E_RECV)) {
        continue;
      }
      std::unique_lock<std::mutex> lock(m_mutex);
      if (!pipe->recv(0, NULL, NULL)) {
        int err = ::WSAGetLastError();
        if (err != WSA_IO_PENDING) {
          pipe->error(ESocketErrorReason::E_REASON_RECV);
        }
      }
    }
  }

  uint64_t TCP_Server::server_accept_thread(void* param) {
    TCP_Server* server = (TCP_Server*)param;

    SOCKADDR_STORAGE from;
    ZeroMemory(&from, sizeof(from));

    while (server->is_running()) {
      SOCKET client_socket = ::WSAAccept(server->m_server_socket.m_pipe->socket(), (sockaddr*)&from, NULL, NULL, 0);
      if (client_socket == INVALID_SOCKET) {
        // Server is shutting down
        return 0;
      }

      std::unique_lock<std::mutex> lock(server->m_mutex);

      if (client_socket == INVALID_SOCKET) {
        server->emit_error(nullptr, EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_ACCEPT);
      }
      else {
        server->m_awaiting_sockets.push(client_socket);
      }
    }

    return 0;
  }

  uint64_t TCP_Server::server_process_thread(void* param) {
    TCP_Server* server = (TCP_Server*)param;
    ISocketPipe* server_pipe = server->m_server_socket.m_pipe;

    while (server->is_running()) {
      server->integrate_pending_sockets();

      if (!server_pipe->notify_all()) {
        return 0;
      }

      server->receive_on_sockets();
    }

    return 0;
  }

  uint64_t TCP_Server::server_iocp_thread_win32(void* param) {
    TCP_Server* server = (TCP_Server*)param;
    ISocketPipe* server_pipe = server->m_server_socket.m_pipe;

    DWORD transferred_;
    ULONG_PTR completion_key;
    LPOVERLAPPED overlapped;

    // TODO: Figure out why the completion status never returns
    //       Establish defined structure (should multiple sockets be handled per iocp thread?)
    //       If so, what does that look like?
    while (server->is_running()) {
      bool success = GetQueuedCompletionStatus((HANDLE)server->m_server_socket.m_pipe->sys_data(), &transferred_, &completion_key, &overlapped, INFINITE);
      if (!success) {
        if (server->m_server_socket.m_pipe->socket() == INVALID_SOCKET) {
          goto exit_thread;
        }
        server->m_server_socket.m_pipe->error(ESocketErrorReason::E_REASON_CORRUPT);
        goto exit_thread;
      }

      if (completion_key == (DWORD)ECompletionKey::E_STOP) {
        goto exit_thread;
      }

      {
        RIORESULT results[16];
        ULONG count = socket_io.rio.RIODequeueCompletion(server->m_server_socket.m_pipe->m_completion_queue, results, 16);
        if (count == RIO_CORRUPT_CQ) {
          server->m_server_socket.m_pipe->error(ESocketErrorReason::E_REASON_CORRUPT);
          goto exit_thread;
        }

        for (ULONG i = 0; i < count; i++) {
          RIORESULT* result = &results[i];

          Tag_RIO_BUF* buf = (Tag_RIO_BUF*)result->RequestContext;
          ISocketOSSupportLayer* pipe = buf->Pipe;

          SocketData& sock_data = server->m_client_sockets[pipe->socket()];

          if (result->Status != NO_ERROR) {
            if (buf->Operation == EPipeOperation::E_RECV) {
              server->m_server_socket.m_pipe->error(ESocketErrorReason::E_REASON_RECV);
            }
            else {
              server->m_server_socket.m_pipe->error(ESocketErrorReason::E_REASON_SEND);
            }
            continue;
          }

          buf->IsBusy = false;

          switch (buf->Operation) {
          case EPipeOperation::E_RECV: {

            // Get the transfered data if received
            if (result->BytesTransferred == 0) {
              continue;
            }

            bool request_handled = false;

            char* recv_buf = pipe->recv_buf();

            IApplicationLayerAdapter* adapter = ApplicationAdapterFactory::detect(recv_buf, result->BytesTransferred);
            if (!adapter) {
              server->m_server_socket.m_pipe->error(ESocketErrorReason::E_REASON_ADAPTER_UNKNOWN);
              continue;
            }

            if (!adapter->on_receive(sock_data.m_pipe, recv_buf, result->BytesTransferred, 0)) {
              server->m_server_socket.m_pipe->error(ESocketErrorReason::E_REASON_ADAPTER_FAIL);
              continue;
            }
            break;
          }
          case EPipeOperation::E_SEND: {
            // Check if the send is incomplete (chunking the data)
            sock_data.m_state.m_bytes_sent += result->BytesTransferred;

            const int32_t bytes_left = sock_data.m_state.m_bytes_total - sock_data.m_state.m_bytes_sent;
            if (bytes_left > 0) {
              // Send the remaining data
              pipe->send(sock_data.m_state.m_bytes_buf + sock_data.m_state.m_bytes_sent, bytes_left, nullptr);
            }
            else {
              // Send is complete
              sock_data.m_state.m_bytes_sent = 0;
              sock_data.m_state.m_bytes_total = 0;

              delete[] sock_data.m_state.m_bytes_buf;
              sock_data.m_state.m_bytes_buf = nullptr;
            }
            break;
          }
          case EPipeOperation::E_CLOSE: {
            pipe->close();
            break;
          }
          }
        }  // End of completion for loop
      }  // End of lock
    }  // End of while loop

  exit_thread:
    return 0;
  }

  uint64_t TCP_Server::server_cleanup_thread(void* param) {
    TCP_Server* server = (TCP_Server*)param;

    while (server->is_running()) {
      if (server->m_purgatory_sockets.size() > 0) {
        uint64_t socket = server->m_purgatory_sockets.front();
        server->m_purgatory_sockets.pop();

        SocketData& sock_data = server->m_client_sockets[socket];
        if (sock_data.m_pipe) {
          // Pipe cleaned itself up earlier by the call to close
          server->m_client_sockets.erase(socket);
          delete sock_data.m_pipe;
        }

        if (server->m_socket_threads.find(socket) != server->m_socket_threads.end()) {
          server->m_socket_threads[socket].join();
          server->m_socket_threads.erase(socket);
        }
      }
    }

    return 0;
  }

}  // namespace netpp

#endif

