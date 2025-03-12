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
  inline TV RoundDown(TV Value, TM Multiple)
  {
    return((Value / Multiple) * Multiple);
  }

  template <typename TV, typename TM>
  inline TV RoundUp(TV Value, TM Multiple)
  {
    return(RoundDown(Value, Multiple) + (((Value % Multiple) > 0) ? Multiple : 0));
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

    m_receive_callback = nullptr;
    m_request_callback = nullptr;
    m_response_callback = nullptr;

    m_socket_io = { 0 };
    m_server_pipe = nullptr;

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
    return m_server_pipe && m_server_pipe->socket() != INVALID_SOCKET && !m_stop_flag;
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
    std::for_each(std::execution::par_unseq, m_client_pipes.begin(), m_client_pipes.end(), [&result, request](auto& kv) {
      if (!kv.second->send(request)) {
        result = false;
      }
      });
    return result;
  }

  bool TCP_Server::send_all(const HTTP_Response* response) {
    bool result = true;
    std::for_each(std::execution::par_unseq, m_client_pipes.begin(), m_client_pipes.end(), [&result, response](auto& kv) {
      if (!kv.second->send(response)) {
        result = false;
      }
      });
    return result;
  }

  bool TCP_Server::send_all(const RawPacket* packet) {
    bool result = true;
    std::for_each(std::execution::par_unseq, m_client_pipes.begin(), m_client_pipes.end(), [&result, packet](auto& kv) {
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
      if (pipe == m_server_pipe) {
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
      m_error = EServerError::E_ERROR_SOCKET;
      m_reason = (int)ESocketErrorReason::E_REASON_STARTUP;
      return false;
    }

    Win32SocketPipe* server_pipe = new Win32SocketPipe(this);
    m_server_pipe = server_pipe;

    server_pipe->m_host_name = hostname;
    server_pipe->m_port = port;

    uint32_t queue_size = 0;

    sockaddr_in server_addr;
    ::ZeroMemory(&server_addr, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = ::htons(atoi(server_pipe->m_port.c_str()));
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // -----------------------------
    // Create the socket and flag it for IOCP with RIO
    server_pipe->m_socket = (int)::WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_REGISTERED_IO);
    if (server_pipe->m_socket == INVALID_SOCKET) {
      m_error = EServerError::E_ERROR_SOCKET;
      m_reason = (int)ESocketErrorReason::E_REASON_SOCKET;
      goto cleanup;
    }

    server_pipe->m_server = this;

    // Initialize RIO and friends
    {
      DWORD bytes = 0;

      GUID rio_id = WSAID_MULTIPLE_RIO;
      GUID acceptex_id = WSAID_ACCEPTEX;
      GUID getacceptexsockaddrs_id = WSAID_GETACCEPTEXSOCKADDRS;

      // Get the RIO extension function table
      if (::WSAIoctl(
        server_pipe->m_socket,
        SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
        &rio_id, sizeof(GUID),
        &m_socket_io.rio, sizeof(RIO_EXTENSION_FUNCTION_TABLE),
        &bytes, NULL, NULL
      ) != 0) {
        int error = WSAGetLastError();
        m_error = EServerError::E_ERROR_SOCKET;
        m_reason = (int)ESocketErrorReason::E_REASON_SOCKET;
        goto cleanup;
      }

      // Get the AcceptEx function
      if (::WSAIoctl(
        server_pipe->m_socket,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        &acceptex_id, sizeof(GUID),
        &m_socket_io.exio.AcceptEx, sizeof(LPFN_ACCEPTEX),
        &bytes, NULL, NULL
      ) != 0) {
        m_error = EServerError::E_ERROR_SOCKET;
        m_reason = (int)ESocketErrorReason::E_REASON_SOCKET;
        goto cleanup;
      }

      // Get the GetAcceptExSockAddrs function
      if (::WSAIoctl(
        server_pipe->m_socket,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        &getacceptexsockaddrs_id, sizeof(GUID),
        &m_socket_io.exio.GetAcceptExSockAddrs, sizeof(LPFN_GETACCEPTEXSOCKADDRS),
        &bytes, NULL, NULL
      ) != 0) {
        m_error = EServerError::E_ERROR_SOCKET;
        m_reason = (int)ESocketErrorReason::E_REASON_SOCKET;
        goto cleanup;
      }
    }

    server_pipe->m_iocp = ::CreateIoCompletionPort((HANDLE)server_pipe->m_socket, NULL, 0, 0);
    if (server_pipe->m_iocp == NULL) {
      m_error = EServerError::E_ERROR_SOCKET;
      m_reason = (int)ESocketErrorReason::E_REASON_SOCKET;
      goto cleanup;
    }

    // Initialize Overlapped structure
    ::ZeroMemory(&server_pipe->m_overlapped, sizeof(server_pipe->m_overlapped));

    // Create the completion queues and request queues
    RIO_NOTIFICATION_COMPLETION completion;
    completion.Type = RIO_IOCP_COMPLETION;
    completion.Iocp.IocpHandle = server_pipe->m_iocp;
    completion.Iocp.CompletionKey = (void*)ECompletionKey::E_START;
    completion.Iocp.Overlapped = &server_pipe->m_overlapped;

    queue_size = m_recv_allocator.capacity() + m_send_allocator.capacity();

    server_pipe->m_completion_queue = m_socket_io.rio.RIOCreateCompletionQueue(queue_size * RIO_PENDING_MAX, &completion);
    if (server_pipe->m_completion_queue == RIO_INVALID_CQ) {
      m_error = EServerError::E_ERROR_SOCKET;
      m_reason = (int)ESocketErrorReason::E_REASON_RESOURCES;
      goto cleanup;
    }

    server_pipe->m_request_queue = m_socket_io.rio.RIOCreateRequestQueue(
      server_pipe->m_socket,
      RIO_PENDING_MAX, 1,
      RIO_PENDING_MAX, 1,
      server_pipe->m_completion_queue,
      server_pipe->m_completion_queue,
      &server_pipe
    );
    if (server_pipe->m_request_queue == RIO_INVALID_RQ) {
      m_error = EServerError::E_ERROR_SOCKET;
      m_reason = (int)ESocketErrorReason::E_REASON_RESOURCES;
      goto cleanup;
    }

    server_pipe->m_recv_buffer->BufferId = m_socket_io.rio.RIORegisterBuffer(m_recvbuf, m_recvbuflen);
    if (server_pipe->m_recv_buffer->BufferId == RIO_INVALID_BUFFERID) {
      m_error = EServerError::E_ERROR_SOCKET;
      m_reason = (int)ESocketErrorReason::E_REASON_RESOURCES;
      goto cleanup;
    }

    server_pipe->m_recv_buffer->Length = m_recv_allocator.block_size();
    server_pipe->m_recv_buf_block = m_recv_allocator.allocate();

    server_pipe->m_send_buffer->BufferId = m_socket_io.rio.RIORegisterBuffer(m_sendbuf, m_sendbuflen);
    if (server_pipe->m_send_buffer->BufferId == RIO_INVALID_BUFFERID) {
      m_error = EServerError::E_ERROR_SOCKET;
      m_reason = (int)ESocketErrorReason::E_REASON_RESOURCES;
      goto cleanup;
    }
    server_pipe->m_send_buffer->Length = 0;
    server_pipe->m_send_buf_block = m_send_allocator.allocate();

    // -----------------------------

    if (::bind(server_pipe->m_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
      m_error = EServerError::E_ERROR_SOCKET;
      m_reason = (int)ESocketErrorReason::E_REASON_BIND;
      goto cleanup;
    }

    // -----------------------------
    // Listen on the socket to allow for an incoming connection
    if (::listen(server_pipe->m_socket, SOMAXCONN) == SOCKET_ERROR) {
      m_error = EServerError::E_ERROR_SOCKET;
      m_reason = (int)ESocketErrorReason::E_REASON_LISTEN;
      goto cleanup;
    }

    server_pipe->on_receive(m_receive_callback);
    server_pipe->on_request(m_request_callback);

    m_accept_thread = std::thread(server_accept_thread, this);
    m_process_thread = std::thread(server_process_thread, this);
    m_iocp_thread = std::thread(server_iocp_thread_win32, this);
    m_cleanup_thread = std::thread(server_cleanup_thread, this);

    //// Spin up notifications for the completion queues
    //m_socket_io.rio.RIONotify(m_server_pipe->m_recv_completion_queue);

  cleanup:
    if (m_error != EServerError::E_NONE) {
      deinitialize();
      return false;
    }

    return true;
  }

  void TCP_Server::deinitialize() {
    std::unique_lock<std::mutex> lock(m_mutex);

    Win32SocketPipe* server_pipe = (Win32SocketPipe*)m_server_pipe;
    if (server_pipe->m_socket != INVALID_SOCKET) {
      ::shutdown(server_pipe->m_socket, SD_BOTH);
      ::closesocket(server_pipe->m_socket);
      server_pipe->m_socket = INVALID_SOCKET;
    }

    if (server_pipe->m_iocp) {
      ::CloseHandle(server_pipe->m_iocp);
      server_pipe->m_iocp = NULL;
    }

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

    if (server_pipe->m_completion_queue != RIO_INVALID_CQ) {
      m_socket_io.rio.RIOCloseCompletionQueue(server_pipe->m_completion_queue);
      server_pipe->m_completion_queue = RIO_INVALID_CQ;
    }

    if (server_pipe->m_request_queue != RIO_INVALID_RQ) {
      server_pipe->m_request_queue = RIO_INVALID_RQ;
    }

    if (server_pipe->m_recv_buffer->BufferId != RIO_INVALID_BUFFERID) {
      m_socket_io.rio.RIODeregisterBuffer(server_pipe->m_recv_buffer->BufferId);
      server_pipe->m_recv_buffer->BufferId = RIO_INVALID_BUFFERID;
      m_recv_allocator.deallocate(server_pipe->m_recv_buf_block);
      server_pipe->m_recv_buf_block = StaticBlockAllocator::INVALID_BLOCK;
    }

    if (server_pipe->m_send_buffer->BufferId != RIO_INVALID_BUFFERID) {
      m_socket_io.rio.RIODeregisterBuffer(server_pipe->m_send_buffer->BufferId);
      server_pipe->m_send_buffer->BufferId = RIO_INVALID_BUFFERID;
      m_send_allocator.deallocate(server_pipe->m_send_buf_block);
      server_pipe->m_send_buf_block = StaticBlockAllocator::INVALID_BLOCK;
    }

    delete server_pipe;
    m_server_pipe = nullptr;

    for (auto& pipe : m_client_pipes) {
      delete pipe.second;
    }
  }

  ISocketPipe* TCP_Server::get_socket_pipe(uint64_t socket) {
    return m_client_pipes[socket];
  }

  void TCP_Server::close_socket(ISocketPipe* pipe) {
    m_purgatory_sockets.push(pipe->socket());
  }

  void TCP_Server::integrate_pending_sockets() {
    while (!m_awaiting_sockets.empty()) {
      uint64_t socket = m_awaiting_sockets.front();
      m_awaiting_sockets.pop();

      Win32SocketPipe* client_pipe = new Win32SocketPipe(this);
      client_pipe->open(socket);

      client_pipe->m_on_receive = m_receive_callback;
      client_pipe->m_on_request = m_request_callback;

      m_client_pipes[socket] = client_pipe;
    }
  }

  void TCP_Server::receive_on_sockets() {
    for (auto& pipe : m_client_pipes) {
      if (pipe.second->is_busy(EPipeOperation::E_RECV)) {
        continue;
      }
      std::unique_lock<std::mutex> lock(m_mutex);
      if (!pipe.second->recv(0, NULL, NULL)) {
        int err = ::WSAGetLastError();
        if (err != WSA_IO_PENDING) {
          pipe.second->error(ESocketErrorReason::E_REASON_RECV);
        }
      }
    }
  }

  uint64_t TCP_Server::server_accept_thread(void* param) {
    TCP_Server* server = (TCP_Server*)param;

    SOCKADDR_STORAGE from;
    ZeroMemory(&from, sizeof(from));

    while (server->is_running()) {
      SOCKET client_socket = ::WSAAccept(server->m_server_pipe->socket(), (sockaddr*)&from, NULL, NULL, 0);
      if (client_socket == INVALID_SOCKET) {
        // Server is shutting down
        return 0;
      }

      std::unique_lock<std::mutex> lock(server->m_mutex);

      if (client_socket == INVALID_SOCKET) {
        server->emit_error(nullptr, EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_ACCEPT);
      } else {
        server->m_awaiting_sockets.push(client_socket);
      }
    }

    return 0;
  }

  uint64_t TCP_Server::server_process_thread(void* param) {
    TCP_Server* server = (TCP_Server*)param;
    Win32SocketPipe* server_pipe = (Win32SocketPipe*)server->m_server_pipe;

    while (server->is_running()) {
      server->integrate_pending_sockets();

      int rc = server->m_socket_io.rio.RIONotify(server_pipe->m_completion_queue);
      if (rc != ERROR_SUCCESS && rc != WSAEALREADY) {
        server->emit_error(nullptr, EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_CORRUPT);
        return 0;
      }

      server->receive_on_sockets();
    }

    return 0;
  }

  uint64_t TCP_Server::server_iocp_thread_win32(void* param) {
    TCP_Server* server = (TCP_Server*)param;
    SocketInterface& socket_io = server->m_socket_io;
    Win32SocketPipe* server_pipe = (Win32SocketPipe*)server->m_server_pipe;

    DWORD transferred_;
    ULONG_PTR completion_key;
    LPOVERLAPPED overlapped;

    // TODO: Figure out why the completion status never returns
    //       Establish defined structure (should multiple sockets be handled per iocp thread?)
    //       If so, what does that look like?
    while (server->is_running()) {
      bool success = GetQueuedCompletionStatus(server_pipe->m_iocp, &transferred_, &completion_key, &overlapped, INFINITE);
      if (!success) {
        if (server_pipe->socket() == INVALID_SOCKET) {
          goto exit_thread;
        }
        server_pipe->error(ESocketErrorReason::E_REASON_CORRUPT);
        goto exit_thread;
      }

      if (completion_key == (DWORD)ECompletionKey::E_STOP) {
        goto exit_thread;
      }

      {
        RIORESULT results[16];
        ULONG count = socket_io.rio.RIODequeueCompletion(server_pipe->m_completion_queue, results, 16);
        if (count == RIO_CORRUPT_CQ) {
          server_pipe->error(ESocketErrorReason::E_REASON_CORRUPT);
          goto exit_thread;
        }

        for (ULONG i = 0; i < count; i++) {
          RIORESULT* result = &results[i];

          Tag_RIO_BUF* buf = (Tag_RIO_BUF*)result->RequestContext;
          Win32SocketPipe* pipe = (Win32SocketPipe*)buf->Pipe;

          if (result->Status != NO_ERROR) {
            if (buf->Operation == ESocketOperation::E_RECV) {
              server_pipe->error(ESocketErrorReason::E_REASON_RECV);
            } else {
              server_pipe->error(ESocketErrorReason::E_REASON_SEND);
            }
            continue;
          }

          buf->IsBusy = false;

          switch (buf->Operation) {
          case ESocketOperation::E_RECV: {

            // Get the transfered data if received
            if (result->BytesTransferred == 0) {
              continue;
            }

            bool request_handled = false;

            char* recv_buf = pipe->recv_buf();

            IApplicationLayerAdapter* adapter = ApplicationAdapterFactory::detect(recv_buf, result->BytesTransferred);
            if (!adapter) {
              server_pipe->error(ESocketErrorReason::E_REASON_ADAPTER_UNKNOWN);
              continue;
            }

            if (!adapter->on_receive(pipe, recv_buf, result->BytesTransferred, 0)) {
              server_pipe->error(ESocketErrorReason::E_REASON_ADAPTER_FAIL);
              continue;
            }
            break;
          }
          case ESocketOperation::E_SEND: {
            // Check if the send is incomplete (chunking the data)
            pipe->m_send_offset += result->BytesTransferred;
            if (pipe->m_send_offset < pipe->m_send_size) {
              // Send the remaining data
              uint32_t flags = SKIP_BUF_INIT_FLAG;
              pipe->send(pipe->m_send_data + pipe->m_send_offset, pipe->m_send_size - pipe->m_send_offset, &flags);
            }
            else {
              // Send is complete
              pipe->m_send_offset = 0;
              pipe->m_send_size = 0;

              delete[] pipe->m_send_data;
              pipe->m_send_data = nullptr;
            }
            break;
          }
          case ESocketOperation::E_CLOSE: {
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

        Win32SocketPipe* pipe = (Win32SocketPipe*)server->m_client_pipes[socket];
        if (pipe) {
          ::shutdown(socket, SD_BOTH);
          ::closesocket(socket);

          server->m_recv_allocator.deallocate(pipe->m_recv_buf_block);
          server->m_send_allocator.deallocate(pipe->m_send_buf_block);
          server->m_client_pipes.erase(socket);
          delete pipe;
        }

        if (server->m_socket_threads.find(socket) != server->m_socket_threads.end()) {
          server->m_socket_threads[socket].join();
          server->m_socket_threads.erase(socket);
        }
      }
    }

    return 0;
  }

  char* TCP_Server::Win32SocketPipe::recv_buf() {
    return (char*)m_server->m_recv_allocator.ptr(m_recv_buf_block);
  }

  uint32_t TCP_Server::Win32SocketPipe::recv_buf_size() {
    return m_server->m_recv_allocator.block_size();
  }

  char* TCP_Server::Win32SocketPipe::send_buf() {
    return (char*)m_server->m_send_allocator.ptr(m_send_buf_block);
  }

  uint32_t TCP_Server::Win32SocketPipe::send_buf_size() {
    return m_server->m_send_allocator.block_size();
  }

  bool TCP_Server::Win32SocketPipe::is_busy(EPipeOperation op) const {
    switch (op) {
    case EPipeOperation::E_RECV:
      return m_recv_buffer->IsBusy;
    case EPipeOperation::E_SEND:
      return m_send_buffer->IsBusy;
    case EPipeOperation::E_BOTH:
      return m_recv_buffer->IsBusy || m_send_buffer->IsBusy;
    }
    return false;
  }

  bool TCP_Server::Win32SocketPipe::open(const char* hostname, const char* port) {
    if (!m_server) {
      return false;
    }

    Win32SocketPipe* server_pipe = (Win32SocketPipe*)m_server->m_server_pipe;

    m_host_name = hostname;
    m_port = port;

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(port));
    inet_pton(AF_INET, hostname, &addr.sin_addr);

    uint64_t socket_ = ::WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_REGISTERED_IO);
    if (socket_ == INVALID_SOCKET) {
      return false;
    }

    ZeroMemory(&m_overlapped, sizeof(OVERLAPPED));

    m_recv_buf_block = m_server->m_recv_allocator.allocate();
    m_recv_buffer = new Tag_RIO_BUF(*server_pipe->m_recv_buffer);
    m_recv_buffer->Offset = m_server->m_recv_allocator.ofs(m_recv_buf_block);
    m_recv_buffer->Pipe = this;

    m_send_buf_block = m_server->m_send_allocator.allocate();
    m_send_buffer = new Tag_RIO_BUF(*server_pipe->m_send_buffer);
    m_send_buffer->Offset = m_server->m_send_allocator.ofs(m_send_buf_block);
    m_send_buffer->Pipe = this;

    m_completion_queue = server_pipe->m_completion_queue;
    m_completion_queue = server_pipe->m_completion_queue;

    m_request_queue = m_server->m_socket_io.rio.RIOCreateRequestQueue(
      socket_,
      RIO_PENDING_MAX, 1,
      RIO_PENDING_MAX, 1,
      m_completion_queue,
      m_completion_queue,
      this
    );

    m_iocp = server_pipe->m_iocp;
    m_socket = socket_;
    return true;
  }

  bool TCP_Server::Win32SocketPipe::open(uint64_t socket_) {
    if (!m_server) {
      return false;
    }

    Win32SocketPipe* server_pipe = (Win32SocketPipe*)m_server->m_server_pipe;

    int namelen = sizeof(sockaddr_in);
    sockaddr_in addr;

    int rc = getpeername(socket_, (sockaddr*)&addr, &namelen);
    if (rc == SOCKET_ERROR) {
      return false;
    }

    m_host_name.resize(INET_ADDRSTRLEN + 1);
    inet_ntop(AF_INET, &addr.sin_addr, (char*)m_host_name.data(), INET_ADDRSTRLEN);

    m_port = std::to_string(ntohs(addr.sin_port));

    ZeroMemory(&m_overlapped, sizeof(OVERLAPPED));

    m_recv_buf_block = m_server->m_recv_allocator.allocate();
    m_recv_buffer = new Tag_RIO_BUF(*server_pipe->m_recv_buffer);
    m_recv_buffer->Offset = m_server->m_recv_allocator.ofs(m_recv_buf_block);
    m_recv_buffer->Pipe = this;

    m_send_buf_block = m_server->m_send_allocator.allocate();
    m_send_buffer = new Tag_RIO_BUF(*server_pipe->m_send_buffer);
    m_send_buffer->Offset = m_server->m_send_allocator.ofs(m_send_buf_block);
    m_send_buffer->Pipe = this;

    m_completion_queue = server_pipe->m_completion_queue;
    m_completion_queue = server_pipe->m_completion_queue;

    m_request_queue = m_server->m_socket_io.rio.RIOCreateRequestQueue(
      socket_,
      RIO_PENDING_MAX, 1,
      RIO_PENDING_MAX, 1,
      m_completion_queue,
      m_completion_queue,
      this
    );

    m_iocp = server_pipe->m_iocp;
    m_socket = socket_;
    return true;
  }

  void TCP_Server::Win32SocketPipe::close() {
    m_server->close_socket(this);
  }

  void TCP_Server::Win32SocketPipe::error(ESocketErrorReason reason) {
    m_server->emit_error(this, EServerError::E_ERROR_SOCKET, (int)reason);
  }

  bool TCP_Server::Win32SocketPipe::recv(uint32_t offset, uint32_t* flags, uint32_t* unused) {
    if (m_recv_buffer->IsBusy) {
      return FALSE;
    }

    m_recv_buffer->Offset = m_server->m_recv_allocator.ofs(m_recv_buf_block) + offset;

    SocketInterface& socket_io = m_server->m_socket_io;
    BOOL rc = socket_io.rio.RIOReceive(m_request_queue, m_recv_buffer, 1, NULL, m_recv_buffer);
    if (rc) {
      m_recv_buffer->IsBusy = TRUE;
    }
    return rc;
  }

  bool TCP_Server::Win32SocketPipe::send(const char* data, uint32_t size, uint32_t* flags) {
    if (m_send_buffer->IsBusy) {
      return FALSE;
    }

    SocketInterface& socket_io = m_server->m_socket_io;

    char* send_buf = (char*)m_server->m_send_allocator.ptr(m_send_buf_block);
    uint32_t block_size = m_server->m_send_allocator.block_size();

    uint32_t chunk_size = min(size, block_size);
    memcpy_s(send_buf, (size_t)block_size, data, chunk_size);
    m_send_buffer->Length = (ULONG)chunk_size;

    uint32_t flags_ = flags ? *flags : 0;

    BOOL rc = socket_io.rio.RIOSend(m_request_queue, m_send_buffer, 1, flags_ & ~SKIP_BUF_INIT_FLAG, m_send_buffer);
    if (rc) {
      if ((flags_ & SKIP_BUF_INIT_FLAG) == 0) {
        m_send_data = data;
        m_send_size = size;
      }
      m_send_buffer->IsBusy = TRUE;
    }
    return rc;
  }

  bool TCP_Server::Win32SocketPipe::send(const HTTP_Response* response) {
    uint32_t request_buf_size = 0;
    const char* request_buf = HTTP_Response::build_buf(*response, &request_buf_size);
    return send(request_buf, request_buf_size, NULL) != 0;
  }

  bool TCP_Server::Win32SocketPipe::send(const HTTP_Request* request) {
    uint32_t request_buf_size = 0;
    const char* request_buf = HTTP_Request::build_buf(*request, &request_buf_size);
    return send(request_buf, request_buf_size, NULL) != 0;
  }

  bool TCP_Server::Win32SocketPipe::send(const RawPacket* packet) {
    return send(packet->m_message, packet->m_length, NULL) != 0;
  }

}  // namespace netpp

#endif

