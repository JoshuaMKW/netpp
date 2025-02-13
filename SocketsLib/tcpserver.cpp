#include "server.h"

#include <thread>

#define DEFAULT_THREAD_MAX 4

#ifdef _WIN32
#include <WS2tcpip.h>

#define RIO_PENDING_RECV_MAX 100
#define RIO_PENDING_SEND_MAX 100
#define RIO_MAX_BUFFERS 1024
#endif

static std::string build_http_response(const HTTP_Response* response) {
  std::string response_str =
    "HTTP/" + response->version() + " " + std::to_string((int)response->status_code()) + " " + http_response_status(response->status_code()) + "\r\n";

  // Headers
  const std::string* headers = response->headers();
  for (int i = 0; i < response->headers_count(); i++) {
    response_str += headers[i] + "\r\n";
  }

  // Body
  if (response->has_body()) {
    std::string body = response->body();
    response_str += "Content-Length: " + std::to_string(body.length()) + "\r\n";
    response_str += "\r\n";
    response_str += body;
  }

  return response_str;
}

StaticBlockAllocator::StaticBlockAllocator(void* buffer, size_t block_size, size_t block_count) {
  m_buffer = buffer;
  m_block_size = block_size;
  m_block_count = block_count;
  m_block_used.resize(block_count, false);
}

StaticBlockAllocator::~StaticBlockAllocator() {
  m_buffer = nullptr;
  m_block_size = 0;
  m_block_count = 0;
}

bool StaticBlockAllocator::initialize(void* buffer, size_t block_size, size_t block_count) {
  if (m_block_count > 0) {
    return false;
  }

  m_buffer = buffer;
  m_block_size = block_size;
  m_block_count = block_count;
  m_block_used.resize(block_count, false);
  return true;
}

size_t StaticBlockAllocator::allocate() {
  for (size_t i = 0; i < m_block_count; i++) {
    if (!m_block_used[i]) {
      m_block_used[i] = true;
      return i;
    }
  }

  return INVALID_BLOCK;
}

void StaticBlockAllocator::deallocate(size_t block) {
  if (block < m_block_count) {
    m_block_used[block] = false;
  }
}

void* StaticBlockAllocator::get_ptr(size_t block) const {
  if (block < m_block_count) {
    return (void*)((size_t)m_buffer + (block * m_block_size));
  }

  return nullptr;
}

size_t StaticBlockAllocator::get_ofs(size_t block) const {
  if (block < m_block_count) {
    return block * m_block_size;
  }

  return INVALID_BLOCK;
}

size_t StaticBlockAllocator::block(void* ptr) const {
  size_t block = ((size_t)ptr - (size_t)m_buffer) / m_block_size;
  if (block < m_block_count) {
    return block;
  }

  return INVALID_BLOCK;
}

TCP_Server::TCP_Server(int bufsize, int max_threads) {
  m_port = nullptr;
  m_error = EServerError::E_NONE;
  m_reason = -1;

  bufsize = bufsize > 0 ? bufsize : DEFAULT_BUFLEN;

  unsigned long granularity = 0;

#ifdef _WIN32
  SYSTEM_INFO sysinfo;
  ::GetSystemInfo(&sysinfo);

  granularity = sysinfo.dwAllocationGranularity;
#else
  granularity = sysconf(_SC_PAGESIZE);
#endif

  bufsize = (bufsize + granularity) & ~(granularity - 1);

#ifdef _WIN32
  m_recvbuf = (char*)VirtualAlloc(NULL, bufsize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  m_recvbuflen = bufsize;
  m_sendbuf = (char*)VirtualAlloc(NULL, bufsize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  m_sendbuflen = bufsize;
#else
  m_recvbuf = new char[bufsize];
  m_recvbuflen = bufsize;
  m_sendbuf = new char[bufsize];
  m_sendbuflen = bufsize;
#endif

  m_recv_allocator.initialize(m_recvbuf, bufsize / RIO_MAX_BUFFERS, RIO_MAX_BUFFERS);
  m_send_allocator.initialize(m_sendbuf, bufsize / RIO_MAX_BUFFERS, RIO_MAX_BUFFERS);

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

  m_request_callback = nullptr;
  m_receive_callback = nullptr;
}

TCP_Server::~TCP_Server() {
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
  return m_port != nullptr;  // Could be anything really
}

bool TCP_Server::start(const char* hostname, const char* port) {
  if (is_running()) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_STARTUP;
    return false;
  }

  m_host_name = hostname ? hostname : "localhost";
  m_port = port ? port : "8080";
#ifdef _WIN32
  return initialize_win32();
#else
  return initialize_unix();
#endif
}

void TCP_Server::stop() {
#ifdef _WIN32

  deinitialize_win32();
#else
  deinitialize_unix();
#endif
}

bool TCP_Server::send(int socket, const HTTP_Response* response) {
#ifdef _WIN32
  send_win32((SOCKET)socket, response, &m_server_pipe.m_overlapped, false);
#else
  send_unix(socket, packet, false);
#endif
  return m_error != EServerError::E_NONE;
}

bool TCP_Server::send(int socket, const RawPacket* packet) {
#ifdef _WIN32
  send_win32((SOCKET)socket, packet, &m_server_pipe.m_overlapped, false);
#else
  send_unix(socket, packet, false);
#endif
  return m_error != EServerError::E_NONE;
}

bool TCP_Server::is_startup_thread_cur() const {
  return m_startup_thread == std::this_thread::get_id();
}

bool TCP_Server::initialize_win32() {
#ifndef _WIN32
  m_error = EServerError::E_ERROR_SOCKET;
  return false;
#else

  if (!is_running()) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_STARTUP;
    return false;
  }

  int max_outstanding_recv = 1;
  int max_outstanding_send = 1;

  sockaddr_in server_addr;
  ZeroMemory(&server_addr, sizeof(server_addr));

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(atoi(m_port));
  server_addr.sin_addr.s_addr = INADDR_ANY;

  // -----------------------------
  // Create the socket and flag it for IOCP with RIO
  m_server_pipe.m_socket = (int)WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_REGISTERED_IO);
  if (m_server_pipe.m_socket == INVALID_SOCKET) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_SOCKET;
    goto cleanup;
  }

  // Initialize RIO and friends
  {
    DWORD bytes = 0;

    GUID rio_id = WSAID_MULTIPLE_RIO;
    GUID acceptex_id = WSAID_ACCEPTEX;
    GUID getacceptexsockaddrs_id = WSAID_GETACCEPTEXSOCKADDRS;

    // Get the RIO extension function table
    int rc = WSAIoctl(
      m_server_pipe.m_socket,
      SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
      &rio_id, sizeof(GUID),
      &m_socket_io.rio, sizeof(RIO_EXTENSION_FUNCTION_TABLE),
      &bytes, NULL, NULL
    );
    if (rc != 0) {
      int error = WSAGetLastError();
      m_error = EServerError::E_ERROR_SOCKET;
      m_reason = (int)ESocketErrorReason::E_REASON_SOCKET;
      goto cleanup;
    }

    // Get the AcceptEx function
    if (WSAIoctl(
      m_server_pipe.m_socket,
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
    if (WSAIoctl(
      m_server_pipe.m_socket,
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

  m_server_pipe.m_iocp = CreateIoCompletionPort((HANDLE)m_server_pipe.m_socket, NULL, 0, 0);
  if (m_server_pipe.m_iocp == NULL) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_SOCKET;
    goto cleanup;
  }

  // Initialize Overlapped structure
  ZeroMemory(&m_server_pipe.m_overlapped, sizeof(m_server_pipe.m_overlapped));

  // Create the completion queues and request queues
  RIO_NOTIFICATION_COMPLETION completion;
  completion.Type = RIO_IOCP_COMPLETION;
  completion.Iocp.IocpHandle = m_server_pipe.m_iocp;
  completion.Iocp.CompletionKey = (void*)m_server_pipe.m_socket;
  completion.Iocp.Overlapped = &m_server_pipe.m_overlapped;

  m_server_pipe.m_recv_completion_queue = m_socket_io.rio.RIOCreateCompletionQueue(RIO_PENDING_RECV_MAX, &completion);
  m_server_pipe.m_send_completion_queue = m_socket_io.rio.RIOCreateCompletionQueue(RIO_PENDING_SEND_MAX, &completion);
  if (m_server_pipe.m_recv_completion_queue == RIO_INVALID_CQ || m_server_pipe.m_send_completion_queue == RIO_INVALID_CQ) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_RESOURCES;
    goto cleanup;
  }

  m_server_pipe.m_request_queue = m_socket_io.rio.RIOCreateRequestQueue(
    m_server_pipe.m_socket,
    RIO_PENDING_RECV_MAX, 1,
    RIO_PENDING_SEND_MAX, 1,
    m_server_pipe.m_recv_completion_queue,
    m_server_pipe.m_send_completion_queue,
    &m_server_pipe
  );
  if (m_server_pipe.m_request_queue == RIO_INVALID_RQ) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_RESOURCES;
    goto cleanup;
  }

  m_server_pipe.m_recv_buffer->BufferId = m_socket_io.rio.RIORegisterBuffer(m_recvbuf, m_recvbuflen);
  if (m_server_pipe.m_recv_buffer->BufferId == RIO_INVALID_BUFFERID) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_RESOURCES;
    goto cleanup;
  }

  m_server_pipe.m_recv_buffer->Length = m_recvbuflen;
  m_server_pipe.m_recv_buf_block = m_recv_allocator.allocate();

  m_server_pipe.m_send_buffer->BufferId = m_socket_io.rio.RIORegisterBuffer(m_sendbuf, m_sendbuflen);
  if (m_server_pipe.m_send_buffer->BufferId == RIO_INVALID_BUFFERID) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_RESOURCES;
    goto cleanup;
  }
  m_server_pipe.m_send_buffer->Length = 0;
  m_server_pipe.m_send_buf_block = m_send_allocator.allocate();

  // -----------------------------

  if (bind(m_server_pipe.m_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_BIND;
    goto cleanup;
  }

  // -----------------------------
  // Listen on the socket to allow for an incoming connection
  if (listen(m_server_pipe.m_socket, SOMAXCONN) == SOCKET_ERROR) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_LISTEN;
    goto cleanup;
  }

  m_server_pipe.on_receive = m_receive_callback;
  m_server_pipe.on_request = m_request_callback;

  m_server_thread = std::thread(server_listen_thread_win32, this);
  m_cleanup_thread = std::thread(server_cleanup_thread_win32, this);

  // Spin up notifications for the completion queues
  m_socket_io.rio.RIONotify(m_server_pipe.m_recv_completion_queue);

cleanup:
  if (m_error != EServerError::E_NONE) {
    deinitialize_win32();
    return false;
  }

  return true;
#endif
}

void TCP_Server::deinitialize_win32() {
  m_port = nullptr;

  m_server_pipe.m_socket = INVALID_SOCKET;
  if (m_server_thread.joinable()) {
    m_server_thread.join();
  }

  if (m_cleanup_thread.joinable()) {
    m_cleanup_thread.join();
  }

  for (auto& thread : m_socket_threads) {
    if (thread.second.joinable()) {
      ::PostQueuedCompletionStatus(m_server_pipe.m_iocp, 0, (DWORD)ECompletionKey::E_STOP, NULL);
      thread.second.join();
    }
  }

  for (auto& pipe : m_client_pipes) {
    delete pipe.second;
  }

  m_socket_threads.clear();
  m_client_pipes.clear();

  if (m_server_pipe.m_recv_completion_queue != RIO_INVALID_CQ) {
    m_socket_io.rio.RIOCloseCompletionQueue(m_server_pipe.m_recv_completion_queue);
    m_server_pipe.m_recv_completion_queue = RIO_INVALID_CQ;
  }

  if (m_server_pipe.m_send_completion_queue != RIO_INVALID_CQ) {
    m_socket_io.rio.RIOCloseCompletionQueue(m_server_pipe.m_send_completion_queue);
    m_server_pipe.m_send_completion_queue = RIO_INVALID_CQ;
  }

  if (m_server_pipe.m_socket != INVALID_SOCKET) {
    closesocket(m_server_pipe.m_socket);
    m_server_pipe.m_socket = INVALID_SOCKET;
  }

  if (m_server_pipe.m_request_queue != RIO_INVALID_RQ) {
    m_server_pipe.m_request_queue = RIO_INVALID_RQ;
  }

  if (m_server_pipe.m_recv_buffer->BufferId != RIO_INVALID_BUFFERID) {
    m_socket_io.rio.RIODeregisterBuffer(m_server_pipe.m_recv_buffer->BufferId);
    m_server_pipe.m_recv_buffer->BufferId = RIO_INVALID_BUFFERID;
    m_recv_allocator.deallocate(m_server_pipe.m_recv_buf_block);
    m_server_pipe.m_recv_buf_block = StaticBlockAllocator::INVALID_BLOCK;
  }

  if (m_server_pipe.m_send_buffer->BufferId != RIO_INVALID_BUFFERID) {
    m_socket_io.rio.RIODeregisterBuffer(m_server_pipe.m_send_buffer->BufferId);
    m_server_pipe.m_send_buffer->BufferId = RIO_INVALID_BUFFERID;
    m_send_allocator.deallocate(m_server_pipe.m_send_buf_block);
    m_server_pipe.m_send_buf_block = StaticBlockAllocator::INVALID_BLOCK;
  }

  if (m_server_pipe.m_iocp) {
    CloseHandle(m_server_pipe.m_iocp);
    m_server_pipe.m_iocp = NULL;
  }
}

bool TCP_Server::initialize_unix() {
#ifdef _WIN32
  m_error = EServerError::E_ERROR_SOCKET;
  m_reason = (int)ESocketErrorReason::E_REASON_SOCKET;
  return false;
#endif

  // TODO: Implement this function
}

void TCP_Server::deinitialize_unix() {
#ifdef _WIN32
  m_error = EServerError::E_ERROR_SOCKET;
  m_reason = (int)ESocketErrorReason::E_REASON_SOCKET;
  return;
#endif

  // TODO: Implement this function
}

void TCP_Server::close_socket(SocketPipe* pipe) {
  m_purgatory_sockets.push(pipe->m_socket);
}

#ifdef _WIN32

size_t TCP_Server::recv_win32(SOCKET socket, char* recvbuf, size_t* recvmax, LPWSAOVERLAPPED overlapped, bool blocking) {
  WSABUF wsa_buf = { (ULONG)*recvmax, recvbuf };

  DWORD flags_io = 0;
  DWORD cb_transferred = 0;
  int rc = WSARecv(socket, &wsa_buf, 1, NULL, &flags_io, overlapped, NULL);
  if (rc != SOCKET_ERROR) {
    rc = WSAGetOverlappedResult(socket, overlapped, &cb_transferred, FALSE, &flags_io);
    if (rc == FALSE) {
      m_error = EServerError::E_ERROR_SOCKET;
      m_reason = (int)ESocketErrorReason::E_REASON_LISTEN;
      return 0;
    }
    return cb_transferred;
  }

  int error = WSAGetLastError();
  if (error != WSA_IO_PENDING) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_LISTEN;
    return -1;
  }

  if (!blocking) {
    return 0;
  }

  rc = WSAWaitForMultipleEvents(1, &overlapped->hEvent, TRUE, INFINITE, FALSE);
  if (rc == WSA_WAIT_FAILED) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_LISTEN;
    return 0;
  }

  DWORD flags;
  rc = WSAGetOverlappedResult(socket, overlapped, &cb_transferred, FALSE, &flags_io);
  if (rc == FALSE) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_LISTEN;
    return 0;
  }



  WSAResetEvent(overlapped->hEvent);
  return cb_transferred;
}

void TCP_Server::send_win32(SOCKET socket, const HTTP_Response* response, LPWSAOVERLAPPED overlapped, bool blocking) {
  std::string response_str = build_http_response(response);
  size_t response_size = response_str.size();

  CHAR* buf = new CHAR[response_size];
  memcpy_s(buf, response_size, response_str.data(), response_size);

  WSABUF wsa_buf = { (ULONG)response_size, (CHAR*)buf };

  DWORD flags_io = 0;
  DWORD cb_transferred = 0;
  int rc = WSASend(socket, &wsa_buf, 1, NULL, 0, overlapped, NULL);
  if (rc != SOCKET_ERROR) {
    return;
  }

  int error = WSAGetLastError();
  if (error != WSA_IO_PENDING) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_SEND;
    return;
  }

  if (!blocking) {
    return;
  }

  rc = WSAWaitForMultipleEvents(1, &overlapped->hEvent, TRUE, INFINITE, FALSE);
  if (rc == WSA_WAIT_FAILED) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_SEND;
    return;
  }

  rc = WSAGetOverlappedResult(socket, overlapped, &cb_transferred, FALSE, &flags_io);
  if (rc == FALSE) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_SEND;
    return;
  }

  WSAResetEvent(overlapped->hEvent);
}

void TCP_Server::send_win32(SOCKET socket, const RawPacket* packet, LPWSAOVERLAPPED overlapped, bool blocking) {
  CHAR* buf = new CHAR[packet->m_length];
  memcpy_s(buf, packet->m_length, packet->m_message, packet->m_length);

  WSABUF wsa_buf = { (ULONG)packet->m_length, (CHAR*)buf };

  DWORD flags_io = 0;
  DWORD cb_transferred = 0;
  int rc = WSASend(socket, &wsa_buf, 1, NULL, 0, overlapped, NULL);
  if (rc != SOCKET_ERROR) {
    return;
  }

  int error = WSAGetLastError();
  if (error != WSA_IO_PENDING) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_SEND;
    return;
  }

  if (!blocking) {
    return;
  }

  rc = WSAWaitForMultipleEvents(1, &overlapped->hEvent, TRUE, INFINITE, FALSE);
  if (rc == WSA_WAIT_FAILED) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_SEND;
    return;
  }

  rc = WSAGetOverlappedResult(socket, overlapped, &cb_transferred, FALSE, &flags_io);
  if (rc == FALSE) {
    m_error = EServerError::E_ERROR_SOCKET;
    m_reason = (int)ESocketErrorReason::E_REASON_SEND;
    return;
  }

  WSAResetEvent(overlapped->hEvent);
}
#else
void TCP_Server::send_unix(int socket, const HTTP_Response* response) {

}

void TCP_Server::send_unix(int socket, const RawPacket* packet) {

}
#endif

unsigned long __stdcall TCP_Server::server_listen_thread_win32(void* param) {
  TCP_Server* server = (TCP_Server*)param;
  SOCKET client_socket = INVALID_SOCKET;

  char hoststr[NI_MAXHOST];
  char servstr[NI_MAXSERV];

  SOCKADDR_STORAGE from;
  ZeroMemory(&from, sizeof(from));

  while (server->m_server_pipe.m_socket != INVALID_SOCKET) {
    // TODO: Accept clients or whatever tf I do with RIO here
    SOCKET client_socket = WSAAccept(server->m_server_pipe.m_socket, (sockaddr*)&from, NULL, NULL, 0);
    if (client_socket == INVALID_SOCKET) {
      server->m_error = EServerError::E_ERROR_SOCKET;
      server->m_reason = (int)ESocketErrorReason::E_REASON_SOCKET;
      continue;
    }

    SocketPipe* client_pipe = new SocketPipe;
    client_pipe->m_socket = client_socket;
    client_pipe->m_server = server;

    ZeroMemory(&client_pipe->m_overlapped, sizeof(OVERLAPPED));
    client_pipe->m_recv_buf_block = server->m_recv_allocator.allocate();
    client_pipe->m_recv_buffer = new Tag_RIO_BUF(*server->m_server_pipe.m_recv_buffer);
    client_pipe->m_send_buf_block = server->m_send_allocator.allocate();
    client_pipe->m_send_buffer = new Tag_RIO_BUF(*server->m_server_pipe.m_send_buffer);

#if 1
    RIO_NOTIFICATION_COMPLETION completion;
    completion.Type = RIO_IOCP_COMPLETION;
    completion.Iocp.IocpHandle = server->m_server_pipe.m_iocp;
    completion.Iocp.CompletionKey = (void*)ECompletionKey::E_START;
    completion.Iocp.Overlapped = &client_pipe->m_overlapped;

    client_pipe->m_recv_completion_queue = server->m_socket_io.rio.RIOCreateCompletionQueue(RIO_PENDING_RECV_MAX, &completion);
    client_pipe->m_send_completion_queue = server->m_socket_io.rio.RIOCreateCompletionQueue(RIO_PENDING_SEND_MAX, &completion);
#else
    client_pipe->m_recv_completion_queue = server->m_server_pipe.m_recv_completion_queue;
    client_pipe->m_send_completion_queue = server->m_server_pipe.m_send_completion_queue;
#endif

    client_pipe->m_request_queue = server->m_socket_io.rio.RIOCreateRequestQueue(
      client_socket,
      RIO_PENDING_RECV_MAX, 1,
      RIO_PENDING_SEND_MAX, 1,
      client_pipe->m_recv_completion_queue,
      client_pipe->m_send_completion_queue,
      client_pipe
    );

    client_pipe->m_iocp = server->m_server_pipe.m_iocp;

    client_pipe->on_close = [server](SocketPipe* self) {
      server->close_socket(self);
      };

    client_pipe->emit_error = [server](EServerError error, int reason) {
      server->m_error = error;
      server->m_reason = reason;
      };

    client_pipe->on_request = [server](const HTTP_Request* request) {
      if (server->m_request_callback) {
        return server->m_request_callback(request);
      }
      return (HTTP_Response*)nullptr;
      };

    client_pipe->on_receive = [server](const RawPacket* packet) {
      if (server->m_receive_callback) {
        return server->m_receive_callback(packet);
      }
      return (RawPacket*)nullptr;
      };

    server->m_client_pipes[client_socket] = client_pipe;
    server->m_socket_threads[client_socket] = std::thread(iocp_thread_win32, client_pipe);
  }

  return 0;
}

unsigned long __stdcall TCP_Server::server_cleanup_thread_win32(void* param) {
  TCP_Server* server = (TCP_Server*)param;

  while (server->m_server_pipe.m_socket != INVALID_SOCKET) {
    if (server->m_purgatory_sockets.size() > 0) {
      int socket = server->m_purgatory_sockets.front();
      server->m_purgatory_sockets.pop();

      SocketPipe* pipe = server->m_client_pipes[socket];
      if (pipe) {
        server->m_recv_allocator.deallocate(pipe->m_recv_buf_block);
        server->m_send_allocator.deallocate(pipe->m_send_buf_block);
        server->m_client_pipes.erase(socket);
        delete pipe;
      }

      if (server->m_socket_threads.find(socket) != server->m_socket_threads.end()) {
        server->m_socket_threads[socket].join();
        server->m_socket_threads.erase(socket);
      }

      closesocket(socket);
    }
  }

  return 0;
}

unsigned long __stdcall TCP_Server::iocp_thread_win32(void* param)
{
  SocketPipe* pipe = (SocketPipe*)param;
  SocketInterface& socket_io = pipe->m_server->m_socket_io;

  DWORD recv_size;
  ULONG_PTR completion_key;
  LPOVERLAPPED overlapped;

  // TODO: Figure out why the completion status never returns
  //       Establish defined structure (should multiple sockets be handled per iocp thread?)
  //       If so, what does that look like?
  while (pipe->m_socket != INVALID_SOCKET) {
    std::unique_lock<std::mutex> lock(pipe->m_mutex);

    int notify_res = socket_io.rio.RIONotify(pipe->m_recv_completion_queue);
    if (notify_res != ERROR_SUCCESS) {
      if (notify_res == WSAEALREADY) {
        continue;
      }
      else {
        pipe->emit_error(EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_LISTEN);
        goto close_socket;
      }
    }

    if (!pipe->recv(NULL)) {
      int err = WSAGetLastError();
      if (err != WSA_IO_PENDING) {
        pipe->emit_error(EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_LISTEN);
        goto close_socket;
      }
    }

    bool success = GetQueuedCompletionStatus(pipe->m_iocp, &recv_size, &completion_key, &overlapped, 10000);
    if (!success) {
      pipe->emit_error(EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_LISTEN);
      goto close_socket;
    }

    if (completion_key == (DWORD)ECompletionKey::E_STOP) {
      goto close_socket;
    }

    {
      RIORESULT results[16];
      ULONG count = socket_io.rio.RIODequeueCompletion(pipe->m_recv_completion_queue, results, 16);
      if (count == RIO_CORRUPT_CQ) {
        pipe->emit_error(EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_LISTEN);
        goto close_socket;
      }

      for (ULONG i = 0; i < count; i++) {
        RIORESULT* result = &results[i];
        if (result->Status != NO_ERROR) {
          pipe->emit_error(EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_LISTEN);
          continue;
        }

        Tag_RIO_BUF* buf = (Tag_RIO_BUF*)result->RequestContext;
        switch (buf->Operation) {
        case ESocketOperation::E_RECV: {
          // Get the transfered data if received
          if (result->BytesTransferred == 0) {
            continue;
          }

          bool request_handled = false;

          char* recv_buf = pipe->recv_buf();

          // Determine if the message is an HTTP request
          if (pipe->on_request) {
            HTTP_Request* client_req = HTTP_Request::create(recv_buf, result->BytesTransferred);
            if (client_req) {
              HTTP_Response* response = pipe->on_request(client_req);
              if (response) {
                pipe->send_response(response);
                delete response;
              }
              request_handled = true;
              delete client_req;
            }
          }

          if (pipe->on_receive && !request_handled) {
            RawPacket client_packet = { recv_buf, result->BytesTransferred };
            RawPacket* response = pipe->on_receive(&client_packet);
            if (response) {
              pipe->send_packet(response);
              delete response;
            }
            request_handled = true;
          }

          // If the request was not handled, send a 501 Not Implemented response
          if (!request_handled) {
            HTTP_Response* response = HTTP_Response::create(EHTTP_ResponseStatusCode::E_STATUS_NOT_IMPLEMENTED);
            if (!response) {
              pipe->emit_error(EServerError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_LISTEN);
              continue;
            }

            const char* html_body = "<!DOCTYPE html><html><body><h1>STATUS: 501\nNot Implemented.</h1></body></html>";

            response->add_header("Content-Type: text/html; charset=UTF-8");
            response->add_header("Connection: close");
            response->add_header("Content-Length: 79");
            response->set_body("<!DOCTYPE html><html><body><h1>STATUS: 501\nNot Implemented.</h1></body></html>");

            pipe->send_response(response);
          }
          break;
        }
        case ESocketOperation::E_SEND: {
          // Do nothing for now
          break;
        }
        case ESocketOperation::E_CLOSE: {
          goto close_socket;
        }
        }
      }  // End of completion for loop
    }  // End of lock
  }  // End of while loop

close_socket:
  pipe->on_close(pipe);
  return 0;
}

#ifdef _WIN32

char* TCP_Server::SocketPipe::recv_buf() {
  return m_server->m_recvbuf;
}

size_t TCP_Server::SocketPipe::recv_buf_size() {
  return m_server->m_recvbuflen;
}

char* TCP_Server::SocketPipe::send_buf() {
  return m_server->m_sendbuf;
}

size_t TCP_Server::SocketPipe::send_buf_size() {
  return m_server->m_sendbuflen;
}

int TCP_Server::SocketPipe::recv(DWORD* flags) {
  SocketInterface& socket_io = m_server->m_socket_io;
  return socket_io.rio.RIOReceive(m_request_queue, m_recv_buffer, 1, NULL, m_recv_buffer);
}

int TCP_Server::SocketPipe::send(const char* data, size_t size, DWORD* flags) {
  SocketInterface& socket_io = m_server->m_socket_io;

  size = min(size, m_server->m_sendbuflen);
  memcpy_s(m_server->m_sendbuf, m_server->m_sendbuflen, data, size);
  m_send_buffer->Length = size;

  return socket_io.rio.RIOSend(m_request_queue, m_send_buffer, 1, NULL, m_send_buffer);
}

bool TCP_Server::SocketPipe::send_response(const HTTP_Response* response) {
  std::string response_str = build_http_response(response);
  return send(response_str.c_str(), response_str.size(), NULL) != 0;
}

bool TCP_Server::SocketPipe::send_packet(const RawPacket* packet) {
  return send(packet->m_message, packet->m_length, NULL) != 0;
}

#else

#endif

