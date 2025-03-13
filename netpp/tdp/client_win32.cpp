#include "client.h"
#include "protocol.h"

#include <cassert>
#include <thread>

#ifdef _WIN32

#define DEFAULT_THREAD_MAX 4
#define RIO_PENDING_MAX 5
#define RIO_MAX_BUFFERS 1024

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

namespace netpp {

  TCP_Client::TCP_Client(uint32_t bufsize) {
    m_error = EClientError::E_NONE;
    m_reason = -1;

    uint32_t desired_size = bufsize;

    uint32_t granularity = 0;

#ifdef _WIN32
    SYSTEM_INFO sysinfo;
    ::GetSystemInfo(&sysinfo);

    granularity = sysinfo.dwAllocationGranularity;
#else
    granularity = sysconf(_SC_PAGESIZE);
#endif

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

    m_startup_thread = std::this_thread::get_id();

    m_receive_callback = nullptr;
    m_request_callback = nullptr;
    m_response_callback = nullptr;

    m_server_pipe = nullptr;

    m_send_spec.m_token_rate = 32000;       // 32KB/s
    m_send_spec.m_token_bucket_size = 8000; // 8KB (1/4 of token rate)
    m_send_spec.m_peak_bandwidth = 32000;   // 32KB/s
    m_send_spec.m_max_latency = 100000;     // 100ms
    m_send_spec.m_jitter_tolerance = 10000; // 10ms
    m_send_spec.m_service_type = EServiceType::E_BEST_EFFORT;
    m_send_spec.m_max_sdu_size = 1500;      // 1500 bytes (typical MTU)
    m_send_spec.m_min_policed_size = 64;    // 64 bytes (typical MTU)

    m_recv_spec.m_token_rate = 8000;       // 32KB/s
    m_recv_spec.m_token_bucket_size = 2000; // 8KB (1/4 of token rate)
    m_recv_spec.m_peak_bandwidth = 8000;   // 32KB/s
    m_recv_spec.m_max_latency = 100000;     // 100ms
    m_recv_spec.m_jitter_tolerance = 10000; // 10ms
    m_recv_spec.m_service_type = EServiceType::E_BEST_EFFORT;
    m_recv_spec.m_max_sdu_size = 1500;      // 1500 bytes (typical MTU)
    m_recv_spec.m_min_policed_size = 64;    // 64 bytes (typical MTU)

    m_stop_flag = false;
  }

  TCP_Client::~TCP_Client() {
    assert(is_startup_thread_cur() && "Client must be destroyed on the same thread it was created on.");
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

  bool TCP_Client::is_running() const {
    return m_server_pipe && !m_stop_flag;
  }

  bool TCP_Client::is_connected() const {
    return m_server_pipe && ((Win32SocketPipe*)m_server_pipe)->m_connected;
  }

  bool TCP_Client::start() {
    if (is_running()) {
      m_error = EClientError::E_ERROR_SOCKET;
      m_reason = (int)ESocketErrorReason::E_REASON_STARTUP;
      return false;
    }

    return initialize();
  }

  void TCP_Client::stop() {
    assert(is_startup_thread_cur() && "Client must be stopped on the same thread it was created on.");
    {
      std::unique_lock<std::mutex> lock(m_mutex);
      m_stop_flag = true;
    }
    deinitialize();
  }

  bool TCP_Client::connect(const char* hostname, const char* port, uint64_t timeout) {
    if (!is_running()) {
      emit_error(nullptr, EClientError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_STARTUP);
      return false;
    }

    Win32SocketPipe* server_pipe = (Win32SocketPipe*)m_server_pipe;
    server_pipe->open(hostname, port);

    using namespace std::chrono;

    // Get now in milliseconds
    uint64_t start_ = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    uint64_t now_ = start_;

    bool check_timeout = timeout > 0;

    do {
      if (server_pipe->m_connected) {
        break;
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(16));
      now_ = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    } while (!check_timeout || now_ - start_ < timeout);

    return true;
  }

  void TCP_Client::disconnect() {
    if (!is_running()) {
      emit_error(nullptr, EClientError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_STARTUP);
      return;
    }

    m_server_pipe->close();
  }

  bool TCP_Client::send(const HTTP_Request* request) {
    if (!is_connected()) {
      return false;
    }

    if (!m_server_pipe->send(request)) {
      emit_error(m_server_pipe, EClientError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_SEND);
      return false;
    }

    return true;
  }

  bool TCP_Client::send(const RawPacket* packet) {
    if (!is_connected()) {
      return false;
    }

    if (!m_server_pipe->send(packet)) {
      emit_error(m_server_pipe, EClientError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_SEND);
      return false;
    }

    return true;
  }

  void TCP_Client::emit_error(ISocketPipe* pipe, EClientError error, int reason) {
    m_error = error;
    m_reason = reason;

    const char* error_str = client_error(error, reason);

    if (pipe) {
      if (pipe == m_server_pipe) {
        fprintf(stderr, "[SERVER] ERROR: Port %s:%s (SERVER) failed with reason: %s\n", pipe->hostname().c_str(), pipe->port().c_str(), error_str);
      }
      else {
        fprintf(stderr, "[SERVER] ERROR: Port %s:%s (CLIENT: %llu) failed with reason: %s\n", pipe->hostname().c_str(), pipe->port().c_str(), pipe->socket(), error_str);
      }
    }
    else {
      fprintf(stderr, "[SERVER] ERROR: Client (PROCESS) failed with reason: %s\n", error_str);
    }
  }

  bool TCP_Client::is_startup_thread_cur() const {
    return m_startup_thread == std::this_thread::get_id();
  }

  bool TCP_Client::initialize() {
    if (is_running()) {
      emit_error(nullptr, EClientError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_STARTUP);
      return false;
    }

    Win32SocketPipe* server_pipe = new Win32SocketPipe(this);
    m_server_pipe = server_pipe;

    server_pipe->on_receive(m_receive_callback);
    server_pipe->on_request(m_request_callback);
    server_pipe->on_response(m_response_callback);

    m_connect_thread = std::thread(client_connect_thread, this);
    m_iocp_thread = std::thread(client_iocp_thread_win32, this);

    if (m_error != EClientError::E_NONE) {
      deinitialize();
      return false;
    }

    return true;
  }

  void TCP_Client::deinitialize() {
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

    if (m_connect_thread.joinable()) {
      m_connect_thread.join();
    }

    if (m_iocp_thread.joinable()) {
      m_iocp_thread.join();
    }

    delete server_pipe;
    m_server_pipe = nullptr;
  }

  uint64_t TCP_Client::client_connect_thread(void* param) {
    TCP_Client* client = (TCP_Client*)param;
    Win32SocketPipe* server_pipe = (Win32SocketPipe*)client->m_server_pipe;

    SOCKADDR_STORAGE from;
    ZeroMemory(&from, sizeof(from));

    while (client->is_running()) {
      if (server_pipe->socket() == INVALID_SOCKET) {
        goto sleep_thread;
      }

      {
        std::unique_lock<std::mutex> lock(client->m_mutex);

        const std::string& hostname = server_pipe->hostname();
        const std::string& port = server_pipe->port();

        if (hostname.empty() || port.empty()) {
          goto sleep_thread;
        }

        // Connect to the server...
        sockaddr_in server_addr;
        ZeroMemory(&server_addr, sizeof(server_addr));

        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(atoi(port.c_str()));
        inet_pton(AF_INET, hostname.c_str(), &server_addr.sin_addr);

        QOS qos;
        ZeroMemory(&qos, sizeof(qos));

        qos.SendingFlowspec.DelayVariation = client->m_send_spec.m_jitter_tolerance;
        qos.SendingFlowspec.ServiceType = (int)client->m_send_spec.m_service_type;
        qos.SendingFlowspec.TokenRate = client->m_send_spec.m_token_rate;
        qos.SendingFlowspec.TokenBucketSize = client->m_send_spec.m_token_bucket_size;
        qos.SendingFlowspec.PeakBandwidth = client->m_send_spec.m_peak_bandwidth;
        qos.SendingFlowspec.MaxSduSize = client->m_send_spec.m_max_sdu_size;
        qos.SendingFlowspec.MinimumPolicedSize = client->m_send_spec.m_min_policed_size;

        qos.ReceivingFlowspec.DelayVariation = client->m_recv_spec.m_jitter_tolerance;
        qos.ReceivingFlowspec.ServiceType = (int)client->m_recv_spec.m_service_type;
        qos.ReceivingFlowspec.TokenRate = client->m_recv_spec.m_token_rate;
        qos.ReceivingFlowspec.TokenBucketSize = client->m_recv_spec.m_token_bucket_size;
        qos.ReceivingFlowspec.PeakBandwidth = client->m_recv_spec.m_peak_bandwidth;
        qos.ReceivingFlowspec.MaxSduSize = client->m_recv_spec.m_max_sdu_size;
        qos.ReceivingFlowspec.MinimumPolicedSize = client->m_recv_spec.m_min_policed_size;

        // TODO: Potentially handle QOS differently here
        qos.ProviderSpecific.buf = (char*)&qos;
        qos.ProviderSpecific.len = sizeof(qos);

        addrinfo hints;
        ::ZeroMemory(&hints, sizeof(hints));

        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        addrinfo* result = nullptr;
        int rc = ::getaddrinfo(server_pipe->m_host_name.c_str(), server_pipe->m_port.c_str(), &hints, &result);
        if (rc != 0) {
          client->emit_error(nullptr, EClientError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_ADDRESS);
          goto sleep_thread;
        }

#if CLIENT_USE_WSA
        if (::WSAConnect(server_pipe->socket(), result->ai_addr, (int)result->ai_addrlen, NULL, NULL, &qos, NULL) == SOCKET_ERROR) {
          int rc = ::WSAGetLastError();
          if (rc == WSAEISCONN) {
            goto sleep_thread;
          }
          else {
            if (rc != WSAEWOULDBLOCK && rc != WSAECONNREFUSED) {
              client->emit_error(nullptr, EClientError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_LISTEN);
            }
            // Error connecting to the server (server is down?)
            goto sleep_thread;
          }

          fd_set write_set;
          FD_ZERO(&write_set);
          FD_SET(server_pipe->socket(), &write_set);

          // Check for connection completion
          timeval timeout = { 10, 0 };
          if (::select(0, NULL, &write_set, NULL, &timeout) <= 0) {
            client->emit_error(nullptr, EClientError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_LISTEN);
            goto sleep_thread;
          }

          int error = 0;
          int error_size = sizeof(error);
          if (::getsockopt(server_pipe->socket(), SOL_SOCKET, SO_ERROR, (char*)&error, &error_size) == 0) {
            if (error != 0) {
              client->emit_error(nullptr, EClientError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_LISTEN);
              goto sleep_thread;
            }
          }
        }

        server_pipe->m_connected = true;
        server_pipe->m_connecting = false;

        uint32_t flags = 0;
        uint32_t transferred = 0;
        if (!server_pipe->recv(&flags, &transferred)) {
          server_pipe->error(ESocketErrorReason::E_REASON_LISTEN);
          server_pipe->close();
          goto sleep_thread;
        }
#else
        if (::connect(server_pipe->socket(), (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
          //client->emit_error(nullptr, EClientError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_LISTEN);
          fprintf(stderr, "[CLIENT: %llu] ERROR: Server connection failed... retrying in 1s\n", server_pipe->m_socket);
          goto sleep_thread;
        }

        server_pipe->m_connected = true;
        server_pipe->m_connecting = false;
#endif
      }  // End of lock

      // Connection successful!
      // Periodically ensure the connection is still alive
      // If not, attempt to reconnect
      while (client->is_running()) {
        if (server_pipe->socket() == INVALID_SOCKET || server_pipe->is_busy(EPipeOperation::E_RECV)) {
          goto sleep_thread;
        }

        {
          std::unique_lock<std::mutex> lock(client->m_mutex);

#if CLIENT_USE_WSA
          // Check if the connection is still alive
          uint32_t flags = MSG_PEEK;
          BOOL rc = ::WSARecv(server_pipe->m_socket, server_pipe->m_recv_buffer, 1, NULL, (LPDWORD)&flags, server_pipe->m_recv_overlapped, NULL);
          if (rc <= 0) {
            int error = ::WSAGetLastError();
            if (error == WSA_IO_PENDING || error == 0) {
              // Connection is still alive
            }
            else {
              // Connection was closed
              server_pipe->error(ESocketErrorReason::E_REASON_LISTEN);
              server_pipe->close();
              break;
            }
          }
#else
          char buf[1];
          int rc = ::recv(server_pipe->socket(), buf, 1, MSG_PEEK);
          if (rc <= 0) {
            // Connection was closed
            //server_pipe->error(ESocketErrorReason::E_REASON_LISTEN);
            fprintf(stderr, "[CLIENT: %llu] ERROR: Server connection closed... retrying in 1s\n", server_pipe->m_socket);
            server_pipe->close();
            goto sleep_thread;
          }
#endif
        }  // End of lock

        // Connection is still alive, sleep for a bit
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
      }

    sleep_thread:
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }


    return 0;
  }

  uint64_t TCP_Client::client_iocp_thread_win32(void* param) {
    TCP_Client* client = (TCP_Client*)param;
    Win32SocketPipe* server_pipe = (Win32SocketPipe*)client->m_server_pipe;

#if CLIENT_USE_WSA
    DWORD transferred_;
    ULONG_PTR completion_key;
    LPOVERLAPPED overlapped;
#endif

    // TODO: Figure out why the completion status never returns
    //       Establish defined structure (should multiple sockets be handled per iocp thread?)
    //       If so, what does that look like?
    while (client->is_running()) {
#if CLIENT_USE_WSA
      if (server_pipe->m_iocp == INVALID_HANDLE_VALUE) {
        continue;
      }

      bool success = ::GetQueuedCompletionStatus(server_pipe->m_iocp, &transferred_, &completion_key, &overlapped, INFINITE);
      if (!success) {
        int rc = ::WSAGetLastError();
        if (server_pipe->socket() == INVALID_SOCKET) {
          continue;
        }
        server_pipe->error(ESocketErrorReason::E_REASON_LISTEN);
        continue;
      }

      if (completion_key == (DWORD)ECompletionKey::E_STOP) {
        return 0;
      }

      {
        std::unique_lock<std::mutex> lock(server_pipe->m_mutex);

        Tag_WSA_BUF* buf = (Tag_WSA_BUF*)overlapped->Pointer;
        Win32SocketPipe* pipe = (Win32SocketPipe*)buf->Pipe;

        switch (buf->Operation) {
        case ESocketOperation::E_RECV: {
          // Get the transfered data if received
          if (transferred_ == 0) {
            buf->IsBusy = false;
            continue;
          }

          bool request_handled = false;

          char* recv_buf = pipe->recv_buf();

          // Determine if the message is an HTTP request
          if (pipe->m_on_response) {
            HTTP_Response* client_req = HTTP_Response::create(recv_buf, transferred_);
            if (client_req) {
              HTTP_Request* response = pipe->m_on_response(pipe, client_req);
              if (response) {
                pipe->send(response);
                delete response;
              }
              request_handled = true;
              delete client_req;
            }
          }

          if (pipe->m_on_receive && !request_handled) {
            RawPacket client_packet = { *(uint64_t*)recv_buf, recv_buf + 8, transferred_ };
            RawPacket* response = pipe->m_on_receive(pipe, &client_packet);
            if (response) {
              pipe->send(response);
              delete response;
            }
            request_handled = true;
          }

          if (!request_handled) {
            fprintf(stderr, "[CLIENT] ERROR: Request not handled\n");
          }

          pipe->recv(NULL, NULL);
          break;
        }
        case ESocketOperation::E_SEND: {
          // Do nothing for now
          break;
        }
        case ESocketOperation::E_CLOSE: {
          pipe->close();
          break;
        }
        }
        buf->IsBusy = false;
      }  // End of lock
#else
      if (!client->is_connected()) {
        continue;
      }

      std::unique_lock<std::mutex> lock(server_pipe->m_mutex);
      Win32SocketPipe* pipe = (Win32SocketPipe*)client->m_server_pipe;

      bool is_message_complete = false;
      uint32_t message_size = 0;  // 0 == unknown size

      char* recv_buf = pipe->recv_buf();
      uint32_t recv_buf_offset = 0;
      uint32_t content_length = 0;

      EApplicationLayerProtocol protocol = EApplicationLayerProtocol::E_NONE;

      do {
        uint32_t flags = 0;
        uint32_t transferred = 0;
        bool recv_result = pipe->recv(recv_buf_offset, &flags, &transferred);
        if (!recv_result) {
          continue;
        }

        const char* http_header_begin = HTTP_Response::header_begin(recv_buf, transferred);
        if (!http_header_begin) {
          // Not HTTP, treat as raw packet

          // If the message size is not known, read the first 4 bytes
          if (recv_buf_offset == 0) {
            message_size = *(uint32_t*)recv_buf;
          }

          // Advance the buffer offset
          recv_buf_offset += transferred;
          is_message_complete = recv_buf_offset >= message_size;
        }
        else {
          // HTTP, treat as HTTP request
          recv_buf_offset += transferred;

          if (content_length == 0) {
            if (const char* h_end = HTTP_Response::header_end(recv_buf, recv_buf_offset)) {
              content_length = HTTP_Response::content_length(recv_buf, recv_buf_offset);
              message_size =
                ((uint32_t)(h_end - recv_buf) + 4) + content_length;
            }
          }

          is_message_complete = message_size > 0 && recv_buf_offset >= message_size;
        }
      } while (!is_message_complete);


      bool request_handled = false;

      // Determine if the message is an HTTP request
      if (pipe->m_on_response) {
        HTTP_Response* client_req = HTTP_Response::create(recv_buf, message_size);
        if (client_req) {
          HTTP_Request* response = pipe->m_on_response(pipe, client_req);
          if (response) {
            pipe->send(response);
            delete response;
          }
          request_handled = true;
          delete client_req;
        }
      }

      if (pipe->m_on_receive && !request_handled) {
        RawPacket client_packet = { recv_buf, message_size };
        RawPacket* response = pipe->m_on_receive(pipe, &client_packet);
        if (response) {
          pipe->send(response);
          delete response;
        }
        request_handled = true;
      }

      if (!request_handled) {
        fprintf(stderr, "[CLIENT] ERROR: Request not handled\n");
      }
#endif
    }  // End of while loop

    return 0;
  }

  void TCP_Client::wsa_completion_callback(DWORD dwError, DWORD cbTransferred, LPWSAOVERLAPPED lpOverlapped, DWORD dwFlags) {
    Tag_WSA_OVERLAPPED* overlapped = (Tag_WSA_OVERLAPPED*)lpOverlapped;
    Tag_WSA_BUF* buf = (Tag_WSA_BUF*)overlapped->Buffer;
    buf->IsBusy = FALSE;
  }

  char* TCP_Client::Win32SocketPipe::recv_buf() {
    return m_client->m_recvbuf;
  }

  uint32_t TCP_Client::Win32SocketPipe::recv_buf_size() {
    return m_client->m_recvbuflen;
  }

  char* TCP_Client::Win32SocketPipe::send_buf() {
    return m_client->m_sendbuf;
  }

  uint32_t TCP_Client::Win32SocketPipe::send_buf_size() {
    return m_client->m_sendbuflen;
  }

  bool TCP_Client::Win32SocketPipe::is_busy(EPipeOperation op) const {
    switch (op) {
    case EPipeOperation::E_RECV:
      return m_recv_buffer->IsBusy;
    case EPipeOperation::E_SEND:
      return m_send_buffer->IsBusy;
    case EPipeOperation::E_RECV_SEND:
      return m_recv_buffer->IsBusy || m_send_buffer->IsBusy;
    }
    return false;
  }

  bool TCP_Client::Win32SocketPipe::open(const char* hostname, const char* port) {
    if (!m_client) {
      error(ESocketErrorReason::E_REASON_SOCKET);
      return false;
    }


#if 0
    if (m_socket != INVALID_SOCKET) {
      m_host_name = hostname;
      m_port = port;
      m_connecting = true;
      return true;
    }
#endif

#if CLIENT_USE_WSA
    // -----------------------------
    // Create the socket and flag it for IOCP

    m_socket = (int)::WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (m_socket == INVALID_SOCKET) {
      error(ESocketErrorReason::E_REASON_SOCKET);
      return false;
    }
    // -----------------------------

    m_recv_overlapped->hEvent = NULL;
    m_send_overlapped->hEvent = NULL;

    m_iocp = ::CreateIoCompletionPort((HANDLE)m_iocp, NULL, (int)ECompletionKey::E_START, 0);
    if (m_iocp == NULL) {
      error(ESocketErrorReason::E_REASON_SOCKET);
      return false;
    }

    GUID guid = WSAID_DISCONNECTEX;
    DWORD bytes = 0;
    if (WSAIoctl(m_socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(GUID), &DisconnectEx, sizeof(LPFN_DISCONNECTEX), &bytes, NULL, NULL) == SOCKET_ERROR) {
      error(ESocketErrorReason::E_REASON_SOCKET);
      return false;
    }
#else
    m_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_socket == INVALID_SOCKET) {
      error(ESocketErrorReason::E_REASON_SOCKET);
      return false;
    }
#endif

    m_host_name = hostname;
    m_port = port;
    m_connecting = true;

    return true;
  }

  void TCP_Client::Win32SocketPipe::close() {
    if (m_socket != INVALID_SOCKET) {
#if 1
      ::shutdown(m_socket, SD_BOTH);
      ::closesocket(m_socket);
      m_connected = false;
      m_connecting = false;
      m_socket = INVALID_SOCKET;
#else
      if (!DisconnectEx(m_socket, m_recv_overlapped, TF_REUSE_SOCKET, NULL)) {
        if (::WSAGetLastError() != WSA_IO_PENDING) {
          error(ESocketErrorReason::E_REASON_SOCKET);
        }
      }
      m_connected = false;
#endif
    }
    m_host_name = "";
    m_port = "";
  }

  void TCP_Client::Win32SocketPipe::error(ESocketErrorReason reason) {
    m_client->emit_error(this, EClientError::E_ERROR_SOCKET, (int)reason);
  }

  bool TCP_Client::Win32SocketPipe::recv(uint32_t offset, uint32_t* flags, uint32_t* unused) {
    if (m_recv_buffer->IsBusy) {
      return false;
    }

#if CLIENT_USE_WSA
    bool rc = ::WSARecv(m_socket, m_recv_buffer, 1, NULL, (LPDWORD)flags, m_recv_overlapped, NULL);
    if (!rc) {
      int err = ::WSAGetLastError();
      if (err == WSA_IO_PENDING) {
        m_recv_buffer->IsBusy = TRUE;
      }
      else if (err != 0) {
        error(ESocketErrorReason::E_REASON_SEND);
        return false;
      }
    }
    return true;
#else
    int flags_ = flags ? *flags : 0;
    *unused = ::recv(m_socket, m_recv_buffer->buf + offset, m_client->m_recvbuflen - offset, flags_);
    if (*unused == 0) {
      error(ESocketErrorReason::E_REASON_PORT);
      return false;
    }
    else if (*(int*)unused == INVALID_SOCKET) {
      error(ESocketErrorReason::E_REASON_SOCKET);
      return false;
    }
    return true;
#endif
  }

  bool TCP_Client::Win32SocketPipe::send(const char* data, uint32_t size, uint32_t* flags) {
    if (m_send_buffer->IsBusy) {
      return false;
    }

    using namespace std::chrono;

    size = min(size, m_client->m_sendbuflen);
    memcpy_s(m_send_buffer->buf, m_client->m_sendbuflen, data, size);
    m_send_buffer->len = size;

    uint32_t flags_ = flags ? *flags : 0;

#if CLIENT_USE_WSA
    bool rc = WSASend(m_socket, m_send_buffer, 1, NULL, flags_, m_send_overlapped, NULL);
    if (!rc) {
      int err = ::WSAGetLastError();
      if (err == WSA_IO_PENDING) {
        m_send_buffer->IsBusy = TRUE;
      }
      else if (err != 0) {
        error(ESocketErrorReason::E_REASON_SEND);
        return false;
      }
    }
    return true;
#else
    int rc = ::send(m_socket, m_send_buffer->buf, m_send_buffer->len, flags_);
    if (rc == SOCKET_ERROR) {
      error(ESocketErrorReason::E_REASON_SEND);
      return false;
    }
    return true;
#endif
  }

  bool TCP_Client::Win32SocketPipe::send(const HTTP_Response* response) {
    return false;
  }

  bool TCP_Client::Win32SocketPipe::send(const HTTP_Request* request) {
    std::string response_str = HTTP_Request::build(*request);
    return send(response_str.c_str(), (uint32_t)response_str.size(), NULL) != 0;
  }

  bool TCP_Client::Win32SocketPipe::send(const RawPacket* packet) {
    return send(packet->m_message, packet->m_length, NULL) != 0;
  }

  void TCP_Client::Win32SocketPipe::signal_close() {
    if (m_on_close) {
      m_on_close(this);
    }
  }

  const DNS_Response* TCP_Client::Win32SocketPipe::signal_dns_request(const DNS_Request* request) {
    if (m_on_dns_request) {
      return m_on_dns_request(this, request);
    }
    return nullptr;
  }

  const DNS_Request* TCP_Client::Win32SocketPipe::signal_dns_response(const DNS_Response* response) {
    if (m_on_dns_response) {
      return m_on_dns_response(this, response);
    }
    return nullptr;
  }

  const HTTP_Response* TCP_Client::Win32SocketPipe::signal_http_request(const HTTP_Request* request) {
    if (m_on_http_request) {
      return m_on_http_request(this, request);
    }
    return nullptr;
  }

  const HTTP_Request* TCP_Client::Win32SocketPipe::signal_http_response(const HTTP_Response* response) {
    if (m_on_http_response) {
      return m_on_http_response(this, response);
    }
    return nullptr;
  }

  const RawPacket* TCP_Client::Win32SocketPipe::signal_raw_receive(const RawPacket* packet) {
    if (m_on_raw_receive) {
      return m_on_raw_receive(this, packet);
    }
    return nullptr;
  }

  void TCP_Client::Win32SocketPipe::signal_rtp_packet(const RTP_Packet* packet) {
    if (m_on_rtp_packet) {
      m_on_rtp_packet(this, packet);
    }
  }

  void TCP_Client::Win32SocketPipe::signal_rtcp_packet(const RTCP_Packet* packet) {
    if (m_on_rtcp_packet) {
      m_on_rtcp_packet(this, packet);
    }
  }

  const SIP_Response* TCP_Client::Win32SocketPipe::signal_sip_request(const SIP_Request* request) {
    if (m_on_sip_request) {
      return m_on_sip_request(this, request);
    }
    return nullptr;
  }

  const SIP_Request* TCP_Client::Win32SocketPipe::signal_sip_response(const SIP_Response* response) {
    if (m_on_sip_response) {
      return m_on_sip_response(this, response);
    }
    return nullptr;
  }

}  // namespace netpp

#endif
