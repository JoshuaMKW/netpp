#include "client.h"
#include "protocol.h"

#include <cassert>
#include <chrono>
#include <thread>

using namespace std::chrono_literals;

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

    m_server_pipe = new TCP_Socket(nullptr, &m_recv_allocator, &m_send_allocator, ESocketHint::E_CLIENT);

    //m_send_spec.m_token_rate = 32000;       // 32KB/s
    //m_send_spec.m_token_bucket_size = 8000; // 8KB (1/4 of token rate)
    //m_send_spec.m_peak_bandwidth = 32000;   // 32KB/s
    //m_send_spec.m_max_latency = 100000;     // 100ms
    //m_send_spec.m_jitter_tolerance = 10000; // 10ms
    //m_send_spec.m_service_type = EServiceType::E_BEST_EFFORT;
    //m_send_spec.m_max_sdu_size = 1500;      // 1500 bytes (typical MTU)
    //m_send_spec.m_min_policed_size = 64;    // 64 bytes (typical MTU)

    //m_recv_spec.m_token_rate = 8000;       // 32KB/s
    //m_recv_spec.m_token_bucket_size = 2000; // 8KB (1/4 of token rate)
    //m_recv_spec.m_peak_bandwidth = 8000;   // 32KB/s
    //m_recv_spec.m_max_latency = 100000;     // 100ms
    //m_recv_spec.m_jitter_tolerance = 10000; // 10ms
    //m_recv_spec.m_service_type = EServiceType::E_BEST_EFFORT;
    //m_recv_spec.m_max_sdu_size = 1500;      // 1500 bytes (typical MTU)
    //m_recv_spec.m_min_policed_size = 64;    // 64 bytes (typical MTU)

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
    return m_iocp_thread.joinable() && !m_stop_flag;
  }

  bool TCP_Client::is_connected() const {
    return m_server_pipe;
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

    if (!m_server_pipe->open(hostname, port)) {
      return false;
    }

    if (!m_server_pipe->connect(timeout)) {
      return false;
    }

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

    m_server_pipe->on_error([this](ISocketPipe* pipe, ESocketErrorReason reason) {
      emit_error(pipe, EClientError::E_ERROR_SOCKET, (int)reason);
      return true;
      });

    m_connect_thread = std::thread(client_connect_thread, this);
    m_iocp_thread = std::thread(client_iocp_thread_win32, this);

    return true;
  }

  void TCP_Client::deinitialize() {
    std::unique_lock<std::mutex> lock(m_mutex);

    if (m_connect_thread.joinable()) {
      m_connect_thread.join();
    }

    if (m_iocp_thread.joinable()) {
      m_iocp_thread.join();
    }

    m_server_pipe->close();

    delete m_server_pipe;
    m_server_pipe = nullptr;
  }

  uint64_t TCP_Client::client_connect_thread(void* param) {
    TCP_Client* client = (TCP_Client*)param;

    SOCKADDR_STORAGE from;
    ZeroMemory(&from, sizeof(from));

    while (!client->is_running()) {}

    while (client->is_running()) {
      client->m_server_pipe->connect(0, client->m_recv_spec, client->m_send_spec);
      std::this_thread::sleep_for(500ms);
    }

    return 0;
  }

  uint64_t TCP_Client::client_iocp_thread_win32(void* param) {
    TCP_Client* client = (TCP_Client*)param;
    ISocketPipe* server_pipe = client->m_server_pipe;

    // TODO: Figure out why the completion status never returns
    //       Establish defined structure (should multiple sockets be handled per iocp thread?)
    //       If so, what does that look like?
    while (client->is_running()) {
      if (!client->is_connected()) {
        continue;
      }

      ISocketIOResult* sock_results = server_pipe->wait_results();
      if (!sock_results || !sock_results->is_valid()) {
        server_pipe->error(ESocketErrorReason::E_REASON_CORRUPT);
        return 0;
      }

      std::unique_lock<std::mutex> lock(client->m_mutex);

      sock_results->for_each([client, server_pipe](ISocketOSSupportLayer* pipe, const ISocketIOResult::OperationData& info) {
        IApplicationLayerAdapter* adapter = client->handle_inproc_recv(server_pipe->get_os_layer(), info);
        if (!adapter) {
          server_pipe->error(ESocketErrorReason::E_REASON_ADAPTER_UNKNOWN);
          return false;
        }

        if (!adapter->on_receive(server_pipe, pipe->recv_buf(), info.m_bytes_transferred, 0)) {
          server_pipe->error(ESocketErrorReason::E_REASON_ADAPTER_FAIL);
          return false;
        }

        return true;
      });
#endif
    }  // End of while loop

    return 0;
  }

  IApplicationLayerAdapter* TCP_Client::handle_inproc_recv(ISocketOSSupportLayer* pipe, const ISocketIOResult::OperationData& info) {
    bool is_message_complete = false;
    uint32_t message_size = 0;  // 0 == unknown size

    char* recv_buf = pipe->recv_buf();
    uint32_t recv_buf_offset = 0;
    uint32_t content_length = 0;

    IApplicationLayerAdapter* adapter = nullptr;

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

        adapter = ApplicationAdapterFactory::detect(recv_buf, info.m_bytes_transferred);
      }
    } while (!is_message_complete);

    return adapter;
  }

}  // namespace netpp
