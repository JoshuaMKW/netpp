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

  TCP_Client::TCP_Client(bool use_tls_ssl, const char* key_file, const char* cert_file, uint32_t desired_bufsize) : m_recv_spec(), m_send_spec() {
    m_tls_ssl = use_tls_ssl;

    m_error = EClientError::E_NONE;
    m_reason = -1;

    constexpr uint32_t bufcount = 2;

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

    m_startup_thread = std::this_thread::get_id();

    ISocketPipe* pipe = new TCP_Socket(nullptr, &m_recv_allocator, &m_send_allocator, ESocketHint::E_CLIENT);
    if (m_tls_ssl) {
      m_server_socket.m_pipe = new TLS_SocketProxy(pipe, key_file, cert_file);
    }
    else {
      m_server_socket.m_pipe = pipe;
    }

    m_server_socket.m_recv_state = { nullptr, 0, 0 };
    m_server_socket.m_send_state = { nullptr, 0, 0 };

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
    return m_server_socket.m_pipe->is_ready(netpp::EPipeOperation::E_NONE);
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

    if (!m_server_socket.m_pipe->open(hostname, port)) {
      return false;
    }

    if (!m_server_socket.m_pipe->connect(timeout)) {
      return false;
    }

    // Expect an authentication packet
    EIOState state = m_server_socket.m_pipe->recv(0, nullptr, nullptr);
    if (state == EIOState::E_ERROR) {
      return false;
    }

    // Just in case it is somehow busy, wait for it to finish
    while (state == EIOState::E_BUSY) {
      std::this_thread::sleep_for(16ms);
      state = m_server_socket.m_pipe->recv(0, nullptr, nullptr);
    }

    while (!m_handshake_done) {
      std::this_thread::sleep_for(16ms);
    }

    return true;
  }

  void TCP_Client::disconnect() {
    if (!is_running()) {
      emit_error(nullptr, EClientError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_STARTUP);
      return;
    }

    m_server_socket.m_pipe->close();
  }

  bool TCP_Client::send(const HTTP_Request* request) {
    if (!is_connected()) {
      return false;
    }

    EIOState state = m_server_socket.m_pipe->send(request);
    if (state == EIOState::E_ERROR) {
      emit_error(m_server_socket.m_pipe, EClientError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_SEND);
      return false;
    }

    if (state == EIOState::E_BUSY) {
      emit_error(m_server_socket.m_pipe, EClientError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_SEND);
      return false;
    }

    return true;
  }

  bool TCP_Client::send(const RawPacket* packet) {
    if (!is_connected()) {
      return false;
    }

    EIOState state = m_server_socket.m_pipe->send(packet);
    if (state == EIOState::E_ERROR) {
      emit_error(m_server_socket.m_pipe, EClientError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_SEND);
      return false;
    }

    if (state == EIOState::E_BUSY) {
      emit_error(m_server_socket.m_pipe, EClientError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_SEND);
      return false;
    }

    return true;
  }

  void TCP_Client::emit_error(ISocketPipe* pipe, EClientError error, int reason) {
    m_error = error;
    m_reason = reason;

    const char* error_str = client_error(error, reason);

    if (pipe) {
      if (pipe == m_server_socket.m_pipe) {
        fprintf(stderr, "[CLIENT] ERROR: Port %s:%s (SERVER) failed with reason: %s\n", pipe->hostname().c_str(), pipe->port().c_str(), error_str);
      }
      else {
        fprintf(stderr, "[CLIENT] ERROR: Port %s:%s (CLIENT: %llu) failed with reason: %s\n", pipe->hostname().c_str(), pipe->port().c_str(), pipe->socket(), error_str);
      }
    }
    else {
      fprintf(stderr, "[CLIENT] ERROR: Client (PROCESS) failed with reason: %s\n", error_str);
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

    m_server_socket.m_pipe->on_error([this](ISocketPipe* pipe, ESocketErrorReason reason) {
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

    m_server_socket.m_pipe->close();

    delete m_server_socket.m_pipe;
    m_server_socket.m_pipe = nullptr;
  }

  uint64_t TCP_Client::client_connect_thread(void* param) {
    TCP_Client* client = (TCP_Client*)param;

    SOCKADDR_STORAGE from;
    ZeroMemory(&from, sizeof(from));

    while (!client->m_server_socket.m_pipe->is_ready(EPipeOperation::E_RECV_SEND)) {}

    while (client->is_running()) {
      //client->m_server_socket.m_pipe->connect(0, client->m_recv_spec, client->m_send_spec);
      std::this_thread::sleep_for(500ms);
    }

    return 0;
  }

  uint64_t TCP_Client::client_iocp_thread_win32(void* param) {
    TCP_Client* client = (TCP_Client*)param;
    SocketIOInfo& sock_data = client->m_server_socket;
    ISocketPipe* server_pipe = sock_data.m_pipe;

    // TODO: Figure out why the completion status never returns
    //       Establish defined structure (should multiple sockets be handled per iocp thread?)
    //       If so, what does that look like?
    IApplicationLayerAdapter* adapter_ctx = nullptr;
    char* final_buf = nullptr, * proc_buf = nullptr;
    uint32_t final_buf_size = 0, proc_buf_size = 0;
    bool inproc = false;

    while (client->is_running()) {
      if (!client->is_connected()) {
        std::this_thread::sleep_for(100ms);
        continue;
      }

      // Since the TLS handshake process manages its
      // own recv calls, we wrap this for when
      // the handshake isn't happening.
      if (!client->m_tls_ssl || client->m_handshake_done) {
        EIOState state = server_pipe->recv(0, nullptr, nullptr);
        if (state == EIOState::E_ERROR) {
          server_pipe->error(ESocketErrorReason::E_REASON_RECV);
          return 0;
        }
      }

      ISocketIOResult* sock_results = server_pipe->wait_results();
      if (!sock_results || !sock_results->is_valid()) {
        server_pipe->error(ESocketErrorReason::E_REASON_CORRUPT);
        return 0;
      }

      std::unique_lock<std::mutex> lock(client->m_mutex);

      sock_results->for_each([&](ISocketOSSupportLayer* pipe, const ISocketIOResult::OperationData& info) {
        uint32_t cur_offset = sock_data.m_recv_state.m_bytes_transferred;

        pipe->set_busy(info.m_operation, false);

        if (client->m_tls_ssl && !client->m_handshake_done) {
          return client->handle_auth_operations(sock_data, info);
        }

        if (info.m_operation != EPipeOperation::E_RECV) {
          return true;
        }

        bool was_inproc = inproc;
        IApplicationLayerAdapter* adapter = client->handle_inproc_recv(sock_data, info, inproc);
        if (!adapter_ctx && !adapter) {
          pipe->error(ESocketErrorReason::E_REASON_ADAPTER_UNKNOWN);
          sock_data.m_recv_state = { nullptr, 0, 0 };
          return false;
        }

        // At the start, lock in the detected adapter and allocate necessary buffers
        char* recv_buf = pipe->recv_buf();

        if (!was_inproc) {
          adapter_ctx = adapter;
          proc_buf_size = sock_data.m_recv_state.m_bytes_total;
          proc_buf = new char[proc_buf_size];
          final_buf_size = adapter_ctx->calc_proc_size(recv_buf, proc_buf_size);
          final_buf = new char[final_buf_size];
        }

        memcpy_s(proc_buf + cur_offset, info.m_bytes_transferred, recv_buf, info.m_bytes_transferred);

        // At this point, if the recv is no longer in process, do post processing and signal the receive
        if (!inproc) {
          int32_t true_size = sock_data.m_pipe->proc_post_recv(final_buf, final_buf_size, proc_buf, proc_buf_size);
          if (!adapter_ctx->on_receive(sock_data.m_pipe, final_buf, true_size, 0)) {
            pipe->error(ESocketErrorReason::E_REASON_ADAPTER_FAIL);
            sock_data.m_recv_state = { nullptr, 0, 0 };
            return false;
          }
          sock_data.m_recv_state.m_bytes_transferred = 0;
          sock_data.m_recv_state.m_bytes_processed = 0;
          sock_data.m_recv_state.m_bytes_total = 0;
          delete final_buf;
          delete proc_buf;
        }

        return true;
        });
#endif
    }  // End of while loop

    return 0;
  }

  IApplicationLayerAdapter* TCP_Client::handle_inproc_recv(SocketIOInfo& data, const ISocketIOResult::OperationData& info, bool& inproc) {
    ISocketPipe* pipe = data.m_pipe;
    IApplicationLayerAdapter* adapter = nullptr;

    char* recv_buf = pipe->get_os_layer()->recv_buf();

    data.m_recv_state.m_bytes_transferred += info.m_bytes_transferred;

    if (!inproc) {
      char* proc_out = new char[info.m_bytes_transferred];
      {
        // Here we process enough to determine the underlying protocol
        int32_t true_size = pipe->proc_post_recv(proc_out, info.m_bytes_transferred, recv_buf, info.m_bytes_transferred);
        adapter = ApplicationAdapterFactory::detect(proc_out, true_size, m_tls_ssl);
        data.m_recv_state.m_bytes_processed += true_size;
        data.m_recv_state.m_bytes_total = adapter->calc_size(proc_out, info.m_bytes_transferred);
      }
      delete[] proc_out;
    }

    inproc = false;
    if (data.m_recv_state.m_bytes_total == 0) {
      inproc = true;
    }
    else if (data.m_recv_state.m_bytes_processed < data.m_recv_state.m_bytes_total) {
      inproc = true;
    }

    return adapter;
  }

  bool TCP_Client::handle_auth_operations(SocketIOInfo& sock_data, const ISocketIOResult::OperationData& info) {
    ISocketPipe* pipe = sock_data.m_pipe;

    switch (info.m_operation) {
    case EPipeOperation::E_RECV: {
      sock_data.m_last_op = EPipeOperation::E_RECV;
      pipe->get_os_layer()->set_busy(EPipeOperation::E_RECV, false);
      break;
    }
    case EPipeOperation::E_SEND: {
      sock_data.m_last_op = EPipeOperation::E_SEND;
      pipe->get_os_layer()->set_busy(EPipeOperation::E_SEND, false);
      break;
    }
    case EPipeOperation::E_CLOSE: {
      pipe->close();
      return true;
    }
    default:
      return false;
    }

    if (m_handshake_done) {
      return true;
    }

    if (m_handshake_state == EAuthState::E_AUTHENTICATED) {
      if (sock_data.m_last_op != EPipeOperation::E_RECV) {
        return true;
      }

      char* recv_buf = pipe->get_os_layer()->recv_buf();
      char* proc_out = new char[info.m_bytes_transferred];

      int32_t true_size = pipe->proc_post_recv(proc_out, info.m_bytes_transferred, recv_buf, info.m_bytes_transferred);
      if (true_size < 0) {
        pipe->error(ESocketErrorReason::E_REASON_CONNECT);
        return false;
      }

      if (strncmp(proc_out, "--AUTHENTICATED--", true_size) == 0) {
        m_handshake_done = true;
      }

      delete[] proc_out;
      return true;
    }

    m_handshake_state = pipe->proc_pending_auth(info.m_operation, info.m_bytes_transferred);
    if (m_handshake_state == EAuthState::E_FAILED) {
      pipe->error(ESocketErrorReason::E_REASON_CONNECT);
      return false;
    }
    return true;
  }

}  // namespace netpp
