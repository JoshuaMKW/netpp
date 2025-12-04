

#include <chrono>
#include <future>
#include <iostream>
#include <thread>

#include "netpp/network.h"
#include "netpp/socket.h"

#include "netpp/server.h"

using namespace std::chrono;
using namespace std::chrono_literals;

#ifdef _WIN32

#include <MSWSock.h>

// TODO - Replace these define constants with configurable parameters
#define RIO_PENDING_MAX 10

#define CLIENT_USE_WSA true

struct _WrapperState {
  netpp::ISocketOSSupportLayer* m_pipe = nullptr;
  netpp::ISocketOSSupportLayer::accept_cond_cb m_cond = nullptr;
};

static int _ServerAcceptCondWrapper(LPWSABUF caller_id, LPWSABUF caller_data,
  LPQOS sqos, LPQOS gqos, LPWSABUF callee_id,
  LPWSABUF callee_data, GROUP FAR* g, DWORD_PTR callback_data) {
  _WrapperState* state = reinterpret_cast<_WrapperState*>(callback_data);

  if (state->m_cond == nullptr) {
    return CF_ACCEPT;
  }

  netpp::EInternetLayerProtocol protocol = netpp::EInternetLayerProtocol::E_NONE;
  std::string client_ip, client_port;
  netpp::NetworkFlowSpec client_recv = {}, client_send = {};
  netpp::RawPacket request_in = { nullptr, 0 };
  netpp::RawPacket response_out = { nullptr, 0 };

  if (caller_data) {
    request_in = netpp::RawPacket(caller_data->buf, caller_data->len);
  }

  if (callee_data) {
    response_out = netpp::RawPacket(callee_data->buf, callee_data->len);
  }

  switch (((sockaddr*)(caller_id->buf))->sa_family) {
  case AF_INET: {
    protocol = netpp::EInternetLayerProtocol::E_IPV4;

    sockaddr_in* ipv4_addr = (sockaddr_in*)caller_id->buf;
    client_port = std::to_string(htons(ipv4_addr->sin_port));

    client_ip.resize(INET_ADDRSTRLEN);
    inet_ntop(AF_INET, ipv4_addr, client_ip.data(), client_ip.size());
    break;
  }
  case AF_INET6: {
    protocol = netpp::EInternetLayerProtocol::E_IPV6;

    sockaddr_in6* ipv6_addr = (sockaddr_in6*)caller_id->buf;
    client_port = std::to_string(htons(ipv6_addr->sin6_port));

    client_ip.resize(INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, ipv6_addr, client_ip.data(), client_ip.size());
    break;
  }
  }

  bool has_recv = false, has_send = false;
  if (sqos) {
    has_recv = true;
    has_send = true;

    auto qos_to_spec = [](netpp::NetworkFlowSpec& spec, const FLOWSPEC& qos) {
      spec.m_token_rate = qos.TokenRate;
      spec.m_token_bucket_size = qos.TokenBucketSize;
      spec.m_peak_bandwidth = qos.PeakBandwidth;
      spec.m_max_latency = qos.Latency;
      spec.m_jitter_tolerance = qos.DelayVariation;

      switch (qos.ServiceType) {
      default:
      case SERVICETYPE_BESTEFFORT:
        spec.m_service_type = netpp::EServiceType::E_BEST_EFFORT;
        break;
      case SERVICETYPE_CONTROLLEDLOAD:
        spec.m_service_type = netpp::EServiceType::E_CONTROLLED_LOAD;
        break;
      case SERVICETYPE_GUARANTEED:
        spec.m_service_type = netpp::EServiceType::E_GUARANTEED;
        break;
      }

      spec.m_max_sdu_size = qos.MaxSduSize;
      spec.m_min_policed_size = qos.MinimumPolicedSize;
      };

    qos_to_spec(client_recv, sqos->ReceivingFlowspec);
    qos_to_spec(client_send, sqos->SendingFlowspec);
  }

  if (state->m_cond(
    protocol,
    client_ip, client_port,
    has_recv ? &client_recv : nullptr,
    has_send ? &client_send : nullptr,
    request_in, response_out)) {
    return CF_ACCEPT;
  }
  else {
    return CF_REJECT;
  }
}

namespace netpp {

  static WSADATA wsa_data;

  bool sockets_initialize() {
    if (wsa_data.iMaxSockets > 0 && wsa_data.wVersion == 2) {
      return true;
    }

    // Initialize Winsock
    return WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0;
  }

  void sockets_deinitialize() {
    if (wsa_data.iMaxSockets == 0 || wsa_data.wVersion != 2) {
      return;
    }

    WSACleanup();
  }

}

#else

bool sockets_initialize() {
  return true;
}

void sockets_deinitialize() {
}

#endif

namespace netpp {

  enum class ECompletionKey : DWORD {
    E_STOP,
    E_START,
  };

  RIO_EXTENSION_FUNCTION_TABLE* s_rio = nullptr;
  LPFN_WSARECVMSG s_WSARecvMsg = nullptr;
  LPFN_WSASENDMSG s_WSASendMsg = nullptr;

  static int _win32_init_wsa(SOCKET in_sock) {
    sockets_initialize();

    DWORD bytes = 0;
    GUID wsa_recvmsg_guid = WSAID_WSARECVMSG;
    GUID wsa_sendmsg_guid = WSAID_WSASENDMSG;

    if (s_WSARecvMsg == nullptr && ::WSAIoctl(
      in_sock,
      SIO_GET_EXTENSION_FUNCTION_POINTER,
      &wsa_recvmsg_guid, sizeof(GUID),
      &s_WSARecvMsg, sizeof(s_WSARecvMsg),
      &bytes, NULL, NULL
    ) != 0) {
      return WSAGetLastError();
    }

    if (s_WSASendMsg == nullptr && ::WSAIoctl(
      in_sock,
      SIO_GET_EXTENSION_FUNCTION_POINTER,
      &wsa_recvmsg_guid, sizeof(GUID),
      &s_WSASendMsg, sizeof(s_WSASendMsg),
      &bytes, NULL, NULL
    ) != 0) {
      return WSAGetLastError();
    }

    return 0;
  }

  static int _win32_deinit_wsa(SOCKET in_sock) {
    sockets_deinitialize();
    s_WSARecvMsg = nullptr;
    s_WSASendMsg = nullptr;
    return 0;
  }

  static int _win32_init_rio(SOCKET in_sock) {
    if (s_rio) {
      return 0;
    }

    _win32_init_wsa(in_sock);

    s_rio = new RIO_EXTENSION_FUNCTION_TABLE();

    DWORD bytes = 0;

    GUID rio_id = WSAID_MULTIPLE_RIO;
    GUID acceptex_id = WSAID_ACCEPTEX;
    GUID getacceptexsockaddrs_id = WSAID_GETACCEPTEXSOCKADDRS;

    // Get the RIO extension function table
    if (::WSAIoctl(
      in_sock,
      SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
      &rio_id, sizeof(GUID),
      s_rio, sizeof(RIO_EXTENSION_FUNCTION_TABLE),
      &bytes, NULL, NULL
    ) != 0) {
      return WSAGetLastError();
    }

    return 0;
  }

  static int _win32_deinit_rio(SOCKET in_sock) {
    _win32_deinit_wsa(in_sock);

    if (!s_rio) {
      return 0;
    }

    delete s_rio;
    return 0;
  }

  struct Tag_WSA_BUF : public WSABUF {
    Tag_WSA_BUF(CHAR* buffer, DWORD length, EPipeOperation operation, ISocketOSSupportLayer* owner) {
      this->buf = buffer;
      this->len = length;
      this->Operation = operation;
      this->State = EIOState::E_NONE;
      this->Pipe = owner;
      this->IsBusy = FALSE;
    }

    EPipeOperation Operation;
    EIOState State;
    ISocketOSSupportLayer* Pipe;
    BOOL IsBusy;
  };

  struct Tag_WSA_OVERLAPPED : public WSAOVERLAPPED {
    Tag_WSA_OVERLAPPED(WSABUF* buffer, EPipeOperation operation, ISocketOSSupportLayer* owner) {
      this->Internal = 0;
      this->InternalHigh = 0;
      this->Offset = 0;
      this->OffsetHigh = 0;
      this->hEvent = nullptr;
      this->Operation = operation;
      this->Pipe = owner;
      this->Buffer = buffer;
    }

    EPipeOperation Operation;
    ISocketOSSupportLayer* Pipe;
    WSABUF* Buffer;
  };

  class Win32ClientSocketIOResult : public ISocketIOResult {
  public:
    Win32ClientSocketIOResult(ISocketOSSupportLayer* pipe, LPWSAOVERLAPPED recv_overlapped, LPWSAOVERLAPPED send_overlapped)
      : m_pipe(pipe), m_recv_bytes(0), m_send_bytes(0) {
      DWORD transferred_, flags_;

#ifdef CLIENT_USE_WSA
#if 0
      ULONG_PTR completion_key;
      bool success = GetQueuedCompletionStatus(iocp, &transferred_, &completion_key, &overlapped, INFINITE);
      if (!success) {
        return;
      }

      if (completion_key == (DWORD)ECompletionKey::E_STOP) {
        return;
      }
#else
      bool success = WSAGetOverlappedResult(pipe->socket(), recv_overlapped, &transferred_, false, &flags_);
      if (success) {
        m_recv_bytes = transferred_;
        ZeroMemory(recv_overlapped, sizeof(WSAOVERLAPPED));
      }

      success = WSAGetOverlappedResult(pipe->socket(), send_overlapped, &transferred_, false, &flags_);
      if (success) {
        m_send_bytes = transferred_;
        ZeroMemory(send_overlapped, sizeof(WSAOVERLAPPED));
      }
#endif
#endif
    }

    ~Win32ClientSocketIOResult() override = default;

    bool is_valid() const {
      return m_pipe != nullptr;
    }

    bool for_each(each_fn cb) {
      if (!is_valid()) {
        return false;
      }

      bool result = true;

      if (m_recv_bytes > 0) {
        result &= cb(m_pipe, { EPipeOperation::E_RECV, m_recv_bytes, m_socket });
      }

      if (m_send_bytes > 0) {
        result &= cb(m_pipe, { EPipeOperation::E_SEND, m_send_bytes, m_socket });
      }

      return result;
    }

  private:
    ISocketOSSupportLayer* m_pipe;
    uint32_t m_recv_bytes;
    uint32_t m_send_bytes;
    uint64_t m_socket;
  };

  class Win32ClientSocketLayer : public ISocketOSSupportLayer {
  public:
    Win32ClientSocketLayer(ISocketOSSupportLayer* owner_socket_layer,
      StaticBlockAllocator* recv_allocator, StaticBlockAllocator* send_allocator, ETransportLayerProtocol protocol, void* user_data = nullptr)
      : m_recv_allocator(recv_allocator), m_send_allocator(send_allocator),
      m_recv_buf_block(StaticBlockAllocator::INVALID_BLOCK), m_send_buf_block(StaticBlockAllocator::INVALID_BLOCK),
      m_recv_transferred(0), m_send_transferred(0) {
      m_socket = INVALID_SOCKET;
      m_recv_buffer = new Tag_WSA_BUF{
        nullptr,
        0,
        EPipeOperation::E_RECV,
        this
      };
      m_send_buffer = new Tag_WSA_BUF{
        nullptr,
        0,
        EPipeOperation::E_SEND,
        this
      };
      m_recv_overlapped = new Tag_WSA_OVERLAPPED{
        m_recv_buffer,
        EPipeOperation::E_RECV,
        this
      };
      m_send_overlapped = new Tag_WSA_OVERLAPPED{
        m_send_buffer,
        EPipeOperation::E_SEND,
        this
      };
      m_iocp = INVALID_HANDLE_VALUE;
      m_owner_socket_layer = owner_socket_layer;
      m_connected = false;
      m_protocol = protocol;

      ConnectEx = nullptr;
      DisconnectEx = nullptr;

      m_user_data = user_data;
    }

    ~Win32ClientSocketLayer() override {
      delete m_recv_buffer;
      delete m_send_buffer;
      delete m_recv_overlapped;
      delete m_send_overlapped;

      if (m_socket != INVALID_SOCKET) {
        ::shutdown(m_socket, SD_BOTH);
        ::closesocket(m_socket);
        m_socket = INVALID_SOCKET;
      }
    }

    uint64_t socket() const override {
      return (uint64_t)m_socket;
    }

    ETransportLayerProtocol protocol() const override {
      return m_protocol;
    }

    bool is_server() const { return false; }

    bool is_ready(EPipeOperation op) const override { return m_connected && !is_busy(op); }

    bool is_busy(EPipeOperation op) const override {
      switch (op) {
      case EPipeOperation::E_NONE:
        return false;
      case EPipeOperation::E_RECV:
        return m_recv_buffer->IsBusy;
      case EPipeOperation::E_SEND:
        return m_send_buffer->IsBusy;
      case EPipeOperation::E_RECV_SEND:
        return m_recv_buffer->IsBusy || m_send_buffer->IsBusy;
      }
      return false;
    }

    void set_busy(EPipeOperation op, bool busy) override {
      switch (op) {
      case EPipeOperation::E_RECV:
        m_recv_buffer->IsBusy = busy;
        return;
      case EPipeOperation::E_SEND:
        m_send_buffer->IsBusy = busy;
        return;
      case EPipeOperation::E_RECV_SEND:
        m_recv_buffer->IsBusy = busy;
        m_send_buffer->IsBusy = busy;
        return;
      }
      return;
    }

    EIOState state(EPipeOperation op) const override {
      switch (op) {
      case EPipeOperation::E_NONE:
      default:
        return EIOState::E_NONE;
      case EPipeOperation::E_RECV:
        return m_recv_buffer->State;
      case EPipeOperation::E_SEND:
        return m_send_buffer->State;
      case EPipeOperation::E_RECV_SEND:
        return EIOState::E_NONE;
      }
    }

    void signal_io_complete(EPipeOperation op) override {
      switch (op) {
      case EPipeOperation::E_NONE:
      default:
        return;
      case EPipeOperation::E_RECV:
        m_recv_buffer->State = EIOState::E_COMPLETE;
        return;
      case EPipeOperation::E_SEND:
        m_send_buffer->State = EIOState::E_COMPLETE;
        return;
      case EPipeOperation::E_RECV_SEND:
        m_recv_buffer->State = EIOState::E_COMPLETE;
        m_send_buffer->State = EIOState::E_COMPLETE;
        return;
      }
    }

    bool open(const char* hostname, const char* port) override {
#if 0
      if (m_socket != INVALID_SOCKET) {
        m_host_name = hostname;
        m_port = port;
        m_connecting = true;
        return true;
      }
#endif

      uint64_t socket_ = INVALID_SOCKET;

#if !CLIENT_USE_WSA
      // -----------------------------
      // Create the socket and flag it for IOCP

      switch (m_protocol) {
      case ETransportLayerProtocol::E_TCP: {
        socket_ = (int)::WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (socket_ == INVALID_SOCKET) {
          error(ESocketErrorReason::E_REASON_SOCKET);
          return false;
        }
      }
      case ETransportLayerProtocol::E_UDP: {
        socket_ = (int)::WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (socket_ == INVALID_SOCKET) {
          error(ESocketErrorReason::E_REASON_SOCKET);
          return false;
        }
      }
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
      if (WSAIoctl(socket_, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(GUID), &DisconnectEx, sizeof(LPFN_DISCONNECTEX), &bytes, NULL, NULL) == SOCKET_ERROR) {
        error(ESocketErrorReason::E_REASON_SOCKET);
        return false;
      }
#else
      switch (m_protocol) {
      case ETransportLayerProtocol::E_TCP: {
        socket_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socket_ == INVALID_SOCKET) {
          error(ESocketErrorReason::E_REASON_SOCKET);
          return false;
        }
        break;
      }
      case ETransportLayerProtocol::E_UDP: {
        socket_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socket_ == INVALID_SOCKET) {
          error(ESocketErrorReason::E_REASON_SOCKET);
          return false;
        }
        break;
      }
      }
#endif
      m_host_name = hostname;
      m_port = port;

      return open(socket_);
    }

    bool open(uint64_t socket_) override {
      m_recv_buf_block = m_recv_allocator->allocate();
      m_recv_buffer->buf = (CHAR*)m_recv_allocator->ptr(m_recv_buf_block);
      m_recv_buffer->len = (ULONG)m_recv_allocator->block_size();
      m_recv_buffer->Pipe = this;

      m_send_buf_block = m_send_allocator->allocate();
      m_send_buffer->buf = (CHAR*)m_send_allocator->ptr(m_send_buf_block);
      m_send_buffer->len = 0;
      m_send_buffer->Pipe = this;

      int recv_buf_size = m_recv_allocator->block_size();
      ::setsockopt(socket_, SOL_SOCKET, SO_RCVBUF, (char*)&recv_buf_size, 4);

      int send_buf_size = m_send_allocator->block_size();
      ::setsockopt(socket_, SOL_SOCKET, SO_SNDBUF, (char*)&send_buf_size, 4);

      m_socket = socket_;
      return true;
    }

    void close() override {
      if (!m_on_close || !m_on_close(this)) {
        if (m_socket != INVALID_SOCKET) {
#if 1
          ::shutdown(m_socket, SD_BOTH);
          ::closesocket(m_socket);
          m_connected = false;
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

        if (m_iocp) {
          ::CloseHandle(m_iocp);
          m_iocp = NULL;
        }
      }
    }

    void error(ESocketErrorReason reason) override {
      if (!m_on_error || !m_on_error(this, reason)) {
        fprintf(stderr, "Unhandled error (%d)", (int)reason);
      }
    }

    bool notify_all() override {
      return true;
    }

    int64_t sync(EPipeOperation op, uint64_t wait_time) override {
      if (wait_time == 0) {
        while (is_busy(op)) {
          std::this_thread::sleep_for(10ms);
        }
        return get_transferred(op);
      }

      time_point<high_resolution_clock> start_time = high_resolution_clock::now();
      while (is_busy(op)) {
        time_point<high_resolution_clock> now_time = high_resolution_clock::now();
        if ((now_time - start_time).count() > (int64_t)wait_time) {
          return false;
        }
        std::this_thread::sleep_for(10ms);
      }

      return get_transferred(op);
    }

    SocketLock acquire_lock() override {
      return SocketLock(m_mutex);
    }

    bool accept(accept_cond_cb accept_cond, accept_cb accept_routine) {
      return false;
    }

    bool bind(const char* addr) override {
      return false;
    }

    bool listen(uint32_t backlog) override {
      return false;
    }

    bool connect(uint64_t timeout, const NetworkFlowSpec* recv_flowspec, const NetworkFlowSpec* send_flowspec) override {
#if CLIENT_UDP_CONNECTIONLESS
      if (m_protocol == ETransportLayerProtocol::E_UDP) {
        return false;
      }
#endif

#if CLIENT_USE_WSA
      // Check if the connection is still alive
      uint32_t flags = MSG_PEEK;
      int rc = ::WSARecv(m_socket, m_recv_buffer, 1, NULL, (LPDWORD)&flags, m_recv_overlapped, NULL);
      if (rc == 0) {
        return true;
      }
      else {
        int error = ::WSAGetLastError();
        if (error == WSA_IO_PENDING || error == 0) {
          return true;
        }
      }
#else
      if (m_connected) {
        return true;
      }

      if (m_connecting) {
        return false;
      }

      char buf[1];
      int rc = ::recv(m_socket, buf, 1, MSG_PEEK);
      if (rc > 0) {
        return true;
      }
#endif

      m_connecting = true;

      // Connect to the server...
      sockaddr_in server_addr;
      ZeroMemory(&server_addr, sizeof(server_addr));

      server_addr.sin_family = AF_INET;
      server_addr.sin_port = htons(atoi(m_port.c_str()));
      inet_pton(AF_INET, m_host_name.c_str(), &server_addr.sin_addr);

      std::atomic<bool> time_out(false);

      auto future = std::async(std::launch::async, [&](SOCKET socket, sockaddr* addr, size_t addr_size) {
#if CLIENT_USE_WSA
        QOS qos;
        ZeroMemory(&qos, sizeof(qos));

        bool custom_flowspec = recv_flowspec && send_flowspec;
        if (custom_flowspec) {
          qos.SendingFlowspec.DelayVariation = send_flowspec->m_jitter_tolerance;
          qos.SendingFlowspec.ServiceType = (int)send_flowspec->m_service_type;
          qos.SendingFlowspec.TokenRate = send_flowspec->m_token_rate;
          qos.SendingFlowspec.TokenBucketSize = send_flowspec->m_token_bucket_size;
          qos.SendingFlowspec.PeakBandwidth = send_flowspec->m_peak_bandwidth;
          qos.SendingFlowspec.MaxSduSize = send_flowspec->m_max_sdu_size;
          qos.SendingFlowspec.MinimumPolicedSize = send_flowspec->m_min_policed_size;

          qos.ReceivingFlowspec.DelayVariation = recv_flowspec->m_jitter_tolerance;
          qos.ReceivingFlowspec.ServiceType = (int)recv_flowspec->m_service_type;
          qos.ReceivingFlowspec.TokenRate = recv_flowspec->m_token_rate;
          qos.ReceivingFlowspec.TokenBucketSize = recv_flowspec->m_token_bucket_size;
          qos.ReceivingFlowspec.PeakBandwidth = recv_flowspec->m_peak_bandwidth;
          qos.ReceivingFlowspec.MaxSduSize = recv_flowspec->m_max_sdu_size;
          qos.ReceivingFlowspec.MinimumPolicedSize = recv_flowspec->m_min_policed_size;
        }

        // TODO: Potentially handle QOS differently here
        qos.ProviderSpecific.buf = (char*)&qos;
        qos.ProviderSpecific.len = sizeof(qos);
#endif

        while (true) {
#if CLIENT_USE_WSA
          int conn = ::WSAConnect(socket, addr, (int)addr_size, NULL, NULL, custom_flowspec ? &qos : NULL, NULL);
          if (conn == SOCKET_ERROR) {
            int rc = ::WSAGetLastError();
            if (rc == WSAEISCONN) {
              return true;
            }
            else {
              if (rc != WSAEWOULDBLOCK && rc != WSAECONNREFUSED) {
                error(ESocketErrorReason::E_REASON_LISTEN);
              }
              // Error connecting to the server (server is down?)
              if (time_out) {
                return false;
              }
              fprintf(stderr, "[CLIENT: %llu] ERROR: Server connection failed... retrying in 1s\n", socket);
              std::this_thread::sleep_for(1s);
              continue;
            }

            fd_set write_set;
            FD_ZERO(&write_set);
            FD_SET(socket, &write_set);

            // Check for connection completion
            timeval timeout = { 2, 0 };
            if (::select(0, NULL, &write_set, NULL, &timeout) <= 0) {
              if (time_out) {
                return false;
              }
              fprintf(stderr, "[CLIENT: %llu] ERROR: Server connection failed... retrying in 1s\n", socket);
              std::this_thread::sleep_for(1s);
              continue;
            }

            int error = 0;
            int error_size = sizeof(error);
            if (::getsockopt(socket, SOL_SOCKET, SO_ERROR, (char*)&error, &error_size) == 0) {
              if (time_out) {
                return false;
              }
              fprintf(stderr, "[CLIENT: %llu] ERROR: Server connection failed... retrying in 1s\n", socket);
              std::this_thread::sleep_for(1s);
              continue;
            }
          }
#else
          if (::connect(socket, addr, (int)addr_size) == SOCKET_ERROR) {
            //client->emit_error(nullptr, EClientError::E_ERROR_SOCKET, (int)ESocketErrorReason::E_REASON_LISTEN);
            int rc = WSAGetLastError();
            if (time_out) {
              return false;
            }
            fprintf(stderr, "[CLIENT: %llu] ERROR: Server connection failed... retrying in 1s\n", socket);
            std::this_thread::sleep_for(1s);
            continue;
          }
#endif
          return true;
        }
        }, m_socket, (sockaddr*)&server_addr, sizeof(server_addr));

      if (timeout > 0 && future.wait_for(milliseconds(timeout)) == std::future_status::timeout) {
        time_out = true;
      }

      m_connected = future.get();
      m_connecting = false;
      return m_connected;
    }

    int32_t recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) override {
      if (m_recv_buffer->IsBusy) {
        return 0;
      }

      uint32_t flags_ = flags ? *flags : 0;

      int rc = ::WSARecv(m_socket, m_recv_buffer, 1, (LPDWORD)transferred_out, (LPDWORD)&flags_, m_recv_overlapped, NULL);
      if (rc != 0) {
        int err = ::WSAGetLastError();
        if (err == WSA_IO_PENDING) {
          m_recv_buffer->IsBusy = TRUE;
          m_recv_buffer->State = EIOState::E_ASYNC;
          return 1;
        }
        else if (err != 0) {
          set_transferred(EPipeOperation::E_RECV, -1);
          error(ESocketErrorReason::E_REASON_SEND);
          m_recv_buffer->State = EIOState::E_ERROR;
          return -1;
        }
      }
      m_recv_buffer->State = EIOState::E_COMPLETE;
      return 1;
    }

    int32_t send(const char* data, uint32_t size, uint32_t* flags) override {
      if (m_send_buffer->IsBusy) {
        return 0;
      }

      using namespace std::chrono;

      uint32_t sent_size = 0;

      while (sent_size < size) {
        int32_t chunk_size = min(size - sent_size, send_buf_size());
        memcpy_s(m_send_buffer->buf, send_buf_size(), data + sent_size, chunk_size);
        m_send_buffer->len = chunk_size;

        uint32_t flags_ = flags ? *flags : 0;
        flags_ &= (uint32_t)~ESendFlags::E_FORCE_INSECURE;
        flags_ &= (uint32_t)~ESendFlags::E_PARTIAL_IO;

#if CLIENT_USE_WSA
        int rc = ::WSASend(m_socket, m_send_buffer, 1, NULL, flags_, m_send_overlapped, NULL);
        if (rc != 0) {
          int err = ::WSAGetLastError();
          if (err == WSA_IO_PENDING) {
            sent_size += chunk_size;
            m_send_buffer->IsBusy = TRUE;
            m_send_buffer->State = EIOState::E_ASYNC;
            continue;
          }
          else if (err != 0) {
            if (sent_size > 0) {
              m_send_buffer->State = EIOState::E_PARTIAL;
              return sent_size;
            }
            error(ESocketErrorReason::E_REASON_SEND);
            return -1;
          }
        }
        sent_size += chunk_size;
        continue;
      }

      if (m_send_buffer->State == EIOState::E_ASYNC) {
        return (int32_t)sent_size;
      }

      m_send_buffer->State = EIOState::E_COMPLETE;
      m_send_buffer->IsBusy = FALSE;
      return (int32_t)sent_size;
#else
        switch (m_protocol) {
        case ETransportLayerProtocol::E_TCP: {
          int rc = ::send(m_socket, m_send_buffer->buf, m_send_buffer->len, flags_);
          if (rc == SOCKET_ERROR) {
            set_transferred(EPipeOperation::E_SEND, -1);
            error(ESocketErrorReason::E_REASON_SEND);
            return -1;
          }
          set_transferred(EPipeOperation::E_SEND, m_send_buffer->len);
          return send_size;
        }
        case ETransportLayerProtocol::E_UDP: {
          // Connect to the server...
          sockaddr_in server_addr;
          ZeroMemory(&server_addr, sizeof(server_addr));

          server_addr.sin_family = AF_INET;
          server_addr.sin_port = htons(atoi(m_port.c_str()));
          inet_pton(AF_INET, m_host_name.c_str(), &server_addr.sin_addr);

          int rc = ::sendto(m_socket, m_send_buffer->buf, m_send_buffer->len, flags_, (sockaddr*)&server_addr, sizeof(sockaddr));
          if (rc == SOCKET_ERROR) {
            set_transferred(EPipeOperation::E_SEND, -1);
            error(ESocketErrorReason::E_REASON_SEND);
            return -1;
          }
          set_transferred(EPipeOperation::E_SEND, m_send_buffer->len);
          return send_size;
        }
        }
        return -1;
#endif
    }

    char* recv_buf() const override {
      return (char*)m_recv_allocator->ptr(m_recv_buf_block);
    }

    uint32_t recv_buf_size() const override {
      return m_recv_allocator->block_size();
    }

    char* send_buf() const override {
      return (char*)m_send_allocator->ptr(m_send_buf_block);
    }

    uint32_t send_buf_size() const override {
      return m_send_allocator->block_size();
    }

    void set_recv_buf(char* buf) override {}
    void set_recv_buf_size(uint32_t size) override {}
    void set_send_buf(const char* buf) override {}
    void set_send_buf_size(uint32_t size) override {}

    int64_t get_transferred(EPipeOperation op) {
      switch (op) {
      case EPipeOperation::E_RECV:
        return m_recv_transferred;
      case EPipeOperation::E_SEND:
        return m_send_transferred;
      default:
        return 0;
      }
    }

    void set_transferred(EPipeOperation op, int64_t transferred) {
      switch (op) {
      case EPipeOperation::E_RECV:
        m_recv_transferred = (uint32_t)transferred;
        break;
      case EPipeOperation::E_SEND:
        m_send_transferred = (uint32_t)transferred;
        break;
      default:
        break;
      }
    }

    ISocketIOResult* wait_results() override {
      return new Win32ClientSocketIOResult(this, m_recv_overlapped, m_send_overlapped);
    }

    void* sys_data() const override { return m_iocp; }
    void* user_data() const override { return m_user_data; }

    void on_close(close_cb cb) { m_on_close = cb; }
    void on_error(error_cb cb) { m_on_error = cb; }

    void clone_callbacks_from(ISocketOSSupportLayer* other) {
      Win32ClientSocketLayer* tcp = static_cast<Win32ClientSocketLayer*>(other);
      m_on_close = tcp->m_on_close;
      m_on_error = tcp->m_on_error;
    }

  private:
    std::string m_host_name;
    std::string m_port;

    ISocketOSSupportLayer* m_owner_socket_layer;
    StaticBlockAllocator* m_recv_allocator;
    StaticBlockAllocator* m_send_allocator;
    close_cb m_on_close;
    error_cb m_on_error;

    SOCKET m_socket;

    uint32_t m_recv_buf_block;
    uint32_t m_send_buf_block;

    Tag_WSA_BUF* m_recv_buffer;
    Tag_WSA_BUF* m_send_buffer;

    HANDLE m_iocp;
    Tag_WSA_OVERLAPPED* m_recv_overlapped;
    Tag_WSA_OVERLAPPED* m_send_overlapped;

    uint32_t m_recv_transferred;
    uint32_t m_send_transferred;

    LPFN_CONNECTEX ConnectEx;
    LPFN_DISCONNECTEX DisconnectEx;

    std::atomic<bool> m_connected;
    std::atomic<bool> m_connecting;

    ETransportLayerProtocol m_protocol;

    std::mutex m_mutex;

    void* m_user_data;
  };

    struct Tag_RIO_BUF : public RIO_BUF {
      Tag_RIO_BUF(RIO_BUFFERID buffer_id, DWORD offset, DWORD length, EPipeOperation operation, ISocketOSSupportLayer* owner) {
        this->BufferId = buffer_id;
        this->Offset = offset;
        this->Length = length;
        this->Operation = operation;
        this->State = EIOState::E_NONE;
        this->Pipe = owner;
        this->IsBusy = FALSE;
      }

      EPipeOperation Operation;
      EIOState State;
      ISocketOSSupportLayer* Pipe;
      BOOL IsBusy;
    };

    class Win32ServerSocketIOResult : public ISocketIOResult {
    public:
      Win32ServerSocketIOResult(HANDLE iocp, RIO_CQ& rio_cq, size_t capacity = 16)
        : m_result_count(RIO_CORRUPT_CQ), m_result_max(0), m_results(nullptr) {
        DWORD transferred_;
        ULONG_PTR completion_key;
        LPOVERLAPPED overlapped;

        bool success = GetQueuedCompletionStatus(iocp, &transferred_, &completion_key, &overlapped, INFINITE);
        if (!success) {
          return;
        }

        if (completion_key == (DWORD)ECompletionKey::E_STOP) {
          return;
        }

        m_results = new RIORESULT[capacity];
        m_result_max = capacity;
        m_result_count = static_cast<size_t>(s_rio->RIODequeueCompletion(rio_cq, m_results, (ULONG)capacity));
      }

      ~Win32ServerSocketIOResult() override {
        delete[] m_results;
      }

      bool is_valid() const {
        return m_result_count != RIO_CORRUPT_CQ && m_result_count <= m_result_max;
      }

      bool for_each(each_fn cb) {
        if (!is_valid()) {
          return false;
        }

        for (size_t i = 0; i < m_result_count; ++i) {
          RIORESULT& result = m_results[i];
          if (result.Status != NO_ERROR) {
            return false;
          }

          Tag_RIO_BUF* buf = (Tag_RIO_BUF*)result.RequestContext;
          ISocketOSSupportLayer* pipe = buf->Pipe;

          if (!cb(pipe, { buf->Operation, result.BytesTransferred })) {
            return false;
          }
        }

        return true;
      }

    private:
      RIORESULT* m_results;
      size_t m_result_max;
      size_t m_result_count;
    };

    class Win32ServerSocketLayer : public ISocketOSSupportLayer {
    public:
      Win32ServerSocketLayer(ISocketOSSupportLayer* owner_socker_layer,
        StaticBlockAllocator* recv_allocator, StaticBlockAllocator* send_allocator, ETransportLayerProtocol protocol, void* user_data = nullptr)
        : m_recv_allocator(recv_allocator), m_send_allocator(send_allocator),
        m_recv_buf_block(StaticBlockAllocator::INVALID_BLOCK), m_send_buf_block(StaticBlockAllocator::INVALID_BLOCK) {
        m_socket = INVALID_SOCKET;
        m_recv_buffer = new Tag_RIO_BUF(
          RIO_BUFFERID{ RIO_INVALID_BUFFERID },
          0,
          0,
          EPipeOperation::E_RECV,
          this
        );
        m_send_buffer = new Tag_RIO_BUF(
          RIO_BUFFERID{ RIO_INVALID_BUFFERID },
          0,
          0,
          EPipeOperation::E_SEND,
          this
        );
        m_completion_queue = RIO_INVALID_CQ;
        m_request_queue = RIO_INVALID_RQ;
        m_iocp = INVALID_HANDLE_VALUE;
        m_overlapped = { 0 };
        m_owner_socket_layer = owner_socker_layer;

        m_protocol = protocol;

        m_user_data = user_data;
      }

      ~Win32ServerSocketLayer() override {
        delete m_recv_buffer;
        delete m_send_buffer;

        if (m_socket != INVALID_SOCKET) {
          ::shutdown(m_socket, SD_BOTH);
          ::closesocket(m_socket);
          m_socket = INVALID_SOCKET;
        }
      }

      uint64_t socket() const override {
        return (uint64_t)m_socket;
      }

      ETransportLayerProtocol protocol() const override {
        return m_protocol;
      }

      bool is_server() const { return true; }

      bool is_ready(EPipeOperation op) const override { return !is_busy(op); }

      bool is_busy(EPipeOperation op) const override {
        switch (op) {
        case EPipeOperation::E_NONE:
          return false;
        case EPipeOperation::E_RECV:
          return m_recv_buffer->IsBusy;
        case EPipeOperation::E_SEND:
          return m_send_buffer->IsBusy;
        case EPipeOperation::E_RECV_SEND:
          return m_recv_buffer->IsBusy || m_send_buffer->IsBusy;
        }
        return false;
      }

      void set_busy(EPipeOperation op, bool busy) override {
        switch (op) {
        case EPipeOperation::E_RECV:
          m_recv_buffer->IsBusy = busy;
          return;
        case EPipeOperation::E_SEND:
          m_send_buffer->IsBusy = busy;
          return;
        case EPipeOperation::E_RECV_SEND:
          m_recv_buffer->IsBusy = busy;
          m_send_buffer->IsBusy = busy;
          return;
        }
        return;
      }

      EIOState state(EPipeOperation op) const override {
        switch (op) {
        case EPipeOperation::E_NONE:
        default:
          return EIOState::E_NONE;
        case EPipeOperation::E_RECV:
          return m_recv_buffer->State;
        case EPipeOperation::E_SEND:
          return m_send_buffer->State;
        case EPipeOperation::E_RECV_SEND:
          return EIOState::E_NONE;
        }
      }

      void signal_io_complete(EPipeOperation op) override {
        switch (op) {
        case EPipeOperation::E_NONE:
        default:
          return;
        case EPipeOperation::E_RECV:
          m_recv_buffer->State = EIOState::E_COMPLETE;
          return;
        case EPipeOperation::E_SEND:
          m_send_buffer->State = EIOState::E_COMPLETE;
          return;
        case EPipeOperation::E_RECV_SEND:
          m_recv_buffer->State = EIOState::E_COMPLETE;
          m_send_buffer->State = EIOState::E_COMPLETE;
          return;
        }
      }

      bool open(const char* hostname, const char* port) override {
        Win32ServerSocketLayer* server_pipe = (Win32ServerSocketLayer*)m_owner_socket_layer;

        uint64_t socket_ = 0;

        switch (m_protocol) {
        case ETransportLayerProtocol::E_TCP: {
          socket_ = ::WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_REGISTERED_IO);
          if (socket_ == INVALID_SOCKET) {
            return false;
          }
          break;
        }
        case ETransportLayerProtocol::E_UDP: {
          socket_ = ::WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_REGISTERED_IO);
          if (socket_ == INVALID_SOCKET) {
            return false;
          }
          break;
        }
        }

        m_host_name = hostname;
        m_port = port;

        return open(socket_);
      }

      bool open(uint64_t socket_) override {
        Win32ServerSocketLayer* server_pipe = (Win32ServerSocketLayer*)m_owner_socket_layer;

        if (!SocketOSSupportLayerFactory::initialize(socket_)) {
          return false;
        }

        int namelen = sizeof(sockaddr_in);
        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(atoi(m_port.c_str()));
        inet_pton(AF_INET, m_host_name.c_str(), &addr.sin_addr);

        ZeroMemory(&m_overlapped, sizeof(OVERLAPPED));

        m_recv_buf_block = m_recv_allocator->allocate();
        m_send_buf_block = m_send_allocator->allocate();

        int recv_buf_size = m_recv_allocator->block_size();
        ::setsockopt(socket_, SOL_SOCKET, SO_RCVBUF, (char*)&recv_buf_size, 4);

        int send_buf_size = m_send_allocator->block_size();
        ::setsockopt(socket_, SOL_SOCKET, SO_SNDBUF, (char*)&send_buf_size, 4);

        if (server_pipe) {
          // In this circumstance, it is inheriting resources from the server
          *m_recv_buffer = *server_pipe->m_recv_buffer;
          m_recv_buffer->Offset = m_recv_allocator->ofs(m_recv_buf_block);
          m_recv_buffer->Pipe = this;

          *m_send_buffer = *server_pipe->m_send_buffer;
          m_send_buffer->Offset = m_send_allocator->ofs(m_send_buf_block);
          m_send_buffer->Pipe = this;

          m_completion_queue = server_pipe->m_completion_queue;
          m_iocp = server_pipe->m_iocp;
        }
        else {
          // In this circumstance, this is the server and it needs new resources
          m_recv_buffer->BufferId = s_rio->RIORegisterBuffer(
            (PCHAR)m_recv_allocator->ptr(m_recv_buf_block),
            m_recv_allocator->block_size() * m_recv_allocator->capacity()
          );
          if (m_recv_buffer->BufferId == RIO_INVALID_BUFFERID) {
            error(ESocketErrorReason::E_REASON_RESOURCES);
            return false;
          }
          m_recv_buffer->Length = m_recv_allocator->block_size();
          m_recv_buffer->Offset = m_recv_allocator->ofs(m_recv_buf_block);
          m_recv_buffer->Pipe = this;

          m_send_buffer->BufferId = s_rio->RIORegisterBuffer(
            (PCHAR)m_send_allocator->ptr(m_send_buf_block),
            m_send_allocator->block_size() * m_send_allocator->capacity()
          );
          if (m_send_buffer->BufferId == RIO_INVALID_BUFFERID) {
            error(ESocketErrorReason::E_REASON_RESOURCES);
            s_rio->RIODeregisterBuffer(m_recv_buffer->BufferId);
            return false;
          }
          m_send_buffer->Length = 0;
          m_send_buffer->Offset = m_send_allocator->ofs(m_send_buf_block);
          m_send_buffer->Pipe = this;

          m_iocp = ::CreateIoCompletionPort((HANDLE)m_socket, NULL, 0, 0);
          if (m_iocp == NULL) {
            error(ESocketErrorReason::E_REASON_SOCKET);
            return false;
          }

          // Initialize Overlapped structure
          ::ZeroMemory(&m_overlapped, sizeof(m_overlapped));

          // Create the completion queues and request queues
          RIO_NOTIFICATION_COMPLETION completion;
          completion.Type = RIO_IOCP_COMPLETION;
          completion.Iocp.IocpHandle = m_iocp;
          completion.Iocp.CompletionKey = (void*)ECompletionKey::E_START;
          completion.Iocp.Overlapped = &m_overlapped;

          uint32_t queue_size = m_recv_allocator->capacity() + m_send_allocator->capacity();

          m_completion_queue = s_rio->RIOCreateCompletionQueue(queue_size * RIO_PENDING_MAX, &completion);
          if (m_completion_queue == RIO_INVALID_CQ) {
            error(ESocketErrorReason::E_REASON_RESOURCES);
            return false;
          }
        }

        m_request_queue = s_rio->RIOCreateRequestQueue(
          socket_,
          RIO_PENDING_MAX, 1,
          RIO_PENDING_MAX, 1,
          m_completion_queue,
          m_completion_queue,
          this
        );

        m_host_name.resize(INET_ADDRSTRLEN + 1);
        inet_ntop(AF_INET, &addr.sin_addr, (char*)m_host_name.data(), INET_ADDRSTRLEN);

        m_port = std::to_string(ntohs(addr.sin_port));

        m_socket = socket_;
        return true;
      }

      void close() override {
        if (!m_on_close || !m_on_close(this)) {
          ::shutdown(m_socket, SD_BOTH);
          ::closesocket(m_socket);

          m_recv_allocator->deallocate(m_recv_buf_block);
          m_send_allocator->deallocate(m_send_buf_block);

          if (m_owner_socket_layer) {
            if (m_request_queue != RIO_INVALID_RQ) {
              m_request_queue = RIO_INVALID_RQ;
            }
          }
          else {
            if (m_completion_queue != RIO_INVALID_CQ) {
              s_rio->RIOCloseCompletionQueue(m_completion_queue);
              m_completion_queue = RIO_INVALID_CQ;
            }

            if (m_recv_buffer->BufferId != RIO_INVALID_BUFFERID) {
              s_rio->RIODeregisterBuffer(m_recv_buffer->BufferId);
              m_recv_buffer->BufferId = RIO_INVALID_BUFFERID;
              m_recv_buf_block = StaticBlockAllocator::INVALID_BLOCK;
            }

            if (m_send_buffer->BufferId != RIO_INVALID_BUFFERID) {
              s_rio->RIODeregisterBuffer(m_send_buffer->BufferId);
              m_send_buffer->BufferId = RIO_INVALID_BUFFERID;
              m_send_buf_block = StaticBlockAllocator::INVALID_BLOCK;
            }

            if (m_iocp) {
              ::CloseHandle(m_iocp);
              m_iocp = NULL;
            }
          }
        }
      }

      void error(ESocketErrorReason reason) override {
        if (!m_on_error || !m_on_error(this, reason)) {
          fprintf(stderr, "Unhandled error (%d)", (int)reason);
        }
      }

      bool notify_all() override {
        int rc = s_rio->RIONotify(m_completion_queue);
        if (rc != ERROR_SUCCESS && rc != WSAEALREADY) {
          error(ESocketErrorReason::E_REASON_CORRUPT);
          return false;
        }
        return true;
      }

      int64_t sync(EPipeOperation op, uint64_t wait_time) override {
        if (wait_time == 0) {
          while (is_busy(op)) {
            std::this_thread::sleep_for(10ms);
          }
          return get_transferred(op);
        }

        time_point<high_resolution_clock> start_time = high_resolution_clock::now();
        while (is_busy(op)) {
          time_point<high_resolution_clock> now_time = high_resolution_clock::now();
          if ((now_time - start_time).count() > (int64_t)wait_time) {
            return false;
          }
          std::this_thread::sleep_for(10ms);
        }

        return get_transferred(op);
      }

      SocketLock acquire_lock() override {
        return SocketLock(m_mutex);
      }

      bool accept(accept_cond_cb accept_cond, accept_cb accept_routine) {
        sockaddr_in inaddr;
        int addr_size = sizeof(sockaddr);

        _WrapperState* state = new _WrapperState;
        state->m_pipe = this;
        state->m_cond = accept_cond;

        SOCKET client_socket = ::WSAAccept(m_socket, (sockaddr*)&inaddr, &addr_size, _ServerAcceptCondWrapper, (DWORD_PTR)state);
        if (client_socket == INVALID_SOCKET) {
          return false;
        }

        delete state;

        if (!accept_routine(client_socket)) {
          ::shutdown(client_socket, SD_BOTH);
          ::closesocket(client_socket);
          return false;
        }

        return true;
      }

      bool bind(const char* addr) override {
        sockaddr_in server_addr;
        ::ZeroMemory(&server_addr, sizeof(server_addr));

        server_addr.sin_family = AF_INET;
        server_addr.sin_port = ::htons(atoi(m_port.c_str()));

        if (addr) {
          inet_pton(server_addr.sin_family, addr, &server_addr.sin_addr);
        }
        else {
          server_addr.sin_addr.s_addr = INADDR_ANY;
        }

        if (::bind(m_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
          error(ESocketErrorReason::E_REASON_BIND);
          return false;
        }

        return true;
      }

      bool listen(uint32_t backlog) override {
        if (m_protocol == ETransportLayerProtocol::E_UDP) {
          return false;
        }

        // -----------------------------
        // Listen on the socket to allow for an incoming connection
        if (::listen(m_socket, backlog) == SOCKET_ERROR) {
          error(ESocketErrorReason::E_REASON_LISTEN);
          return false;
        }

        return true;
      }

      bool connect(uint64_t timeout, const NetworkFlowSpec* recv_flowspec, const NetworkFlowSpec* send_flowspec) override {
        return false;
      }

      int32_t recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) override {
        if (m_recv_buffer->IsBusy) {
          return 0;
        }

        m_recv_buffer->Offset = m_recv_allocator->ofs(m_recv_buf_block) + offset;

        BOOL rc = s_rio->RIOReceive(m_request_queue, m_recv_buffer, 1, NULL, m_recv_buffer);
        if (rc) {
          m_recv_buffer->IsBusy = TRUE;
          m_recv_buffer->State = EIOState::E_ASYNC;
          return 1;
        }

        m_recv_buffer->State = EIOState::E_ERROR;
        return -1;
      }

      int32_t send(const char* data, uint32_t size, uint32_t* flags) override {
        if (m_send_buffer->IsBusy) {
          return 0;
        }

        char* send_buf = (char*)m_send_allocator->ptr(m_send_buf_block);
        uint32_t block_size = m_send_allocator->block_size();
        uint32_t bytes_sent = 0;

        uint32_t flags_ = flags ? *flags : 0;
        flags_ &= (uint32_t)~ESendFlags::E_FORCE_INSECURE;
        flags_ &= (uint32_t)~ESendFlags::E_PARTIAL_IO;

        while (bytes_sent < size) {
          uint32_t chunk_size = min(size - bytes_sent, block_size);
          memcpy_s(send_buf, (size_t)block_size, data, chunk_size);
          m_send_buffer->Length = (ULONG)chunk_size;

          BOOL rc = s_rio->RIOSend(m_request_queue, m_send_buffer, 1, flags_, m_send_buffer);
          if (rc) {
            m_send_buffer->IsBusy = TRUE;
            bytes_sent += chunk_size;
            continue;
          }

          if (bytes_sent == 0) {
            m_send_buffer->State = EIOState::E_ERROR;
            return -1;
          }

          m_send_buffer->State = EIOState::E_PARTIAL;
          return (int32_t)bytes_sent;
        }

        m_send_buffer->State = EIOState::E_COMPLETE;
        return (int32_t)bytes_sent;
      }

      char* recv_buf() const override {
        return (char*)m_recv_allocator->ptr(m_recv_buf_block);
      }

      uint32_t recv_buf_size() const override {
        return m_recv_allocator->block_size();
      }

      char* send_buf() const override {
        return (char*)m_send_allocator->ptr(m_send_buf_block);
      }

      uint32_t send_buf_size() const override {
        return m_send_allocator->block_size();
      }

      void set_recv_buf(char* buf) override {}
      void set_recv_buf_size(uint32_t size) override {}
      void set_send_buf(const char* buf) override {}
      void set_send_buf_size(uint32_t size) override {}

      int64_t get_transferred(EPipeOperation op) {
        switch (op) {
        case EPipeOperation::E_RECV:
          return m_recv_transferred;
        case EPipeOperation::E_SEND:
          return m_send_transferred;
        default:
          return 0;
        }
      }

      void set_transferred(EPipeOperation op, int64_t transferred) {
        switch (op) {
        case EPipeOperation::E_RECV:
          m_recv_transferred = (uint32_t)transferred;
          break;
        case EPipeOperation::E_SEND:
          m_send_transferred = (uint32_t)transferred;
          break;
        default:
          break;
        }
      }

      ISocketIOResult* wait_results() override {
        return new Win32ServerSocketIOResult(m_iocp, m_completion_queue, 32);
      }

      void* sys_data() const override { return m_iocp; }
      void* user_data() const override { return m_user_data; }

      void on_close(close_cb cb) { m_on_close = cb; }
      void on_error(error_cb cb) { m_on_error = cb; }

      void clone_callbacks_from(ISocketOSSupportLayer* other) {
        Win32ServerSocketLayer* tcp = static_cast<Win32ServerSocketLayer*>(other);
        m_on_close = tcp->m_on_close;
        m_on_error = tcp->m_on_error;
      }

    private:
      std::string m_host_name;
      std::string m_port;

      ISocketOSSupportLayer* m_owner_socket_layer;
      StaticBlockAllocator* m_recv_allocator;
      StaticBlockAllocator* m_send_allocator;
      close_cb m_on_close;
      error_cb m_on_error;

      SOCKET m_socket;

      uint32_t m_recv_buf_block;
      Tag_RIO_BUF* m_recv_buffer;

      uint32_t m_send_buf_block;
      Tag_RIO_BUF* m_send_buffer;

      uint32_t m_recv_transferred;
      uint32_t m_send_transferred;

      RIO_CQ m_completion_queue;
      RIO_RQ m_request_queue;
      HANDLE m_iocp;
      OVERLAPPED m_overlapped;

      ETransportLayerProtocol m_protocol;

      std::mutex m_mutex;

      void* m_user_data;
    };

    bool SocketOSSupportLayerFactory::initialize(uint64_t socket) {
      return _win32_init_rio(socket) == 0;
    }

    bool SocketOSSupportLayerFactory::deinitialize() {
      if (s_rio) {
        delete s_rio;
      }
      return true;
    }

    ISocketOSSupportLayer* SocketOSSupportLayerFactory::create(netpp::ISocketOSSupportLayer* owner_socket_layer,
      netpp::StaticBlockAllocator* recv_allocator, netpp::StaticBlockAllocator* send_allocator, ETransportLayerProtocol protocol, ESocketHint hint, void* user_data) {
#ifdef _WIN32
      switch (hint) {
      case ESocketHint::E_CLIENT:
        return new Win32ClientSocketLayer(owner_socket_layer, recv_allocator, send_allocator, protocol, user_data);
      case ESocketHint::E_SERVER:
      default:
        return new Win32ServerSocketLayer(owner_socket_layer, recv_allocator, send_allocator, protocol, user_data);
      }
#else
      switch (hint) {
      case ESocketHint::E_CLIENT:
      default:
        return nullptr;
      case ESocketHint::E_SERVER:
        return nullptr;
      }
#endif
    }

}  // namespace netpp
