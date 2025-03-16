

#include <chrono>
#include <iostream>
#include <thread>

#include "network.h"
#include "socket.h"

#include "server.h"

using namespace std::chrono;
using namespace std::chrono_literals;

#ifdef _WIN32

#pragma comment(lib, "ws2_32.lib")
#include <MSWSock.h>

#define RIO_PENDING_MAX 5
#define RIO_MAX_BUFFERS 1024

#define SKIP_BUF_INIT_FLAG 0x80000000

#define CLIENT_USE_WSA false

namespace netpp {

  static WSADATA wsa_data;

  bool sockets_initialize() {
    // Initialize Winsock
    return WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0;
  }

  void sockets_deinitialize() {
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

  RIO_EXTENSION_FUNCTION_TABLE* s_rio;

  static int _win32_init_rio(SOCKET in_sock) {
    if (s_rio) {
      return 0;
    }

    sockets_initialize();

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
    sockets_initialize();

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
      this->Pipe = owner;
      this->IsBusy = FALSE;
    }

    EPipeOperation Operation;
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

  class Win32ClientSocketLayer : public ISocketOSSupportLayer {
  public:
    Win32ClientSocketLayer(ISocketOSSupportLayer* owner_socket_layer,
      StaticBlockAllocator* recv_allocator, StaticBlockAllocator* send_allocator, ETransportLayerProtocol protocol) {
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
        m_send_buffer,
        EPipeOperation::E_RECV,
        this
      };
      m_send_overlapped = new Tag_WSA_OVERLAPPED{
        m_recv_buffer,
        EPipeOperation::E_SEND,
        this
      };
      m_iocp = INVALID_HANDLE_VALUE;
      m_owner_socket_layer = owner_socket_layer;
      m_connected = false;
      m_connecting = false;
      m_protocol = protocol;
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

    bool is_busy(EPipeOperation op) const override {
      switch (op) {
      case EPipeOperation::E_RECV:
        return m_recv_busy;
      case EPipeOperation::E_SEND:
        return m_send_busy;
      case EPipeOperation::E_RECV_SEND:
        return m_recv_busy || m_send_busy;
      }
      return false;
    }

    void set_busy(EPipeOperation op, bool busy) override {
      switch (op) {
      case EPipeOperation::E_RECV:
        m_recv_busy = busy;
        return;
      case EPipeOperation::E_SEND:
        m_send_busy = busy;
        return;
      case EPipeOperation::E_RECV_SEND:
        m_recv_busy = busy;
        m_send_busy = busy;
        return;
      }
      return;
    }

    bool open(const char* hostname, const char* port) override {
      m_recv_buf_block = m_recv_allocator->allocate();
      m_recv_buffer->buf = (CHAR*)m_recv_allocator->ptr(m_recv_buf_block);
      m_recv_buffer->len = (ULONG)m_recv_allocator->block_size();
      m_recv_buffer->Pipe = this;

      m_send_buf_block = m_send_allocator->allocate();
      m_send_buffer->buf = (CHAR*)m_send_allocator->ptr(m_send_buf_block);
      m_send_buffer->len = 0;
      m_send_buffer->Pipe = this;

#if 0
      if (m_socket != INVALID_SOCKET) {
        m_host_name = hostname;
        m_port = port;
        m_connecting = true;
        return true;
      }
#endif

      uint64_t socket_ = INVALID_SOCKET;

#if CLIENT_USE_WSA
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
      }
      case ETransportLayerProtocol::E_UDP: {
        socket_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socket_ == INVALID_SOCKET) {
          error(ESocketErrorReason::E_REASON_SOCKET);
          return false;
        }
      }
      }
#endif

      return open(socket_);
    }

    bool open(uint64_t socket_) override {
      m_socket = socket_;
      m_connecting = true;
      return true;
    }

    void close() override {
      if (!m_on_close || !m_on_close(this)) {
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

    bool sync(uint64_t wait_time) override {
      if (wait_time == 0) {
        while (is_busy(EPipeOperation::E_RECV_SEND)) {
          std::this_thread::sleep_for(10ms);
        }
        return true;
      }

      time_point<high_resolution_clock> start_time = high_resolution_clock::now();
      while (is_busy(EPipeOperation::E_RECV_SEND)) {
        time_point<high_resolution_clock> now_time = high_resolution_clock::now();
        if ((now_time - start_time).count() > (int64_t)wait_time) {
          return false;
        }
        std::this_thread::sleep_for(10ms);
      }

      return true;
    }

    bool bind_and_listen(const char* addr, uint32_t backlog) override {
      return false;
    }

    bool recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) override {
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
      *transferred_out = ::recv(m_socket, m_recv_buffer->buf + offset, recv_buf_size() - offset, flags_);
      if (*transferred_out == 0) {
        error(ESocketErrorReason::E_REASON_PORT);
        return false;
      }
      else if (*(int*)transferred_out == INVALID_SOCKET) {
        error(ESocketErrorReason::E_REASON_SOCKET);
        return false;
      }
      return true;
#endif
    }

    bool send(const char* data, uint32_t size, uint32_t* flags) override {
      if (m_send_buffer->IsBusy) {
        return false;
      }

      using namespace std::chrono;

      size = min(size, send_buf_size());
      memcpy_s(m_send_buffer->buf, send_buf_size(), data, size);
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

    void* sys_data() const override { return m_iocp; }
    void* user_data() const override { return nullptr; }

    void on_close(close_cb cb) { m_on_close = cb; }
    void on_error(error_cb cb) { m_on_error = cb; }

  private:
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

    LPFN_DISCONNECTEX DisconnectEx;

    bool m_connected;
    bool m_connecting;
    bool m_recv_busy;
    bool m_send_busy;

    ETransportLayerProtocol m_protocol;
  };

  struct Tag_RIO_BUF : public RIO_BUF {
    Tag_RIO_BUF(RIO_BUFFERID buffer_id, DWORD offset, DWORD length, EPipeOperation operation, ISocketOSSupportLayer* owner) {
      this->BufferId = buffer_id;
      this->Offset = offset;
      this->Length = length;
      this->Operation = operation;
      this->Pipe = owner;
      this->IsBusy = FALSE;
    }

    EPipeOperation Operation;
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
      m_result_count = s_rio->RIODequeueCompletion(rio_cq, m_results, capacity);
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
    RIORESULT *m_results;
    size_t m_result_max;
    size_t m_result_count;
  };

  class Win32ServerSocketLayer : public ISocketOSSupportLayer {
  public:
    Win32ServerSocketLayer(ISocketOSSupportLayer* owner_socker_layer,
      StaticBlockAllocator* recv_allocator, StaticBlockAllocator* send_allocator, ETransportLayerProtocol protocol) {
      m_socket = INVALID_SOCKET;
      m_recv_buffer = new Tag_RIO_BUF{
        RIO_BUFFERID{ RIO_INVALID_BUFFERID },
        0,
        0,
        EPipeOperation::E_RECV,
        this
      };
      m_send_buffer = new Tag_RIO_BUF{
        RIO_BUFFERID{ RIO_INVALID_BUFFERID },
        0,
        0,
        EPipeOperation::E_SEND,
        this
      };
      m_completion_queue = RIO_INVALID_CQ;
      m_request_queue = RIO_INVALID_RQ;
      m_iocp = INVALID_HANDLE_VALUE;
      m_overlapped = { 0 };
      m_owner_socket_layer = owner_socker_layer;

      m_protocol = protocol;
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

    bool is_busy(EPipeOperation op) const override {
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

    bool open(const char* hostname, const char* port) override {
      Win32ServerSocketLayer* server_pipe = (Win32ServerSocketLayer*)m_owner_socket_layer;

      sockaddr_in addr;
      addr.sin_family = AF_INET;
      addr.sin_port = htons(atoi(port));
      inet_pton(AF_INET, hostname, &addr.sin_addr);

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

      return open(socket_);
    }

    bool open(uint64_t socket_) override {
      Win32ServerSocketLayer* server_pipe = (Win32ServerSocketLayer*)m_owner_socket_layer;

      int namelen = sizeof(sockaddr_in);
      sockaddr_in addr;

      int rc = getpeername(socket_, (sockaddr*)&addr, &namelen);
      if (rc == SOCKET_ERROR) {
        return false;
      }

      ZeroMemory(&m_overlapped, sizeof(OVERLAPPED));

      m_recv_buf_block = m_recv_allocator->allocate();
      m_send_buf_block = m_send_allocator->allocate();

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

    bool sync(uint64_t wait_time) override {
      if (wait_time == 0) {
        while (is_busy(EPipeOperation::E_RECV_SEND)) {
          std::this_thread::sleep_for(10ms);
        }
        return true;
      }

      time_point<high_resolution_clock> start_time = high_resolution_clock::now();
      while (is_busy(EPipeOperation::E_RECV_SEND)) {
        time_point<high_resolution_clock> now_time = high_resolution_clock::now();
        if ((now_time - start_time).count() > (int64_t)wait_time) {
          return false;
        }
        std::this_thread::sleep_for(10ms);
      }

      return true;
    }

    bool bind_and_listen(const char* addr, uint32_t backlog) override {
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

      // -----------------------------
      // Listen on the socket to allow for an incoming connection
      if (::listen(m_socket, backlog) == SOCKET_ERROR) {
        error(ESocketErrorReason::E_REASON_LISTEN);
        return false;
      }

      return true;
    }

    bool recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) override {
      if (m_recv_buffer->IsBusy) {
        return FALSE;
      }

      m_recv_buffer->Offset = m_recv_allocator->ofs(m_recv_buf_block) + offset;

      BOOL rc = s_rio->RIOReceive(m_request_queue, m_recv_buffer, 1, NULL, m_recv_buffer);
      if (rc) {
        m_recv_buffer->IsBusy = TRUE;
      }
      return rc;
    }

    bool send(const char* data, uint32_t size, uint32_t* flags) override {
      if (m_send_buffer->IsBusy) {
        return FALSE;
      }

      char* send_buf = (char*)m_send_allocator->ptr(m_send_buf_block);
      uint32_t block_size = m_send_allocator->block_size();

      uint32_t chunk_size = min(size, block_size);
      memcpy_s(send_buf, (size_t)block_size, data, chunk_size);
      m_send_buffer->Length = (ULONG)chunk_size;

      uint32_t flags_ = flags ? *flags : 0;

      BOOL rc = s_rio->RIOSend(m_request_queue, m_send_buffer, 1, flags_ & ~SKIP_BUF_INIT_FLAG, m_send_buffer);
      if (rc) {
        m_send_buffer->IsBusy = TRUE;
      }
      return rc;
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

    ISocketIOResult *wait_results() override {
      return new Win32ServerSocketIOResult(m_iocp, m_completion_queue, 32);
    }

    void* sys_data() const override { return m_iocp; }
    void* user_data() const override { return nullptr; }

    void on_close(close_cb cb) { m_on_close = cb; }
    void on_error(error_cb cb) { m_on_error = cb; }

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

    RIO_CQ m_completion_queue;
    RIO_RQ m_request_queue;
    HANDLE m_iocp;
    OVERLAPPED m_overlapped;

    ETransportLayerProtocol m_protocol;
  };

  bool SocketOSSupportLayerFactory::initialize() {
    return true;
  }

  bool SocketOSSupportLayerFactory::deinitialize() {
    if (s_rio) {
      delete s_rio;
    }
    return true;
  }

  ISocketOSSupportLayer* SocketOSSupportLayerFactory::create(netpp::ISocketOSSupportLayer* owner_socket_layer,
    netpp::StaticBlockAllocator* recv_allocator, netpp::StaticBlockAllocator* send_allocator, ETransportLayerProtocol protocol, ESocketHint hint) {
#ifdef _WIN32
    switch (hint) {
    case ESocketHint::E_CLIENT:
      return new Win32ClientSocketLayer(owner_socket_layer, recv_allocator, send_allocator, protocol);
    case ESocketHint::E_SERVER:
    default:
      if (int err = _win32_init_rio(owner_socket_layer->socket()); err != 0) {
        owner_socket_layer->error(ESocketErrorReason::E_REASON_SOCKET);
        return nullptr;
      }
      return new Win32ServerSocketLayer(owner_socket_layer, recv_allocator, send_allocator, protocol);
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
