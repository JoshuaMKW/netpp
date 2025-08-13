#pragma once

#include <functional>
#include <mutex>
#include <string>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsockdef.h>
#include <MSWSock.h>
#else
#include <sys/socket.h>
#endif

#include "netpp.h"
#include "allocator.h"
#include "network.h"
#include "protocol.h"
#include "sockenum.h"
#include "http/request.h"
#include "http/response.h"

namespace netpp {

    class DNS_Request;
  class DNS_Response;
  class HTTP_Request;
  class HTTP_Response;
  class RawPacket;
  class RTP_Packet;
  class RTCP_Packet;
  class SIP_Request;
  class SIP_Response;

  class SocketLock {
  public:
    SocketLock(std::mutex& mut) : m_lock(mut) {}
    ~SocketLock() = default;

  private:
    std::unique_lock<std::mutex> m_lock;
  };

  struct SocketIOState {
    const char* m_bytes_buf = nullptr;
    uint32_t m_bytes_transferred = 0;
    uint32_t m_bytes_total = 0;

    char* m_proc_buf = nullptr;
    uint32_t m_bytes_processed = 0;

    void reset_all() {
      m_bytes_buf = nullptr;
      reset_state();
    }

    void reset_state() {
      m_bytes_transferred = 0;
      m_bytes_total = 0;
      m_bytes_processed = 0;

      delete[] m_proc_buf;
      m_proc_buf = nullptr;
    }
  };

  class ISocketOSSupportLayer;

  class NETPP_API ISocketIOResult {
  public:
    struct OperationData {
      EPipeOperation m_operation;
      uint32_t m_bytes_transferred;
      uint64_t m_socket;
    };

    using each_fn = std::function<bool(ISocketOSSupportLayer* pipe, const OperationData& info)>;

    virtual ~ISocketIOResult() = default;

    virtual bool is_valid() const = 0;
    virtual bool for_each(each_fn cb) = 0;
  };

  class NETPP_API ISocketOSSupportLayer {
  public:
    using close_cb = std::function<bool(ISocketOSSupportLayer*)>;
    using error_cb = std::function<bool(ISocketOSSupportLayer*, ESocketErrorReason reason)>;

    using accept_cb = std::function<bool(uint64_t socket)>;
    using accept_cond_cb = std::function<bool(
      EInternetLayerProtocol protocol,
      const std::string& client_ip, const std::string& client_port,
      const NetworkFlowSpec* client_recv, const NetworkFlowSpec* client_send,
      const RawPacket& request_in, RawPacket& response_out)>;

    virtual ~ISocketOSSupportLayer() = default;

    virtual uint64_t socket() const = 0;
    virtual ETransportLayerProtocol protocol() const = 0;

    virtual bool is_server() const = 0;
    virtual bool is_ready(EPipeOperation op) const = 0;
    virtual bool is_busy(EPipeOperation op) const = 0;
    virtual void set_busy(EPipeOperation op, bool busy) = 0;

    virtual EIOState state(EPipeOperation op) const = 0;
    virtual void signal_io_complete(EPipeOperation op) = 0;

    virtual bool open(const char* hostname, const char* port) = 0;
    virtual bool open(uint64_t socket) = 0;

    virtual void close() = 0;
    virtual void error(ESocketErrorReason reason) = 0;

    virtual bool notify_all() = 0;

    // Return value is how many bytes were transferred or -1 on error.
    virtual int64_t sync(EPipeOperation op = EPipeOperation::E_RECV_SEND, uint64_t wait_time = 0) = 0;

    virtual SocketLock acquire_lock() = 0;

    virtual bool accept(accept_cond_cb accept_cond, accept_cb accept_routine) = 0;
    virtual bool bind(const char* addr = nullptr) = 0;
    virtual bool listen(uint32_t backlog = 0x7FFFFFFF) = 0;
    virtual bool connect(uint64_t timeout = 0, const NetworkFlowSpec* recv_flowspec = nullptr, const NetworkFlowSpec* send_flowspec = nullptr) = 0;

    virtual int32_t recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) = 0;

    // Application surrenders ownership of the buffer
    virtual int32_t send(const char* data, uint32_t size, uint32_t* flags) = 0;

    // --------------------

    virtual char* recv_buf() const = 0;
    virtual uint32_t recv_buf_size() const = 0;
    virtual char* send_buf() const = 0;
    virtual uint32_t send_buf_size() const = 0;

    virtual void set_recv_buf(char* buf) = 0;
    virtual void set_recv_buf_size(uint32_t size) = 0;
    virtual void set_send_buf(const char* buf) = 0;
    virtual void set_send_buf_size(uint32_t size) = 0;

    // Use to signal to sync() how much transferred.
    virtual int64_t get_transferred(EPipeOperation op) = 0;
    virtual void set_transferred(EPipeOperation op, int64_t transferred) = 0;

    virtual ISocketIOResult* wait_results() = 0;

    virtual void* sys_data() const = 0;
    virtual void* user_data() const = 0;

    // --------------------

    virtual void on_close(close_cb cb) = 0;
    virtual void on_error(error_cb cb) = 0;
    virtual void clone_callbacks_from(ISocketOSSupportLayer* other) = 0;
  };

  class NETPP_API SocketOSSupportLayerFactory {
  public:
    static bool initialize(uint64_t socket);
    static ISocketOSSupportLayer* create(netpp::ISocketOSSupportLayer* owner_socker_layer,
      netpp::StaticBlockAllocator* recv_allocator, netpp::StaticBlockAllocator* send_allocator,
      ETransportLayerProtocol protocol, ESocketHint hint, void* user_data = nullptr);
    static bool deinitialize();
  };

}
