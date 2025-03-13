#pragma once

#include <functional>
#include <queue>
#include <mutex>
#include <vector>
#include <unordered_map>

#include "allocator.h"
#include "network.h"
#include "response.h"
#include "request.h"
#include "socket.h"

#define CLIENT_USE_WSA 0

namespace netpp {

  enum class EClientError {
    E_NONE = -1,
    E_ERROR_SOCKET,
    E_COUNT,
  };

  const char* client_error(EClientError error, int reason);

  class IClient {
  public:
    using receive_callback = std::function<RawPacket* (const ISocketPipe* source, const RawPacket* packet)>;
    using request_callback = std::function<HTTP_Response* (const ISocketPipe* source, const HTTP_Request* request)>;
    using response_callback = std::function<HTTP_Request* (const ISocketPipe* source, const HTTP_Response* response)>;

    virtual ~IClient() = default;

    virtual bool is_running() const = 0;
    virtual bool is_connected() const = 0;

    // Start the client to listen on the specified port
    virtual bool start() = 0;
    virtual void stop() = 0;

    virtual bool connect(const char* hostname, const char* port, uint64_t timeout = 0) = 0;
    virtual void disconnect() = 0;

    virtual const std::string& hostname() const = 0;
    virtual const std::string& port() const = 0;

    virtual const std::string& server_hostname() const = 0;
    virtual const std::string& server_port() const = 0;

    // Get the last error that occured
    virtual EClientError error() const = 0;

    // Get the reason for the last error
    virtual int reason() const = 0;

    // Set these before starting the client
    virtual void on_receive(receive_callback callback) = 0;
    virtual void on_response(response_callback callback) = 0;

    virtual bool send(const HTTP_Request*) = 0;
    virtual bool send(const RawPacket*) = 0;

  protected:
    virtual void emit_error(ISocketPipe* pipe, EClientError error, int reason) = 0;
  };

  class TCP_Client final : public IClient {
  public:
    TCP_Client(uint32_t bufsize = 4096);
    ~TCP_Client();

    bool is_running() const override;
    bool is_connected() const override;

    bool start() override;
    void stop() override;

    bool connect(const char* hostname, const char* port, uint64_t timeout = 0) override;
    void disconnect() override;

    const std::string& hostname() const override { return m_server_pipe->hostname(); }
    const std::string& port() const override { return m_server_pipe->port(); }

    const std::string& server_hostname() const override { return m_server_pipe->hostname(); }
    const std::string& server_port() const override { return m_server_pipe->port(); }

    EClientError error() const override { return m_error; }
    int reason() const override { return m_reason; }

    // Set these before starting the client
    void on_receive(receive_callback callback) override { m_receive_callback = callback; }
    void on_response(response_callback callback) override { m_response_callback = callback; }

    bool send(const HTTP_Request*) override;
    bool send(const RawPacket*) override;

    void set_send_flow_spec(const NetworkFlowSpec& flow_spec) { m_send_spec = flow_spec; }
    void set_recv_flow_spec(const NetworkFlowSpec& flow_spec) { m_recv_spec = flow_spec; }

  protected:
    void emit_error(ISocketPipe* pipe, EClientError error, int reason) override;

  protected:
    friend struct Win32SocketPipe;

    using pipe_response_callback = response_callback;
    using pipe_receive_callback = receive_callback;

#ifdef _WIN32

    enum class ESocketOperation : DWORD {
      E_SEND,
      E_RECV,
      E_CLOSE,
    };

    enum class ECompletionKey : DWORD {
      E_STOP,
      E_START,
    };

    struct Win32SocketPipe;

    struct Tag_WSA_BUF : public WSABUF {
      Tag_WSA_BUF(CHAR* buffer, DWORD length, ESocketOperation operation, Win32SocketPipe* owner) {
        this->buf = buffer;
        this->len = length;
        this->Operation = operation;
        this->Pipe = owner;
        this->IsBusy = FALSE;
      }

      ESocketOperation Operation;
      Win32SocketPipe* Pipe;
      BOOL IsBusy;
    };

    struct Tag_WSA_OVERLAPPED : public WSAOVERLAPPED {
      Tag_WSA_OVERLAPPED(WSABUF* buffer, ESocketOperation operation, Win32SocketPipe* owner) {
        this->Internal = 0;
        this->InternalHigh = 0;
        this->Offset = 0;
        this->OffsetHigh = 0;
        this->hEvent = nullptr;
        this->Operation = operation;
        this->Pipe = owner;
        this->Buffer = buffer;
      }

      ESocketOperation Operation;
      Win32SocketPipe* Pipe;
      WSABUF* Buffer;
    };

    struct Win32SocketPipe : ISocketPipe {
      friend class TCP_Client;

      Win32SocketPipe(TCP_Client* client) {
        m_socket = INVALID_SOCKET;
        m_host_name = "";
        m_port = "";
        m_recv_buffer = new Tag_WSA_BUF{
          client->m_recvbuf,
          (DWORD)client->m_recvbuflen,
          ESocketOperation::E_RECV,
          this
        };
        m_send_buffer = new Tag_WSA_BUF{
          client->m_sendbuf,
          (DWORD)client->m_sendbuflen,
          ESocketOperation::E_SEND,
          this
        };
        m_recv_overlapped = new Tag_WSA_OVERLAPPED{
          m_send_buffer,
          ESocketOperation::E_RECV,
          this
        };
        m_send_overlapped = new Tag_WSA_OVERLAPPED{
          m_recv_buffer,
          ESocketOperation::E_SEND,
          this
        };
        m_iocp = INVALID_HANDLE_VALUE;
        m_client = client;
        m_connected = false;
        m_connecting = false;
      }

      ~Win32SocketPipe() {
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

      uint64_t socket() const override { return (uint64_t)m_socket; }

      const std::string& hostname() const override { return m_host_name; }
      const std::string& port() const override { return m_port; }

      bool is_busy(EPipeOperation op) const override;

      bool open(const char* hostname, const char* port) override;
      void close() override;
      void error(ESocketErrorReason reason) override;
      bool recv(uint32_t offset, uint32_t* flags, uint32_t* unused) override;
      bool send(const char* data, uint32_t size, uint32_t* flags) override;
      bool send(const HTTP_Response* response) override;
      bool send(const HTTP_Request* request) override;
      bool send(const RawPacket* packet) override;

      void on_close(ISocketPipe::close_callback callback) override {  }
      void on_dns_request(ISocketPipe::dns_request_callback callback) override { m_on_dns_request = callback; }
      void on_dns_response(ISocketPipe::dns_response_callback callback) override { m_on_dns_response = callback; }
      void on_http_request(ISocketPipe::http_request_callback callback) override { m_on_http_request = callback; }
      void on_http_response(ISocketPipe::http_response_callback callback) override { m_on_http_response = callback; }
      void on_raw_receive(ISocketPipe::raw_receive_callback callback) override { m_on_raw_receive = callback; }
      void on_rtp_packet(ISocketPipe::rtp_packet_callback callback) override { m_on_rtp_packet = callback; }
      void on_rtcp_packet(ISocketPipe::rtcp_packet_callback callback) override { m_on_rtcp_packet = callback; }
      void on_sip_request(ISocketPipe::sip_request_callback callback) override { m_on_sip_request = callback; }
      void on_sip_response(ISocketPipe::sip_response_callback callback) override { m_on_sip_response = callback; }

      const DNS_Response* signal_dns_request(const DNS_Request* request) override;
      const DNS_Request* signal_dns_response(const DNS_Response* response) override;
      const HTTP_Response* signal_http_request(const HTTP_Request* request) override;
      const HTTP_Request* signal_http_response(const HTTP_Response* response) override;
      const RawPacket* signal_raw_receive(const RawPacket* packet) override;
      void signal_rtp_packet(const RTP_Packet* packet) override;
      void signal_rtcp_packet(const RTCP_Packet* packet) override;
      const SIP_Response* signal_sip_request(const SIP_Request* request) override;
      const SIP_Request* signal_sip_response(const SIP_Response* response) override;

    protected:
      char* recv_buf();
      uint32_t recv_buf_size();
      char* send_buf();
      uint32_t send_buf_size();

      std::string m_host_name;
      std::string m_port;

      ISocketPipe::dns_request_callback m_on_dns_request;
      ISocketPipe::dns_response_callback m_on_dns_response;
      ISocketPipe::http_request_callback m_on_http_request;
      ISocketPipe::http_response_callback m_on_http_response;
      ISocketPipe::raw_receive_callback m_on_raw_receive;
      ISocketPipe::rtp_packet_callback m_on_rtp_packet;
      ISocketPipe::rtcp_packet_callback m_on_rtcp_packet;
      ISocketPipe::sip_request_callback m_on_sip_request;
      ISocketPipe::sip_response_callback m_on_sip_response;

      Tag_WSA_BUF* m_recv_buffer;
      Tag_WSA_BUF* m_send_buffer;

      SOCKET m_socket;
      std::mutex m_mutex;

      HANDLE m_iocp;
      Tag_WSA_OVERLAPPED* m_recv_overlapped;
      Tag_WSA_OVERLAPPED* m_send_overlapped;

      LPFN_DISCONNECTEX DisconnectEx;

      TCP_Client* m_client;

      bool m_connected;
      bool m_connecting;
    };

#else
    using close_callback = std::function<void(int socket)>;
    using pipe_response_callback = response_callback;
    using pipe_receive_callback = receive_callback;
    using send_response_fn = std::function<bool(int socket, const HTTP_Response* response)>;
    using send_packet_fn = std::function<bool(int socket, const RawPacket* packet)>;
    using error_fn = std::function<void(int socket, EClientError error, int reason)>;

    struct SocketPipe {
      int m_socket;
      std::mutex m_mutex;

      // Pipe interface
      close_callback on_close;
      pipe_response_callback on_response;
      pipe_receive_callback on_receive;
      send_response_fn send_response;
      send_packet_fn send_packet;
    };
#endif

    bool is_startup_thread_cur() const;

    bool initialize();
    void deinitialize();

#ifdef _WIN32
    static uint64_t client_iocp_thread_win32(void* param);
    static void wsa_completion_callback(DWORD error, DWORD transferred, LPWSAOVERLAPPED overlapped, DWORD flags);
#endif

    static uint64_t client_connect_thread(void* param);

  private:
    EClientError m_error;
    int m_reason;

    ISocketPipe* m_server_pipe;

    std::thread::id m_startup_thread;

    std::thread m_connect_thread;
    std::thread m_iocp_thread;

    char* m_sendbuf;
    uint32_t m_sendbuflen;

    char* m_recvbuf;
    uint32_t m_recvbuflen;

    receive_callback m_receive_callback;
    request_callback m_request_callback;
    response_callback m_response_callback;

    NetworkFlowSpec m_send_spec;
    NetworkFlowSpec m_recv_spec;

    std::mutex m_mutex;
    bool m_stop_flag;
  };

}  // namespace netpp
