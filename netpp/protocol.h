#pragma once

#include <cstdint>

#include "network.h"

struct sockaddr;

namespace netpp {

  enum class EInternetLayerProtocol {
    E_NONE = -1,
    E_IPV4,
    E_IPV6,
    E_COUNT,
  };

  enum class ETransportLayerProtocol {
    E_NONE = -1,
    E_TCP,
    E_UDP,
    E_COUNT,
  };

  enum class EApplicationLayerProtocol {
    E_NONE = -1,
    E_DNS,
    E_HTTP,
    E_HTTPS,
    E_RAW,
    E_RTP,
    E_RTCP,
    E_SIP,
    E_COUNT,
  };

#pragma region Transport Layer

  class ITransportLayerAdapter {
  public:
    virtual ~ITransportLayerAdapter() = default;

    virtual ETransportLayerProtocol protocol() const = 0;

    virtual uint64_t open_socket(EInternetLayerProtocol internet_protocol) = 0;
    virtual void close_socket(uint64_t sockfd) = 0;

    virtual bool bind(uint64_t sockfd, sockaddr* inaddr) = 0;
    virtual bool listen(uint64_t sockfd, uint32_t backlog) = 0;

    virtual bool connect(uint64_t sockfd, sockaddr* inaddr, const NetworkFlowSpec* recv_spec, const NetworkFlowSpec* send_spec) = 0;
    virtual void disconnect(uint64_t sockfd) = 0;

    virtual bool ping(uint64_t sockfd, sockaddr* inaddr) = 0;
    virtual bool recv(uint64_t sockfd, sockaddr* inaddr, char* buffer, uint32_t size, uint32_t* flags, uint32_t* transferred_out) = 0;
    virtual bool send(uint64_t sockfd, sockaddr* inaddr, const char* buffer, uint32_t size, uint32_t* flags) = 0;

    virtual void set_user_context(void* ctx) = 0;
  };

  class TCPTransportAdapter final : public ITransportLayerAdapter {
  public:
    TCPTransportAdapter() = default;
    ~TCPTransportAdapter() override = default;

    ETransportLayerProtocol protocol() const override {
      return ETransportLayerProtocol::E_TCP;
    }

    uint64_t open_socket(EInternetLayerProtocol internet_protocol) override;
    void close_socket(uint64_t sockfd) override;

    bool bind(uint64_t sockfd, sockaddr* inaddr) override;
    bool listen(uint64_t sockfd, uint32_t backlog) override;

    bool connect(uint64_t sockfd, sockaddr* inaddr, const NetworkFlowSpec* recv_spec, const NetworkFlowSpec* send_spec) override;
    void disconnect(uint64_t sockfd) override;

    bool ping(uint64_t sockfd, sockaddr* inaddr) override;
    bool recv(uint64_t sockfd, sockaddr* inaddr, char* buffer, uint32_t size, uint32_t* flags, uint32_t* transferred_out) override;
    bool send(uint64_t sockfd, sockaddr* inaddr, const char* buffer, uint32_t size, uint32_t* flags) override;
  };

  class UDPTransportAdapter final : public ITransportLayerAdapter {
  public:
    UDPTransportAdapter(bool server_mode, void* user_data);
    ~UDPTransportAdapter() override = default;

  protected:
    UDPTransportAdapter() = default;

  public:
    ETransportLayerProtocol protocol() const override {
      return ETransportLayerProtocol::E_UDP;
    }

    uint64_t open_socket(EInternetLayerProtocol internet_protocol) override;
    void close_socket(uint64_t sockfd) override;

    bool connect(uint64_t sockfd, sockaddr* inaddr, const NetworkFlowSpec* recv_spec, const NetworkFlowSpec* send_spec) override;
    void disconnect(uint64_t sockfd) override;

    bool ping(uint64_t sockfd, sockaddr* inaddr) override;
    bool recv(uint64_t sockfd, sockaddr* inaddr, char* buffer, uint32_t size, uint32_t* flags, uint32_t* transferred_out) override;
    bool send(uint64_t sockfd, sockaddr* inaddr, const char* buffer, uint32_t size, uint32_t* flags) override;

  private:
    bool m_server_mode;
    void* m_io_data;
  };

#pragma endregion

#pragma region Application Layer

  class ISocketPipe;

  class IApplicationLayerAdapter {
  public:
    virtual ~IApplicationLayerAdapter() = default;

    virtual bool on_receive(ISocketPipe *pipe, const char* data, uint32_t size, uint32_t flags) = 0;
    virtual uint32_t calc_size(const char* data, uint32_t size) = 0;
    virtual uint32_t calc_proc_size(const char* data, uint32_t size) = 0;
  };

  class DNS_ApplicationAdapter final : public IApplicationLayerAdapter {
  public:
    DNS_ApplicationAdapter() = default;
    ~DNS_ApplicationAdapter() override = default;

    bool on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) override;
    uint32_t calc_size(const char* data, uint32_t size) override;
    uint32_t calc_proc_size(const char* data, uint32_t size) override;
  };

  class HTTP_ApplicationAdapter final : public IApplicationLayerAdapter {
  public:
    HTTP_ApplicationAdapter() = default;
    ~HTTP_ApplicationAdapter() override = default;

    bool on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) override;
    uint32_t calc_size(const char* data, uint32_t size) override;
    uint32_t calc_proc_size(const char* data, uint32_t size) override;
  };

  class HTTPS_ApplicationAdapter final : public IApplicationLayerAdapter {
  public:
    HTTPS_ApplicationAdapter() = default;
    ~HTTPS_ApplicationAdapter() override = default;

    bool on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) override;
    uint32_t calc_size(const char* data, uint32_t size) override;
    uint32_t calc_proc_size(const char* data, uint32_t size) override;
  };

  class RAW_ApplicationAdapter final : public IApplicationLayerAdapter {
  public:
    RAW_ApplicationAdapter() = default;
    ~RAW_ApplicationAdapter() override = default;

    bool on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) override;
    uint32_t calc_size(const char* data, uint32_t size) override;
    uint32_t calc_proc_size(const char* data, uint32_t size) override;
  };

  class RTP_ApplicationAdapter final : public IApplicationLayerAdapter {
  public:
    RTP_ApplicationAdapter() = default;
    ~RTP_ApplicationAdapter() override = default;

    bool on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) override;
    uint32_t calc_size(const char* data, uint32_t size) override;
    uint32_t calc_proc_size(const char* data, uint32_t size) override;
  };

  class RTCP_ApplicationAdapter final : public IApplicationLayerAdapter {
  public:
    RTCP_ApplicationAdapter() = default;
    ~RTCP_ApplicationAdapter() override = default;

    bool on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) override;
    uint32_t calc_size(const char* data, uint32_t size) override;
    uint32_t calc_proc_size(const char* data, uint32_t size) override;
  };

  class SIP_ApplicationAdapter final : public IApplicationLayerAdapter {
  public:
    SIP_ApplicationAdapter() = default;
    ~SIP_ApplicationAdapter() override = default;

    bool on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) override;
    uint32_t calc_size(const char* data, uint32_t size) override;
    uint32_t calc_proc_size(const char* data, uint32_t size) override;
  };

  class ApplicationAdapterFactory {
  public:
    static IApplicationLayerAdapter* create(EApplicationLayerProtocol protocol);
    static IApplicationLayerAdapter* detect(const char* data, uint32_t size);
  };

#pragma endregion

}  // namespace netpp