#pragma once

#include <cstdint>

#include "netpp/netpp.h"
#include "netpp/network.h"
#include "netpp/security.h"

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

#pragma region Application Layer

  class ISocketPipe;

  class NETPP_API IApplicationLayerAdapter {
  public:
    virtual ~IApplicationLayerAdapter() = default;

    virtual bool on_receive(ISocketPipe *pipe, const char* data, uint32_t size, uint32_t flags) = 0;

    // Calculate the total size of the application layer packet
    // when this is 0, assume to read until the end of the stream.
    virtual uint32_t calc_size(const char* data, uint32_t size) const = 0;
    virtual uint32_t calc_proc_size(const char* data, uint32_t size) const = 0;

    virtual bool wants_more_data(const char* data, uint32_t size) const = 0;
  };

  class NETPP_API DNS_ApplicationAdapter final : public IApplicationLayerAdapter {
  public:
    DNS_ApplicationAdapter() = default;
    ~DNS_ApplicationAdapter() override = default;

    bool on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) override;
    uint32_t calc_size(const char* data, uint32_t size) const override;
    uint32_t calc_proc_size(const char* data, uint32_t size) const override;
    bool wants_more_data(const char* data, uint32_t size) const override;
  };

  class NETPP_API HTTP_ApplicationAdapter : public IApplicationLayerAdapter {
  public:
    HTTP_ApplicationAdapter() = default;
    ~HTTP_ApplicationAdapter() override = default;

    bool on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) override;
    uint32_t calc_size(const char* data, uint32_t size) const override;
    uint32_t calc_proc_size(const char* data, uint32_t size) const override;
    bool wants_more_data(const char* data, uint32_t size) const override;
  };

  class NETPP_API HTTPS_ApplicationAdapter final : public HTTP_ApplicationAdapter {
  public:
    HTTPS_ApplicationAdapter() = default;
    ~HTTPS_ApplicationAdapter() override = default;
  };

  class NETPP_API RAW_ApplicationAdapter final : public IApplicationLayerAdapter {
  public:
    RAW_ApplicationAdapter() = default;
    ~RAW_ApplicationAdapter() override = default;

    bool on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) override;
    uint32_t calc_size(const char* data, uint32_t size) const override;
    uint32_t calc_proc_size(const char* data, uint32_t size) const override;
    bool wants_more_data(const char* data, uint32_t size) const override;
  };

  class NETPP_API RTP_ApplicationAdapter final : public IApplicationLayerAdapter {
  public:
    RTP_ApplicationAdapter() = default;
    ~RTP_ApplicationAdapter() override = default;

    bool on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) override;
    uint32_t calc_size(const char* data, uint32_t size) const override;
    uint32_t calc_proc_size(const char* data, uint32_t size) const override;
    bool wants_more_data(const char* data, uint32_t size) const override;
  };

  class NETPP_API RTCP_ApplicationAdapter final : public IApplicationLayerAdapter {
  public:
    RTCP_ApplicationAdapter() = default;
    ~RTCP_ApplicationAdapter() override = default;

    bool on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) override;
    uint32_t calc_size(const char* data, uint32_t size) const override;
    uint32_t calc_proc_size(const char* data, uint32_t size) const override;
    bool wants_more_data(const char* data, uint32_t size) const override;
  };

  class NETPP_API SIP_ApplicationAdapter final : public IApplicationLayerAdapter {
  public:
    SIP_ApplicationAdapter() = default;
    ~SIP_ApplicationAdapter() override = default;

    bool on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) override;
    uint32_t calc_size(const char* data, uint32_t size) const override;
    uint32_t calc_proc_size(const char* data, uint32_t size) const override;
    bool wants_more_data(const char* data, uint32_t size) const override;
  };

  class NETPP_API ApplicationAdapterFactory {
  public:
    static IApplicationLayerAdapter* create(EApplicationLayerProtocol protocol);
    static IApplicationLayerAdapter* detect(const char* data, uint32_t size, ISecurityFactory *security);
  };

#pragma endregion

}  // namespace netpp