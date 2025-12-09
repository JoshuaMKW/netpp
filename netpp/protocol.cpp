#include "netpp/protocol.h"
#include "netpp/http/request.h"
#include "netpp/http/response.h"
#include "netpp/socket.h"

#ifdef max
#undef max
#endif

namespace netpp {

  bool DNS_ApplicationAdapter::on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) {
    return false;
  }

  uint32_t DNS_ApplicationAdapter::calc_size(const char* data, uint32_t size) const {
    return 0;
  }

  uint32_t DNS_ApplicationAdapter::calc_proc_size(const char* data, uint32_t size) const {
    return 0;
  }

  bool DNS_ApplicationAdapter::wants_more_data(const char* data, uint32_t size) const {
    return false;
  }

  bool RAW_ApplicationAdapter::on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) {
    if (data == nullptr || size <= 4) {
      return false;
    }

    RawPacket packet(data + sizeof(uint32_t), size - sizeof(uint32_t));

    const RawPacket* response = pipe->signal_raw_receive(&packet);
    if (response) {
      pipe->send(response);
      delete response;
    }

    return true;
  }

  uint32_t RAW_ApplicationAdapter::calc_size(const char* data, uint32_t size) const {
    return size >= 4 ? *(uint32_t*)data + 4 : 0;
  }

  uint32_t RAW_ApplicationAdapter::calc_proc_size(const char* data, uint32_t size) const {
    return calc_size(data, size);
  }

  bool RAW_ApplicationAdapter::wants_more_data(const char* data, uint32_t size) const {
    return false;
  }

  bool RTP_ApplicationAdapter::on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) {
    return false;
  }

  uint32_t RTP_ApplicationAdapter::calc_size(const char* data, uint32_t size) const {
    return 0;
  }

  uint32_t RTP_ApplicationAdapter::calc_proc_size(const char* data, uint32_t size) const {
    return 0;
  }

  bool RTP_ApplicationAdapter::wants_more_data(const char* data, uint32_t size) const {
    return false;
  }

  bool RTCP_ApplicationAdapter::on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) {
    return false;
  }

  uint32_t RTCP_ApplicationAdapter::calc_size(const char* data, uint32_t size) const {
    return 0;
  }

  uint32_t RTCP_ApplicationAdapter::calc_proc_size(const char* data, uint32_t size) const {
    return 0;
  }

  bool RTCP_ApplicationAdapter::wants_more_data(const char* data, uint32_t size) const {
    return false;
  }

  bool SIP_ApplicationAdapter::on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) {
    return false;
  }

  uint32_t SIP_ApplicationAdapter::calc_size(const char* data, uint32_t size) const {
    return 0;
  }

  uint32_t SIP_ApplicationAdapter::calc_proc_size(const char* data, uint32_t size) const {
    return 0;
  }

  bool SIP_ApplicationAdapter::wants_more_data(const char* data, uint32_t size) const {
    return false;
  }

  IApplicationLayerAdapter* ApplicationAdapterFactory::create(EApplicationLayerProtocol protocol) {
    switch (protocol) {
    case EApplicationLayerProtocol::E_DNS:
      return new DNS_ApplicationAdapter();
    case EApplicationLayerProtocol::E_HTTP:
      return new HTTP_ApplicationAdapter();
    case EApplicationLayerProtocol::E_HTTPS:
      return new HTTPS_ApplicationAdapter();
    case EApplicationLayerProtocol::E_RAW:
      return new RAW_ApplicationAdapter();
    case EApplicationLayerProtocol::E_RTP:
      return new RTP_ApplicationAdapter();
    case EApplicationLayerProtocol::E_RTCP:
      return new RTCP_ApplicationAdapter();
    case EApplicationLayerProtocol::E_SIP:
      return new SIP_ApplicationAdapter();
    default:
      return nullptr;
    }
  }

  IApplicationLayerAdapter* ApplicationAdapterFactory::detect(const char* data, uint32_t size, ISecurityFactory *security) {
    EApplicationLayerProtocol protocol = EApplicationLayerProtocol::E_RAW;
    // Check here for HTTPS

    if (HTTP_Request::is_http_request(data, size) || HTTP_Response::is_http_response(data, size)) {
      protocol = security ? EApplicationLayerProtocol::E_HTTPS : EApplicationLayerProtocol::E_HTTP;
    }

    return create(protocol);
  }

}  // namespace netpp
