#include "netpp/protocol.h"
#include "netpp/http/request.h"
#include "netpp/http/response.h"
#include "netpp/socket.h"

namespace netpp {

  bool DNS_ApplicationAdapter::on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) {
    return false;
  }

  uint32_t DNS_ApplicationAdapter::calc_size(const char* data, uint32_t size) {
    return 0;
  }

  uint32_t DNS_ApplicationAdapter::calc_proc_size(const char* data, uint32_t size) {
    return 0;
  }

  bool HTTP_ApplicationAdapter::on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) {
    if (HTTP_Request::is_http_request(data, size)) {
      HTTP_Request* request = HTTP_Request::create(data, size);
      if (!request) {
        return false;
      }

      const HTTP_Response* response = pipe->signal_http_request(request);
      if (response) {
        pipe->send(response); 
        delete response;
      }

      delete request;
      return true;
    }

    if (HTTP_Response::is_http_response(data, size)) {
      HTTP_Response* response = HTTP_Response::create(data, size);
      if (!response) {
        return false;
      }

      const HTTP_Request* request = pipe->signal_http_response(response);
      if (request) {
        pipe->send(request);
        delete request;
      }

      delete response;
      return true;
    }

    return false;
  }

  uint32_t HTTP_ApplicationAdapter::calc_size(const char* data, uint32_t size) {
    if (const char* h_end = HTTP_Request::header_end(data, size)) {
      uint32_t content_length = HTTP_Request::content_length(data, size);
      return ((uint32_t)(h_end - data) + 4) + content_length;
    }

    if (const char* h_end = HTTP_Response::header_end(data, size)) {
      uint32_t content_length = HTTP_Response::content_length(data, size);
      return ((uint32_t)(h_end - data) + 4) + content_length;
    }
    return 0;
  }

  uint32_t HTTP_ApplicationAdapter::calc_proc_size(const char* data, uint32_t size) {
    return calc_size(data, size);
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

  uint32_t RAW_ApplicationAdapter::calc_size(const char* data, uint32_t size) {
    return size >= 4 ? *(uint32_t*)data + 4 : 0;
  }

  uint32_t RAW_ApplicationAdapter::calc_proc_size(const char* data, uint32_t size) {
    return calc_size(data, size);
  }

  bool RTP_ApplicationAdapter::on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) {
    return false;
  }

  uint32_t RTP_ApplicationAdapter::calc_size(const char* data, uint32_t size) {
    return 0;
  }

  uint32_t RTP_ApplicationAdapter::calc_proc_size(const char* data, uint32_t size) {
    return 0;
  }

  bool RTCP_ApplicationAdapter::on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) {
    return false;
  }

  uint32_t RTCP_ApplicationAdapter::calc_size(const char* data, uint32_t size) {
    return 0;
  }

  uint32_t RTCP_ApplicationAdapter::calc_proc_size(const char* data, uint32_t size) {
    return 0;
  }

  bool SIP_ApplicationAdapter::on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) {
    return false;
  }

  uint32_t SIP_ApplicationAdapter::calc_size(const char* data, uint32_t size) {
    return 0;
  }

  uint32_t SIP_ApplicationAdapter::calc_proc_size(const char* data, uint32_t size) {
    return 0;
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
