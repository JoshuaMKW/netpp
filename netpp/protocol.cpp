#include "protocol.h"
#include "request.h"
#include "response.h"
#include "socket.h"

namespace netpp {

  bool DNS_ApplicationAdapter::on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags)
  {
    return false;
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

  bool HTTPS_ApplicationAdapter::on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) {
    return false;
  }

  bool RAW_ApplicationAdapter::on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) {
    RawPacket packet(data, size);

    const RawPacket* response = pipe->signal_raw_receive(&packet);
    if (response) {
      pipe->send(response);
      delete response;
      return true;
    }

    return false;
  }

  bool RTP_ApplicationAdapter::on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags)
  {
    return false;
  }

  bool RTCP_ApplicationAdapter::on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags)
  {
    return false;
  }

  bool SIP_ApplicationAdapter::on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags)
  {
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

  IApplicationLayerAdapter* ApplicationAdapterFactory::detect(const char* data, uint32_t size) {
    EApplicationLayerProtocol protocol = EApplicationLayerProtocol::E_RAW;
    // Check here for HTTPS

    if (HTTP_Request::is_http_request(data, size) || HTTP_Response::is_http_response(data, size)) {
      protocol = EApplicationLayerProtocol::E_HTTP;
    }

    return create(protocol);
  }

}  // namespace netpp
