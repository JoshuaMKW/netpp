#include "router.h"

namespace netpp {

  HTTP_Response* HTTP_Router::signal_method(const HTTP_Request* request) {
    if (!request) {
      return nullptr;
    }

    switch (request->method()) {
    case EHTTP_RequestMethod::E_REQUEST_GET:
      if (m_get_cb.find(request->path()) == m_get_cb.end()) {
        return m_unhandled_cb ? m_unhandled_cb(request) : nullptr;
      }
      return m_get_cb[request->path()](request);
    case EHTTP_RequestMethod::E_REQUEST_POST:
      if (m_post_cb.find(request->path()) == m_post_cb.end()) {
        return m_unhandled_cb ? m_unhandled_cb(request) : nullptr;
      }
      return m_post_cb[request->path()](request);
    case EHTTP_RequestMethod::E_REQUEST_PUT:
      if (m_put_cb.find(request->path()) == m_put_cb.end()) {
        return m_unhandled_cb ? m_unhandled_cb(request) : nullptr;
      }
      return m_put_cb[request->path()](request);
    case EHTTP_RequestMethod::E_REQUEST_DELETE:
      if (m_delete_cb.find(request->path()) == m_delete_cb.end()) {
        return m_unhandled_cb ? m_unhandled_cb(request) : nullptr;
      }
      return m_delete_cb[request->path()](request);
    case EHTTP_RequestMethod::E_REQUEST_HEAD:
      if (m_head_cb.find(request->path()) == m_head_cb.end()) {
        return m_unhandled_cb ? m_unhandled_cb(request) : nullptr;
      }
      return m_head_cb[request->path()](request);
    case EHTTP_RequestMethod::E_REQUEST_OPTIONS:
      if (m_options_cb.find(request->path()) == m_options_cb.end()) {
        return m_unhandled_cb ? m_unhandled_cb(request) : nullptr;
      }
      return m_options_cb[request->path()](request);
    case EHTTP_RequestMethod::E_REQUEST_TRACE:
      if (m_trace_cb.find(request->path()) == m_trace_cb.end()) {
        return m_unhandled_cb ? m_unhandled_cb(request) : nullptr;
      }
      return m_trace_cb[request->path()](request);
    case EHTTP_RequestMethod::E_REQUEST_CONNECT:
      if (m_connect_cb.find(request->path()) == m_connect_cb.end()) {
        return m_unhandled_cb ? m_unhandled_cb(request) : nullptr;
      }
      return m_connect_cb[request->path()](request);
    case EHTTP_RequestMethod::E_REQUEST_PATCH:
      if (m_patch_cb.find(request->path()) == m_patch_cb.end()) {
        return m_unhandled_cb ? m_unhandled_cb(request) : nullptr;
      }
      return m_patch_cb[request->path()](request);
    default:
      return m_unhandled_cb ? m_unhandled_cb(request) : nullptr;
    }
  }

}

