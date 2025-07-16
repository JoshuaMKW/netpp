#pragma once

#include <functional>
#include <string>

#include "request.h"
#include "response.h"

namespace netpp {

  class HTTP_Router {
  public:

    HTTP_Router() = default;
    ~HTTP_Router() = default;

    using get_cb = std::function<HTTP_Response* (const HTTP_Request* request)>;
    using head_cb = std::function<HTTP_Response* (const HTTP_Request* request)>;
    using post_cb = std::function<HTTP_Response* (const HTTP_Request* request)>;
    using put_cb = std::function<HTTP_Response* (const HTTP_Request* request)>;
    using delete_cb = std::function<HTTP_Response* (const HTTP_Request* request)>;
    using options_cb = std::function<HTTP_Response* (const HTTP_Request* request)>;
    using trace_cb = std::function<HTTP_Response* (const HTTP_Request* request)>;
    using connect_cb = std::function<HTTP_Response* (const HTTP_Request* request)>;
    using patch_cb = std::function<HTTP_Response* (const HTTP_Request* request)>;
    using unhandled_cb = std::function<HTTP_Response* (const HTTP_Request* request)>;

    HTTP_Response* on_get(const std::string& route, get_cb handler) { m_get_cb[route] = handler; }
    HTTP_Response* on_head(const std::string& route, head_cb handler) { m_head_cb[route] = handler; }
    HTTP_Response* on_post(const std::string& route, post_cb handler) { m_post_cb[route] = handler; }
    HTTP_Response* on_put(const std::string& route, put_cb handler) { m_put_cb[route] = handler; }
    HTTP_Response* on_delete(const std::string& route, delete_cb handler) { m_delete_cb[route] = handler; }
    HTTP_Response* on_options(const std::string& route, options_cb handler) { m_options_cb[route] = handler; }
    HTTP_Response* on_trace(const std::string& route, trace_cb handler) { m_trace_cb[route] = handler; }
    HTTP_Response* on_connect(const std::string& route, trace_cb handler) { m_connect_cb[route] = handler; }
    HTTP_Response* on_patch(const std::string& route, patch_cb handler) { m_patch_cb[route] = handler; }

    HTTP_Response* on_unhandled(unhandled_cb handler) { m_unhandled_cb = handler; }

    const HTTP_Response* signal_method(const HTTP_Request* request);

  private:
    std::unordered_map<std::string, get_cb> m_get_cb;
    std::unordered_map<std::string, head_cb> m_head_cb;
    std::unordered_map<std::string, post_cb> m_post_cb;
    std::unordered_map<std::string, put_cb> m_put_cb;
    std::unordered_map<std::string, delete_cb> m_delete_cb;
    std::unordered_map<std::string, options_cb> m_options_cb;
    std::unordered_map<std::string, trace_cb> m_trace_cb;
    std::unordered_map<std::string, trace_cb> m_connect_cb;
    std::unordered_map<std::string, patch_cb> m_patch_cb;

    unhandled_cb m_unhandled_cb;
  };

}