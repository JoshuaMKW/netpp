#pragma once

#include <string>
#include <vector>

#include "netpp.h"

namespace netpp {

  enum class EHTTP_ResponseStatusCode {
    E_NONE = -1,
    E_STATUS_CONTINUE = 100,
    E_STATUS_SWITCHING_PROTOCOLS = 101,
    E_STATUS_PROCESSING = 102,
    E_STATUS_EARLY_HINTS = 103,
    E_STATUS_OK = 200,
    E_STATUS_CREATED = 201,
    E_STATUS_ACCEPTED = 202,
    E_STATUS_NON_AUTHORITATIVE_INFORMATION = 203,
    E_STATUS_NO_CONTENT = 204,
    E_STATUS_RESET_CONTENT = 205,
    E_STATUS_PARTIAL_CONTENT = 206,
    E_STATUS_MULTI_STATUS = 207,
    E_STATUS_ALREADY_REPORTED = 208,
    E_STATUS_IM_USED = 226,
    E_STATUS_MULTIPLE_CHOICES = 300,
    E_STATUS_MOVED_PERMANENTLY = 301,
    E_STATUS_FOUND = 302,
    E_STATUS_SEE_OTHER = 303,
    E_STATUS_NOT_MODIFIED = 304,
    E_STATUS_USE_PROXY = 305,
    E_STATUS_SWITCH_PROXY = 306,
    E_STATUS_TEMPORARY_REDIRECT = 307,
    E_STATUS_PERMANENT_REDIRECT = 308,
    E_STATUS_BAD_REQUEST = 400,
    E_STATUS_UNAUTHORIZED = 401,
    E_STATUS_PAYMENT_REQUIRED = 402,
    E_STATUS_FORBIDDEN = 403,
    E_STATUS_NOT_FOUND = 404,
    E_STATUS_METHOD_NOT_ALLOWED = 405,
    E_STATUS_NOT_ACCEPTABLE = 406,
    E_STATUS_PROXY_AUTHENTICATION_REQUIRED = 407,
    E_STATUS_REQUEST_TIMEOUT = 408,
    E_STATUS_CONFLICT = 409,
    E_STATUS_GONE = 410,
    E_STATUS_LENGTH_REQUIRED = 411,
    E_STATUS_PRECONDITION_FAILED = 412,
    E_STATUS_PAYLOAD_TOO_LARGE = 413,
    E_STATUS_URI_TOO_LONG = 414,
    E_STATUS_UNSUPPORTED_MEDIA_TYPE = 415,
    E_STATUS_RANGE_NOT_SATISFIABLE = 416,
    E_STATUS_EXPECTATION_FAILED = 417,
    E_STATUS_IM_A_TEAPOT = 418,
    E_STATUS_MISDIRECTED_REQUEST = 421,
    E_STATUS_UNPROCESSABLE_ENTITY = 422,
    E_STATUS_LOCKED = 423,
    E_STATUS_FAILED_DEPENDENCY = 424,
    E_STATUS_TOO_EARLY = 425,
    E_STATUS_UPGRADE_REQUIRED = 426,
    E_STATUS_PRECONDITION_REQUIRED = 428,
    E_STATUS_TOO_MANY_REQUESTS = 429,
    E_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE = 431,
    E_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS = 451,
    E_STATUS_INTERNAL_SERVER_ERROR = 500,
    E_STATUS_NOT_IMPLEMENTED = 501,
    E_STATUS_BAD_GATEWAY = 502,
    E_STATUS_SERVICE_UNAVAILABLE = 503,
    E_STATUS_GATEWAY_TIMEOUT = 504,
    E_STATUS_HTTP_VERSION_NOT_SUPPORTED = 505,
    E_STATUS_VARIANT_ALSO_NEGOTIATES = 506,
    E_STATUS_INSUFFICIENT_STORAGE = 507,
    E_STATUS_LOOP_DETECTED = 508,
    E_STATUS_NOT_EXTENDED = 510,
    E_STATUS_NETWORK_AUTHENTICATION_REQUIRED = 511,
  };

  const char* http_response_status(EHTTP_ResponseStatusCode status);

  class NETPP_API HTTP_Response {
  public:
    static bool is_http_response(const char* http_buf, uint32_t buflen);
    static HTTP_Response* create(EHTTP_ResponseStatusCode status);
    static HTTP_Response* create(const char* http_buf, int buflen);

    static std::string build(const HTTP_Response& response);

    // Returns a heap allocated buffer that must be freed by the caller
    static const char* build_buf(const HTTP_Response& response, uint32_t* size_out);

    static const char* header_begin(const char* http_buf, int buflen);
    static const char* header_end(const char* http_buf, int buflen);

    static const char* body_begin(const char* http_buf, int buflen);
    static const char* body_end(const char* http_buf, int buflen);

    static uint32_t content_length(const char* http_buf, int buflen);

    EHTTP_ResponseStatusCode status_code() const { return m_status; }
    std::string version() const { return m_version; }
    const std::vector<std::string>& headers() const { return m_headers; }
    std::string body() const { return m_body; }

    void set_version(const std::string& version) { m_version = version; }

    void add_header(const std::string& header);
    void set_body(const std::string& body);

    bool has_header(const std::string& header) const;
    bool has_body() const { return !m_body.empty(); }

  protected:
    HTTP_Response() = default;

  public:
    HTTP_Response(const HTTP_Response&) = delete;
    HTTP_Response& operator=(const HTTP_Response&) = delete;

    HTTP_Response(HTTP_Response&&) = default;
    HTTP_Response& operator=(HTTP_Response&&) = default;

    ~HTTP_Response() = default;

  private:
    EHTTP_ResponseStatusCode m_status = EHTTP_ResponseStatusCode::E_NONE;
    std::string m_version;
    std::vector<std::string> m_headers;
    std::string m_body;
  };

}  // namespace netpp
