#pragma once

#include <string>
#include <vector>

#include "netpp.h"

namespace netpp {

  enum class EDNS_RequestMethod {
    E_NONE = -1,
    E_REQUEST_GET,
    E_REQUEST_POST,
    E_REQUEST_PUT,
    E_REQUEST_DELETE,
    E_REQUEST_HEAD,
    E_REQUEST_OPTIONS,
    E_REQUEST_TRACE,
    E_REQUEST_CONNECT,
    E_REQUEST_PATCH,
    E_COUNT,
  };

  const char* dns_request_str(EDNS_RequestMethod method);

  class NETPP_API DNS_Request {
  public:
    static bool is_dns_request(const char* dns_buf, uint32_t buflen);
    static DNS_Request* create(EDNS_RequestMethod type);
    static DNS_Request* create(const char* dns_buf, uint32_t buflen);

    static std::string build(const DNS_Request& request);
    // Returns a heap allocated buffer that must be freed by the caller
    static const char *build_buf(const DNS_Request& request, uint32_t* size_out);

    static uint32_t content_length(const char* http_buf, int buflen);

    EDNS_RequestMethod method() const { return m_method; }
    std::string path() const { return m_path; }

    std::string version() const { return m_version; }
    std::string body() const { return m_body; }

    void set_path(const std::string& path) { m_path = path; }
    void set_version(const std::string& version) { m_version = version; }

    void add_header(const std::string& header);
    void add_query(const std::string& query);

    void set_body(const std::string& body);

    bool has_header(const std::string& header) const;
    bool has_body() const { return !m_body.empty(); }

  protected:
    DNS_Request() = default;

  public:
    DNS_Request(const DNS_Request&) = delete;
    DNS_Request& operator=(const DNS_Request&) = delete;

    DNS_Request(DNS_Request&&) = default;
    DNS_Request& operator=(DNS_Request&&) = default;

    ~DNS_Request() = default;

  private:
    EDNS_RequestMethod m_method = EDNS_RequestMethod::E_NONE;
    std::string m_path;
    std::string m_version;
    std::vector<std::string> m_headers;
    std::vector<std::string> m_queries;
    std::string m_body;
  };

} // namespace netpp
