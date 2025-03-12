#pragma once

#include <string>

namespace netpp {

  enum class EHTTP_RequestMethod {
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

  const char* http_request_str(EHTTP_RequestMethod method);

  class HTTP_Request {
  public:
    static bool is_http_request(const char* http_buf, uint32_t buflen);
    static HTTP_Request* create(EHTTP_RequestMethod type);
    static HTTP_Request* create(const char* http_buf, uint32_t buflen);

    static std::string build(const HTTP_Request& request);
    // Returns a heap allocated buffer that must be freed by the caller
    static const char *build_buf(const HTTP_Request& request, uint32_t* size_out);

    EHTTP_RequestMethod method() const { return m_method; }
    std::string path() const { return m_path; }
    std::string version() const { return m_version; }
    const std::string* headers() const { return m_headers; }
    int headers_count() const { return m_headers_count; }
    std::string body() const { return m_body; }

    void set_path(const std::string& path) { m_path = path; }
    void set_version(const std::string& version) { m_version = version; }

    void add_header(const std::string& header);
    void add_query(const std::string& query);

    void set_body(const std::string& body);

    bool has_header(const std::string& header) const;
    bool has_body() const { return !m_body.empty(); }

  protected:
    HTTP_Request() = default;

  public:
    HTTP_Request(const HTTP_Request&) = delete;
    HTTP_Request& operator=(const HTTP_Request&) = delete;

    HTTP_Request(HTTP_Request&&) = default;
    HTTP_Request& operator=(HTTP_Request&&) = default;

  private:
    EHTTP_RequestMethod m_method;
    std::string m_path;
    std::string m_version;
    std::string* m_headers;
    int m_headers_count;
    std::string* m_queries;
    int m_queries_count;
    std::string m_body;
  };

} // namespace netpp
