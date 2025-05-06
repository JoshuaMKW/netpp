#include "request.h"
#include <string.h>

namespace netpp {

  static bool is_whitespace(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
  }

  static bool is_newline(char c) {
    return c == '\r' || c == '\n';
  }

  static const char* end_token(const char* str, const char* end, char delimiter = -1) {
    for (int i = 0; (str + i) < end; i++) {
      if (delimiter != -1) {
        if (str[i] == delimiter) {
          return str + i;
        }
      }
      else if (str[i] == ' ' || is_whitespace(str[i])) {
        return str + i;
      }
    }

    return end;
  }

  static const char* next_token(const char* str, const char* end, char delimiter = -1) {
    for (int i = 0; (str + i) < end; i++) {
      if (delimiter != -1) {
        if (str[i] == delimiter) {
          do {
            i++;
          } while (str[i] == delimiter);
          return str + i;
        }
      }
      else if (is_newline(str[i]) || is_whitespace(str[i])) {
        do {
          i++;
        } while (is_newline(str[i]) || is_whitespace(str[i]));
        return str + i;
      }
    }

    return end;
  }

  static const char* end_line(const char* str, const char* end) {
    for (int i = 0; (str + i) < end; i++) {
      if (is_newline(str[i])) {
        return str + i;
      }
    }

    return end;
  }

  static const char* next_line(const char* str, const char* end) {
    for (int i = 0; (str + i) < end; i++) {
      if (is_newline(str[i])) {
        do {
          i++;
        } while (is_newline(str[i]));
        return str + i;
      }
    }

    return end;
  }

  bool HTTP_Request::is_http_request(const char* http_buf, uint32_t buflen) {
    // Check for the HTTP tag
    bool is_http = false;

    // Attempt to trim leading whitespace
    const char* end = http_buf + buflen;
    if (http_buf[0] == ' ' || http_buf[0] == '\t' || http_buf[0] == '\n') {
      const char* ltrim = next_token(http_buf, end);
      if (ltrim) {
        http_buf = ltrim;
      }
    }

    for (uint32_t i = 0; i < buflen - 3; i++) {
      if (http_buf[i] == 'H' && http_buf[i + 1] == 'T' && http_buf[i + 2] == 'T' && http_buf[i + 3] == 'P') {
        is_http = i > 6;
        break;
      }

      // HTTP tag is always followed by a newline
      if (http_buf[i] == '\n') {
        break;
      }
    }

    return is_http;
  }

  HTTP_Request* HTTP_Request::create(EHTTP_RequestMethod type) {
    HTTP_Request* request = new HTTP_Request();
    request->m_method = type;
    request->m_path = "";
    request->m_version = "";
    request->m_headers = new std::string[32]();
    request->m_headers_count = 0;
    request->m_body = "";
    return request;
  }

  HTTP_Request* HTTP_Request::create(const char* http_buf, uint32_t buflen) {
    if (!is_http_request(http_buf, buflen)) {
      return nullptr;
    }

    const char* end = http_buf + buflen;

    EHTTP_RequestMethod method = EHTTP_RequestMethod::E_NONE;
    if (http_buf[0] == 'G' && http_buf[1] == 'E' && http_buf[2] == 'T') {
      method = EHTTP_RequestMethod::E_REQUEST_GET;
    }
    else if (http_buf[0] == 'P' && http_buf[1] == 'O' && http_buf[2] == 'S' && http_buf[3] == 'T') {
      method = EHTTP_RequestMethod::E_REQUEST_POST;
    }
    else if (http_buf[0] == 'P' && http_buf[1] == 'U' && http_buf[2] == 'T') {
      method = EHTTP_RequestMethod::E_REQUEST_PUT;
    }
    else if (http_buf[0] == 'D' && http_buf[1] == 'E' && http_buf[2] == 'L' && http_buf[3] == 'E' && http_buf[4] == 'T' && http_buf[5] == 'E') {
      method = EHTTP_RequestMethod::E_REQUEST_DELETE;
    }
    else if (http_buf[0] == 'H' && http_buf[1] == 'E' && http_buf[2] == 'A' && http_buf[3] == 'D') {
      method = EHTTP_RequestMethod::E_REQUEST_HEAD;
    }
    else if (http_buf[0] == 'O' && http_buf[1] == 'P' && http_buf[2] == 'T' && http_buf[3] == 'I' && http_buf[4] == 'O' && http_buf[5] == 'N' && http_buf[6] == 'S') {
      method = EHTTP_RequestMethod::E_REQUEST_OPTIONS;
    }
    else if (http_buf[0] == 'T' && http_buf[1] == 'R' && http_buf[2] == 'A' && http_buf[3] == 'C' && http_buf[4] == 'E') {
      method = EHTTP_RequestMethod::E_REQUEST_TRACE;
    }
    else if (http_buf[0] == 'C' && http_buf[1] == 'O' && http_buf[2] == 'N' && http_buf[3] == 'N' && http_buf[4] == 'E' && http_buf[5] == 'C' && http_buf[6] == 'T') {
      method = EHTTP_RequestMethod::E_REQUEST_CONNECT;
    }
    else if (http_buf[0] == 'P' && http_buf[1] == 'A' && http_buf[2] == 'T' && http_buf[3] == 'C' && http_buf[4] == 'H') {
      method = EHTTP_RequestMethod::E_REQUEST_PATCH;
    }
    else {
      return nullptr;
    }

    HTTP_Request* request = HTTP_Request::create(method);

    // Parse the path
    const char* path = next_token(http_buf, end);
    const char* end_path = end_token(path, end, '?');
    const char* end_path_query = end_token(path, end);

    bool has_query = end_path < end_path_query;

    // This means we have query parameters
    if (has_query) {
      const char* query = end_path + 1;
      while (true) {
        const char* end_query = end_token(query, end, '&');
        if (!end_query) {
          end_query = end_token(query, end);
          request->add_query(std::string(query, end_query));
          break;
        }
        request->add_query(std::string(query, end_query));
        query = end_query + 1;
      }
      request->set_path(std::string(path, end_path));
    }
    else {
      request->set_path(std::string(path, end_path_query));
    }

    const char* version = next_token(end_path_query, end);
    const char* end_version = end_token(version, end);

    // Crop the HTTP/ part of the version tag
    request->set_version(std::string(version + 5, end_version));

    bool parsing_body = false;
    bool can_parse_body = false;
    int content_length_int = 0;

    // Parse the headers
    const char* header = next_line(end_version, end);
    while (header < end) {
      const char* end_header = end_line(header, end);
      if (!end_header) {
        break;
      }

      std::string header_str(header, end_header);
      if (header_str.substr(0, 14) == "Content-Length") {
        const char* content_length = header + 16;
        const char* end_content_length = end_token(content_length, end_header);
        if (!end_content_length) {
          delete request;
          return nullptr;
        }

        std::string content_length_str(content_length, end_content_length);
        content_length_int = std::stoi(content_length_str);
        if (content_length_int > 0) {
          can_parse_body = true;
        }
      }

      bool is_body_sep =
        (header_str[0] == '\n' && header_str[1] == '\n') ||
        (header_str[0] == '\r' && header_str[1] == '\n' && header_str[2] == '\r' && header_str[3] == '\n');

      if (is_body_sep) {
        // This is the end of the headers (double newline)
        parsing_body = can_parse_body;
        break;
      }
      else if (!header_str.empty()) {
        // Continue parsing headers
        request->add_header(header_str);
      }

      header = next_line(end_header, end);
    }

    if (parsing_body) {
      const char* body = next_line(header, end);

      std::string body_str(body, end);
      if (content_length_int != body_str.length()) {
        fprintf(stderr, "Content-Length does not match body length\n");
      }

      request->set_body(std::string(body, end));
    }

    return request;
  }

  const char* HTTP_Request::header_begin(const char* http_buf, int buflen) {
    const char* end = http_buf + buflen;

    if (is_whitespace(http_buf[0])) {
      http_buf = next_token(http_buf, end);
    }

    if (!is_http_request(http_buf, buflen)) {
      return nullptr;
    }

    http_buf += 13;  // Skip "HTTP/X.Y ZZZ "
    for (int i = 0; i < buflen - 1; i++) {
      if (http_buf[i] == '\r' && http_buf[i + 1] == '\n') {
        return &http_buf[i + 2];
      }
    }

    return nullptr;
  }

  const char* HTTP_Request::header_end(const char* http_buf, int buflen) {
    const char* begin = header_begin(http_buf, buflen);
    const char* end = http_buf + buflen;

    if (!begin) {
      return nullptr;
    }

    if (begin[0] == '\r' && begin[1] == '\n') {
      return nullptr;
    }

    return strstr(begin, "\r\n\r\n");
  }


  const char* HTTP_Request::body_begin(const char* http_buf, int buflen) {
    const char* h_end = header_end(http_buf, buflen);
    if (!h_end) {
      return nullptr;
    }

    const char* end = http_buf + buflen;
    const char* b_begin = h_end + 4;

    if (b_begin >= end) {
      return nullptr;
    }

    return b_begin;
  }

  const char* HTTP_Request::body_end(const char* http_buf, int buflen) {
    if (!body_begin(http_buf, buflen)) {
      return nullptr;
    }
    return http_buf + buflen;
  }

  uint32_t HTTP_Request::content_length(const char* http_buf, int buflen) {
    const char* content_len_header = strstr(http_buf, "Content-Length: ");
    if (!content_len_header) {
      return 0;
    }

    uint32_t content_len = std::stoi(content_len_header + 16);
    return content_len;
  }

  void HTTP_Request::add_header(const std::string& header) {
    m_headers[m_headers_count++] = header;
  }

  void HTTP_Request::set_body(const std::string& body) {
    m_body = body;
  }

  void HTTP_Request::add_query(const std::string& query) {
    m_queries[m_queries_count++] = query;
  }

  bool HTTP_Request::has_header(const std::string& header) const {
    for (int i = 0; i < m_headers_count; ++i) {
      if (m_headers[i] == header) {
        return true;
      }
    }
    return false;
  }

  std::string HTTP_Request::build(const HTTP_Request& request) {
    std::string request_str = http_request_str(request.method());
    request_str += " " + request.path() + " HTTP/" + request.version() + "\r\n";

    const std::string* headers = request.headers();
    for (int i = 0; i < request.headers_count(); i++) {
      request_str += headers[i] + "\r\n";
    }

    if (request.has_body()) {
      std::string body = request.body();
      request_str += "Content-Length: " + std::to_string(body.length()) + "\r\n";
      request_str += "\r\n";
      request_str += body;
    }

    return request_str;
  }

  const char* HTTP_Request::build_buf(const HTTP_Request& request, uint32_t *size_out) {
    size_t offset = 0;

    //--------------------------------------------------------------
    // Calculate the size of the buffer
    size_t http_size = 9;  // 2 spaces, 1 carriage return, 1 newline, HTTP/
    const char* request_str = http_request_str(request.method());

    http_size += strlen(request_str);
    http_size += request.path().length();
    http_size += request.version().length() + 5;

    const std::string* headers = request.headers();
    for (int i = 0; i < request.headers_count(); i++) {
      http_size += headers[i].length() + 2;  // 1 carriage return, 1 newline
    }

    if (request.has_body()) {
      std::string body = request.body();

      size_t body_len = body.length();

      // Calclulate the number of digits in the body length
      while (body_len > 0) {
        body_len /= 10;
        http_size++;
      }

      http_size += 18;  // Content-Length: \r\n
      http_size += body.length() + 2;
    }
    //--------------------------------------------------------------

    char* buf_out = new char[http_size];
    
    //--------------------------------------------------------------
    // Method
    size_t request_len = strlen(request_str);
    memcpy(buf_out + offset, request_str, request_len);
    offset += request_len;

    buf_out[offset++] = ' ';

    size_t path_len = request.path().length();
    memcpy(buf_out + offset, request.path().c_str(), path_len);
    offset += path_len;

    buf_out[offset++] = ' ';

    memcpy(buf_out + offset, "HTTP/", 5);
    offset += 5;

    size_t version_len = request.version().length();
    memcpy(buf_out + offset, request.version().c_str(), version_len);
    offset += version_len;

    *(uint16_t*)((uint8_t*)buf_out + offset) = '\r\n';
    offset += 2;
    //--------------------------------------------------------------

    //--------------------------------------------------------------
    // Headers
    for (int i = 0; i < request.headers_count(); i++) {
      size_t header_len = headers[i].length();
      memcpy(buf_out + offset, headers[i].c_str(), header_len);
      offset += header_len;
      *(uint16_t*)((uint8_t*)buf_out + offset) = '\r\n';
      offset += 2;
    }
    //--------------------------------------------------------------

    //--------------------------------------------------------------
    // End of headers
    *(uint16_t*)((uint8_t*)buf_out + offset) = '\r\n';
    offset += 2;
    //--------------------------------------------------------------

    //--------------------------------------------------------------
    // Body
    if (request.has_body()) {
      std::string body = request.body();
      size_t body_len = body.length();
      memcpy(buf_out + offset, body.c_str(), body_len);
      offset += body_len;
      *(uint16_t*)((uint8_t*)buf_out + offset) = '\r\n';
      offset += 2;
    }

    *(uint16_t*)((uint8_t*)buf_out + offset) = '\r\n';
    offset += 2;
    //--------------------------------------------------------------

    *size_out = static_cast<uint32_t>(http_size);
    return buf_out;
  }

  const char* http_request_str(EHTTP_RequestMethod method) {
    switch (method) {
    case EHTTP_RequestMethod::E_REQUEST_GET:
      return "GET";
    case EHTTP_RequestMethod::E_REQUEST_POST:
      return "POST";
    case EHTTP_RequestMethod::E_REQUEST_PUT:
      return "PUT";
    case EHTTP_RequestMethod::E_REQUEST_DELETE:
      return "DELETE";
    case EHTTP_RequestMethod::E_REQUEST_HEAD:
      return "HEAD";
    case EHTTP_RequestMethod::E_REQUEST_OPTIONS:
      return "OPTIONS";
    case EHTTP_RequestMethod::E_REQUEST_TRACE:
      return "TRACE";
    case EHTTP_RequestMethod::E_REQUEST_CONNECT:
      return "CONNECT";
    case EHTTP_RequestMethod::E_REQUEST_PATCH:
      return "PATCH";
    default:
      return "NONE";
    }
  }

} // namespace netpp
