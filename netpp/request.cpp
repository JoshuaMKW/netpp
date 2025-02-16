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

  HTTP_Request* HTTP_Request::create(const char* http_buf, int buflen) {
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

    for (int i = 0; i < buflen - 3; i++) {
      if (http_buf[i] == 'H' && http_buf[i + 1] == 'T' && http_buf[i + 2] == 'T' && http_buf[i + 3] == 'P') {
        is_http = true;
        break;
      }

      // HTTP tag is always followed by a newline
      if (http_buf[i] == '\n' || http_buf[i + 1] == '\n' || http_buf[i + 2] == '\n' || http_buf[i + 3] == '\n') {
        break;
      }
    }

    if (!is_http) {
      return nullptr;
    }

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
    } else {
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
