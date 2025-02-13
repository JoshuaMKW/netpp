#include "response.h"
#include <string.h>

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

  return nullptr;
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

  return nullptr;
}

static const char* end_line(const char* str, const char* end) {
  for (int i = 0; (str + i) < end; i++) {
    if (is_newline(str[i])) {
      return str + i;
    }
  }

  return nullptr;
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

  return nullptr;
}

HTTP_Response* HTTP_Response::create(EHTTP_ResponseStatusCode status) {
  HTTP_Response* response = new HTTP_Response();
  response->m_status = status;
  response->m_headers = new std::string [32]();
  response->m_headers_count = 0;
  response->m_body = std::string();
  return response;
}

HTTP_Response* HTTP_Response::create(const char* http_buf, int buflen) {
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

  if (is_whitespace(http_buf[0])) {
    http_buf = next_token(http_buf, end);
  }

  http_buf += 5;  // Skip "HTTP/"

  std::string version = std::string(http_buf, end_token(http_buf, end));
  http_buf = next_token(http_buf, end);

  std::string status_code = std::string(http_buf, end_token(http_buf, end));

  EHTTP_ResponseStatusCode status = (EHTTP_ResponseStatusCode)atoi(status_code.c_str());
  http_buf = next_line(http_buf, end);

  HTTP_Response* response = HTTP_Response::create(status);
  response->set_version(version);

  bool has_body = false;
  bool parsing_body = false;
  int content_length_int = 0;
  
  while (http_buf < end) {
    const char* line_end = end_line(http_buf, end);
    std::string header = std::string(http_buf, line_end);

    if (header.substr(0, 14) == "Content-Length") {
      const char* content_length = http_buf + 16;
      const char* end_content_length = end_token(content_length, line_end);
      if (!end_content_length) {
        delete response;
        return nullptr;
      }

      std::string content_length_str(content_length, end_content_length);
      content_length_int = std::stoi(content_length_str);
      if (content_length_int > 0) {
        has_body = true;
      }
    }


    bool is_body_sep =
      (header[0] == '\n' && header[1] == '\n') ||
      (header[0] == '\r' && header[1] == '\n' && header[2] == '\r' && header[3] == '\n');

    if (is_body_sep) {
      // This is the end of the headers (double newline)
      parsing_body = has_body;
      break;
    }
    else {
      // Continue parsing headers
      response->add_header(header);
    }

    http_buf = next_line(http_buf, end);
  }

  if (parsing_body) {
    const char* body = next_line(http_buf, end);

    std::string body_str(body, end);
    if (content_length_int != body_str.length()) {
      fprintf(stderr, "Content-Length does not match body length\n");
    }

    response->set_body(std::string(body, end));
  }

  return response;
}

void HTTP_Response::add_header(const std::string& header) {
  m_headers[m_headers_count++] = header;
}

void HTTP_Response::set_body(const std::string& body) {
  m_body = body;
}

bool HTTP_Response::has_header(const std::string& header) const {
  for (int i = 0; i < m_headers_count; ++i) {
    if (m_headers[i] == header) {
      return true;
    }
  }
}

const char* http_response_status(EHTTP_ResponseStatusCode status) {
  switch (status) {
  case EHTTP_ResponseStatusCode::E_STATUS_CONTINUE: return "Continue";
  case EHTTP_ResponseStatusCode::E_STATUS_SWITCHING_PROTOCOLS: return "Switching Protocols";
  case EHTTP_ResponseStatusCode::E_STATUS_PROCESSING: return "Processing";
  case EHTTP_ResponseStatusCode::E_STATUS_EARLY_HINTS: return "Early Hints";
  case EHTTP_ResponseStatusCode::E_STATUS_OK: return "OK";
  case EHTTP_ResponseStatusCode::E_STATUS_CREATED: return "Created";
  case EHTTP_ResponseStatusCode::E_STATUS_ACCEPTED: return "Accepted";
  case EHTTP_ResponseStatusCode::E_STATUS_NON_AUTHORITATIVE_INFORMATION: return "Non-Authoritative Information";
  case EHTTP_ResponseStatusCode::E_STATUS_NO_CONTENT: return "No Content";
  case EHTTP_ResponseStatusCode::E_STATUS_RESET_CONTENT: return "Reset Content";
  case EHTTP_ResponseStatusCode::E_STATUS_PARTIAL_CONTENT: return "Partial Content";
  case EHTTP_ResponseStatusCode::E_STATUS_MULTI_STATUS: return "Multi-Status";
  case EHTTP_ResponseStatusCode::E_STATUS_ALREADY_REPORTED: return "Already Reported";
  case EHTTP_ResponseStatusCode::E_STATUS_IM_USED: return "IM Used";
  case EHTTP_ResponseStatusCode::E_STATUS_MULTIPLE_CHOICES: return "Multiple Choices";
  case EHTTP_ResponseStatusCode::E_STATUS_MOVED_PERMANENTLY: return "Moved Permanently";
  case EHTTP_ResponseStatusCode::E_STATUS_FOUND: return "Found";
  case EHTTP_ResponseStatusCode::E_STATUS_SEE_OTHER: return "See Other";
  case EHTTP_ResponseStatusCode::E_STATUS_NOT_MODIFIED: return "Not Modified";
  case EHTTP_ResponseStatusCode::E_STATUS_USE_PROXY: return "Use Proxy";
  case EHTTP_ResponseStatusCode::E_STATUS_TEMPORARY_REDIRECT: return "Temporary Redirect";
  case EHTTP_ResponseStatusCode::E_STATUS_PERMANENT_REDIRECT: return "Permanent Redirect";
  case EHTTP_ResponseStatusCode::E_STATUS_BAD_REQUEST: return "Bad Request";
  case EHTTP_ResponseStatusCode::E_STATUS_UNAUTHORIZED: return "Unauthorized";
  case EHTTP_ResponseStatusCode::E_STATUS_PAYMENT_REQUIRED: return "Payment Required";
  case EHTTP_ResponseStatusCode::E_STATUS_FORBIDDEN: return "Forbidden";
  case EHTTP_ResponseStatusCode::E_STATUS_NOT_FOUND: return "Not Found";
  case EHTTP_ResponseStatusCode::E_STATUS_METHOD_NOT_ALLOWED: return "Method Not Allowed";
  case EHTTP_ResponseStatusCode::E_STATUS_NOT_ACCEPTABLE: return "Not Acceptable";
  case EHTTP_ResponseStatusCode::E_STATUS_PROXY_AUTHENTICATION_REQUIRED: return "Proxy Authentication Required";
  case EHTTP_ResponseStatusCode::E_STATUS_REQUEST_TIMEOUT: return "Request Timeout";
  case EHTTP_ResponseStatusCode::E_STATUS_CONFLICT: return "Conflict";
  case EHTTP_ResponseStatusCode::E_STATUS_GONE: return "Gone";
  case EHTTP_ResponseStatusCode::E_STATUS_LENGTH_REQUIRED: return "Length Required";
  case EHTTP_ResponseStatusCode::E_STATUS_PRECONDITION_FAILED: return "Precondition Failed";
  case EHTTP_ResponseStatusCode::E_STATUS_PAYLOAD_TOO_LARGE: return "Payload Too Large";
  case EHTTP_ResponseStatusCode::E_STATUS_URI_TOO_LONG: return "URI Too Long";
  case EHTTP_ResponseStatusCode::E_STATUS_UNSUPPORTED_MEDIA_TYPE: return "Unsupported Media Type";
  case EHTTP_ResponseStatusCode::E_STATUS_RANGE_NOT_SATISFIABLE: return "Range Not Satisfiable";
  case EHTTP_ResponseStatusCode::E_STATUS_EXPECTATION_FAILED: return "Expectation Failed";
  case EHTTP_ResponseStatusCode::E_STATUS_IM_A_TEAPOT: return "I'm a teapot";
  case EHTTP_ResponseStatusCode::E_STATUS_MISDIRECTED_REQUEST: return "Misdirected Request";
  case EHTTP_ResponseStatusCode::E_STATUS_UNPROCESSABLE_ENTITY: return "Unprocessable Entity";
  case EHTTP_ResponseStatusCode::E_STATUS_LOCKED: return "Locked";
  case EHTTP_ResponseStatusCode::E_STATUS_FAILED_DEPENDENCY: return "Failed Dependency";
  case EHTTP_ResponseStatusCode::E_STATUS_TOO_EARLY: return "Too Early";
  case EHTTP_ResponseStatusCode::E_STATUS_UPGRADE_REQUIRED: return "Upgrade Required";
  case EHTTP_ResponseStatusCode::E_STATUS_PRECONDITION_REQUIRED: return "Precondition Required";
  case EHTTP_ResponseStatusCode::E_STATUS_TOO_MANY_REQUESTS: return "Too Many Requests";
  case EHTTP_ResponseStatusCode::E_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE: return "Request Header Fields Too Large";
  case EHTTP_ResponseStatusCode::E_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS: return "Unavailable For Legal Reasons";
  case EHTTP_ResponseStatusCode::E_STATUS_INTERNAL_SERVER_ERROR: return "Internal Server Error";
  case EHTTP_ResponseStatusCode::E_STATUS_NOT_IMPLEMENTED: return "Not Implemented";
  case EHTTP_ResponseStatusCode::E_STATUS_BAD_GATEWAY: return "Bad Gateway";
  case EHTTP_ResponseStatusCode::E_STATUS_SERVICE_UNAVAILABLE: return "Service Unavailable";
  case EHTTP_ResponseStatusCode::E_STATUS_GATEWAY_TIMEOUT: return "Gateway Timeout";
  case EHTTP_ResponseStatusCode::E_STATUS_HTTP_VERSION_NOT_SUPPORTED: return "HTTP Version Not Supported";
  case EHTTP_ResponseStatusCode::E_STATUS_VARIANT_ALSO_NEGOTIATES: return "Variant Also Negotiates";
  case EHTTP_ResponseStatusCode::E_STATUS_INSUFFICIENT_STORAGE: return "Insufficient Storage";
  case EHTTP_ResponseStatusCode::E_STATUS_LOOP_DETECTED: return "Loop Detected";
  case EHTTP_ResponseStatusCode::E_STATUS_NOT_EXTENDED: return "Not Extended";
  case EHTTP_ResponseStatusCode::E_STATUS_NETWORK_AUTHENTICATION_REQUIRED: return "Network Authentication Required";
  default: return nullptr;
  }
}
