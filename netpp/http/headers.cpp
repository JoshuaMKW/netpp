#include "netpp/http/headers.h"

#include <string>
#include <unordered_map>

namespace netpp {

  EHTTP_ContentEncoding http_content_encoding_from_str(const char* str) {
    struct EncodingMapping {
      const char* name;
      EHTTP_ContentEncoding encoding;
    };

    EncodingMapping encodings[] = {
      { "br", EHTTP_ContentEncoding::E_BR },
      { "compress", EHTTP_ContentEncoding::E_COMPRESS },
      { "dcb", EHTTP_ContentEncoding::E_DCB },
      { "dcz", EHTTP_ContentEncoding::E_DCZ },
      { "gzip", EHTTP_ContentEncoding::E_GZIP },
      { "zstd", EHTTP_ContentEncoding::E_ZSTD },
    };

    if (strncmp(str, "x-gzip", 6) == 0) {
      return EHTTP_ContentEncoding::E_GZIP;
    }

    for (const auto& encoding : encodings) {
      if (strncmp(str, encoding.name, 9) == 0) {
        return encoding.encoding;
      }
    }

    return EHTTP_ContentEncoding::E_NONE;
  }

  EHTTP_TransferEncoding http_transfer_encoding_from_str(const char* str) {
    struct EncodingMapping {
      const char* name;
      EHTTP_TransferEncoding encoding;
    };

    EncodingMapping encodings[] = {
      { "chunked", EHTTP_TransferEncoding::E_CHUNKED },
      { "compress", EHTTP_TransferEncoding::E_COMPRESS },
      { "deflate", EHTTP_TransferEncoding::E_DEFLATE },
      { "gzip", EHTTP_TransferEncoding::E_GZIP },
    };

    if (strncmp(str, "x-gzip", 6) == 0) {
      return EHTTP_TransferEncoding::E_GZIP;
    }

    for (const auto& encoding : encodings) {
      if (strncmp(str, encoding.name, 9) == 0) {
        return encoding.encoding;
      }
    }

    return EHTTP_TransferEncoding::E_NONE;
  }

  const char* http_content_encoding_to_str(EHTTP_ContentEncoding encoding) {
    struct EncodingMapping {
      const char* name;
      EHTTP_ContentEncoding encoding;
    };

    EncodingMapping encodings[] = {
      { "br", EHTTP_ContentEncoding::E_BR },
      { "compress", EHTTP_ContentEncoding::E_COMPRESS },
      { "dcb", EHTTP_ContentEncoding::E_DCB },
      { "dcz", EHTTP_ContentEncoding::E_DCZ },
      { "gzip", EHTTP_ContentEncoding::E_GZIP },
      { "zstd", EHTTP_ContentEncoding::E_ZSTD },
    };

    for (const auto& enc : encodings) {
      if (encoding == enc.encoding) {
        return enc.name;
      }
    }

    return nullptr;
  }

  const char* http_transfer_encoding_to_str(EHTTP_TransferEncoding encoding) {
    struct EncodingMapping {
      const char* name;
      EHTTP_TransferEncoding encoding;
    };

    EncodingMapping encodings[] = {
      { "chunked", EHTTP_TransferEncoding::E_CHUNKED },
      { "compress", EHTTP_TransferEncoding::E_COMPRESS },
      { "deflate", EHTTP_TransferEncoding::E_DEFLATE },
      { "gzip", EHTTP_TransferEncoding::E_GZIP },
    };

    for (const auto& enc : encodings) {
      if (encoding == enc.encoding) {
        return enc.name;
      }
    }

    return nullptr;
  }

  bool http_get_hostname_and_path_from_str(const char* str, char* hostname, uint32_t hostname_maxlen, char* path, uint32_t path_maxlen) {
    uint32_t src_len = (uint32_t)strnlen_s(str, 256);

    const char* host_start = strstr(str, "://");
    if (host_start == nullptr) {
      const char* location_start = strchr(str, '/');
      if (location_start != str) {  // Expected to be / at start
        return false;
      }
      strncpy_s(path, path_maxlen, str, src_len);
      return true;
    }

    host_start += 3;

    const char* location_start = strchr(host_start, '/');
    if (!location_start) {
      strncpy_s(path, path_maxlen, "/", 1);
    }
    else {
      strncpy_s(path, path_maxlen, location_start, src_len - (location_start - str));
    }

    strncpy_s(hostname, hostname_maxlen, host_start, location_start - host_start);
    return true;
  }

}