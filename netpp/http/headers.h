#pragma once

namespace netpp {

  // https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Encoding
  enum class EHTTP_ContentEncoding {
    E_NONE,
    E_BR,
    E_COMPRESS,
    E_DCB,
    E_DCZ,
    E_GZIP,
    E_ZSTD,
  };

  // https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Transfer-Encoding
  enum class EHTTP_TransferEncoding {
    E_NONE,
    E_CHUNKED,
    E_COMPRESS,
    E_DEFLATE,
    E_GZIP,
  };

  EHTTP_ContentEncoding http_content_encoding_from_str(const char* str);
  EHTTP_TransferEncoding http_transfer_encoding_from_str(const char* str);
  const char* http_content_encoding_to_str(EHTTP_ContentEncoding encoding);
  const char* http_transfer_encoding_to_str(EHTTP_TransferEncoding encoding);

}