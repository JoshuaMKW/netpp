#include "netpp/protocol.h"
#include "netpp/socket.h"
#include "netpp/http/request.h"
#include "netpp/http/response.h"

#include <limits>

namespace netpp {

  static uint32_t get_chunked_bytes_to_read(const char* data, uint32_t size) {
    // Rationale: Chunked encoding consists of a series of chunks.
    // ---
    // Each chunk starts with a line indicating the chunk size in hexadecimal,
    // followed by that many bytes of data, and ends with a CRLF.
    // The end of the chunked message is indicated by a chunk of size 0.
    // ---
    // To determine how many bytes to read, we need to parse the chunk sizes
    // and sum them up along with the overhead of the chunk size lines and CRLFs.
    // Finally we subtract this total from the overall size to get the bytes to read.
    // ---
    uint32_t total_bytes = 0;
    uint32_t offset = 0;
    while (offset < size) {
      const char* line_end = strstr(data + offset, "\r\n");
      if (!line_end) {
        break; // Incomplete chunk size line
      }
      uint32_t line_length = (uint32_t)(line_end - (data + offset));
      std::string chunk_size_str(data + offset, line_length);
      uint32_t chunk_size = std::stoul(chunk_size_str, nullptr, 16);
      total_bytes += line_length + 2; // Chunk size line + CRLF
      offset += line_length + 2;
      if (chunk_size == 0) {
        total_bytes += 2; // Final CRLF after last chunk
        break; // End of chunks
      }
      total_bytes += chunk_size + 2; // Chunk data + CRLF
      offset += chunk_size + 2;
    }

    return total_bytes;
  }

  bool HTTP_ApplicationAdapter::on_receive(ISocketPipe* pipe, const char* data, uint32_t size, uint32_t flags) {
    if (HTTP_Request::is_http_request(data, size)) {
      HTTP_Request* request = HTTP_Request::create(data, size);
      if (!request) {
        return false;
      }

      const HTTP_Response* response = pipe->signal_http_request(request);
      if (response) {
        pipe->send(response);
        delete response;
      }

      delete request;
      return true;
    }

    if (HTTP_Response::is_http_response(data, size)) {
      HTTP_Response* response = HTTP_Response::create(data, size);
      if (!response) {
        return false;
      }

      const HTTP_Request* request = pipe->signal_http_response(response);
      if (request) {
        pipe->send(request);
        delete request;
      }

      delete response;
      return true;
    }

    return false;
  }

  uint32_t HTTP_ApplicationAdapter::calc_size(const char* data, uint32_t size) const {
    if (const char* h_end = HTTP_Request::header_end(data, size)) {
      uint32_t content_length = HTTP_Request::content_length(data, size);
      return ((uint32_t)(h_end - data) + 4) + content_length;
    }

    if (const char* h_end = HTTP_Response::header_end(data, size)) {
      EHTTP_TransferEncoding transfer_encoding = HTTP_Response::transfer_encoding(data, size);
      switch (transfer_encoding) {
      case EHTTP_TransferEncoding::E_CHUNKED:
        // Cannot determine size with chunked encoding
        return 0;
      case EHTTP_TransferEncoding::E_COMPRESS:
      case EHTTP_TransferEncoding::E_DEFLATE:
      case EHTTP_TransferEncoding::E_GZIP:
        // Cannot determine size with compressed encoding
        return 0;
      default:
        break;
      }

      EHTTP_ContentEncoding content_encoding = HTTP_Response::content_encoding(data, size);
      switch (content_encoding) {
      case EHTTP_ContentEncoding::E_BR:
      case EHTTP_ContentEncoding::E_COMPRESS:
      case EHTTP_ContentEncoding::E_DCB:
      case EHTTP_ContentEncoding::E_DCZ:
      case EHTTP_ContentEncoding::E_GZIP:
      case EHTTP_ContentEncoding::E_ZSTD:
        // Cannot determine size with compressed encoding
        return 0;
      default:
        break;
      }

      uint32_t content_length = HTTP_Response::content_length(data, size);
      if (content_length == std::numeric_limits<uint32_t>::max()) {
        return 0;
      }
      return ((uint32_t)(h_end - data) + 4) + content_length;
    }
    return 0;
  }

  uint32_t HTTP_ApplicationAdapter::calc_proc_size(const char* data, uint32_t size) const {
     uint32_t total_size = calc_size(data, size);
     if (total_size != 0) {
       if (size < total_size) {
         return total_size - size;
       } else {
         return 0;
       }
     }

     if (const char* h_end = HTTP_Response::header_end(data, size)) {
       EHTTP_TransferEncoding transfer_encoding = HTTP_Response::transfer_encoding(data, size);
       switch (transfer_encoding) {
       case EHTTP_TransferEncoding::E_CHUNKED:
       {
         const char* body_start = HTTP_Response::body_begin(data, size);
         if (!body_start) {
           return 1024;
         }
         return (body_start - data) + get_chunked_bytes_to_read(body_start, size) - size;
       }
       case EHTTP_TransferEncoding::E_COMPRESS:
       case EHTTP_TransferEncoding::E_DEFLATE:
       case EHTTP_TransferEncoding::E_GZIP:
         // Cannot determine size with compressed encoding
         return 0;
       default:
         break;
       }

       EHTTP_ContentEncoding content_encoding = HTTP_Response::content_encoding(data, size);
       switch (content_encoding) {
       case EHTTP_ContentEncoding::E_BR:
       case EHTTP_ContentEncoding::E_COMPRESS:
       case EHTTP_ContentEncoding::E_DCB:
       case EHTTP_ContentEncoding::E_DCZ:
       case EHTTP_ContentEncoding::E_GZIP:
       case EHTTP_ContentEncoding::E_ZSTD:
         // Cannot determine size with compressed encoding
         return 0;
       default:
         break;
       }

       uint32_t content_length = HTTP_Response::content_length(data, size);
       if (content_length == std::numeric_limits<uint32_t>::max()) {
         return 0;
       }
       return ((uint32_t)(h_end - data) + 4) + content_length;
     }
     return 0;
  }

  bool HTTP_ApplicationAdapter::wants_more_data(const char* data, uint32_t size) const {
    return calc_proc_size(data, size) > 0;
  }

}