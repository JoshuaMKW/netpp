#include <chrono>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "network.h"
#include "socket.h"

using namespace std::chrono_literals;

namespace netpp {

  TLS_SocketProxy::TLS_SocketProxy(ISocketPipe* pipe, uint8_t* aes_key) : m_pipe(pipe) {
    if (aes_key) {
      memmove(m_aes_key, aes_key, key_size);
    }

    m_tls_ctx = SSL_CTX_new(TLS_method());
    m_ssl = nullptr;
  }

  bool TLS_SocketProxy::open(const char* hostname, const char* port) {
    bool result = m_pipe->open(hostname, port);
    if (!result) {
      return false;
    }

    m_ssl = SSL_new(m_tls_ctx);
    if (!m_ssl) {
      return false;
    }

    m_in_bio = BIO_new(BIO_s_mem());
    m_out_bio = BIO_new(BIO_s_mem());
    SSL_set_bio(m_ssl, m_in_bio, m_out_bio);

    return true;
  }

  bool TLS_SocketProxy::open(uint64_t socket) {
    bool result = m_pipe->open(socket);
    if (!result) {
      return false;
    }

    m_ssl = SSL_new(m_tls_ctx);
    if (!m_ssl) {
      return false;
    }

    m_in_bio = BIO_new(BIO_s_mem());
    m_out_bio = BIO_new(BIO_s_mem());
    SSL_set_bio(m_ssl, m_in_bio, m_out_bio);

    return true;
  }

  void TLS_SocketProxy::close() {
    m_pipe->close();

    SSL_free(m_ssl);
    m_ssl = nullptr;
  }

  bool TLS_SocketProxy::accept(accept_cond_cb accept_cond, accept_cb accept_routine) {
    accept_cb SSL_wrapper_routine = [&](uint64_t socket) -> bool {
      SSL_set_accept_state(m_ssl);

      std::this_thread::sleep_for(100ms);

      if (!SSL_handshake_routine()) {
        return false;
      }

      return accept_routine(socket);
      };

    return m_pipe->accept(accept_cond, SSL_wrapper_routine);
  }

  bool TLS_SocketProxy::connect(uint64_t timeout, const NetworkFlowSpec* recv_flowspec, const NetworkFlowSpec* send_flowspec) {
    bool connected = m_pipe->connect(timeout, recv_flowspec, send_flowspec);
    if (!connected) {
      return false;
    }

    SSL_set_connect_state(m_ssl);
    return SSL_handshake_routine();
  }

  bool TLS_SocketProxy::ping()
  {
    return false;
  }

  bool TLS_SocketProxy::recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) {
    return m_pipe->recv(offset, flags, transferred_out);
  }

  bool TLS_SocketProxy::proc_post_recv(char* out_data, uint32_t out_size, const char* in_data, uint32_t in_size) {
#if 0
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    uint8_t* tag = (uint8_t*)(in_data + iv_size);
    uint8_t* iv = (uint8_t*)in_data;

    // Initialize decryption
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, tag, iv);

    uint32_t offset = iv_size + tag_size;

    if (in_size <= offset) {
      return false;
    }

    // Cyphertext decryption
    int _in_s = (int)in_size;
    int _out_s;
    EVP_DecryptUpdate(ctx, (uint8_t*)out_data, &_out_s, (uint8_t*)(in_data + offset), in_size - offset);

    // Set the expected auth tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_size, tag);

    int ret = EVP_DecryptFinal_ex(ctx, (uint8_t*)(out_data + _out_s), &_out_s);

    EVP_CIPHER_CTX_free(ctx);

    return ret > 0;
#else
    if (BIO_write(m_in_bio, in_data, in_size) != in_size) {
      return false;
    }

    int bytes = SSL_read(m_ssl, out_data, out_size);
    if (bytes > 0) {
      out_data[bytes] = 0;
      return true;
    }
#endif
  }

  // Application surrenders ownership of the buffer
  bool TLS_SocketProxy::send(const char* data, uint32_t size, uint32_t* flags) {
#if 0
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    uint32_t crypt_size = record_size + iv_size + tag_size + size;
    uint8_t* crypt_data = new uint8_t[crypt_size];
    if (!crypt_data) {
      return false;
    }

    uint8_t* record_ptr = crypt_data;
    uint8_t* iv_ptr = crypt_data + record_size;
    uint8_t* tag_ptr = crypt_data + record_size + iv_size;
    uint8_t* data_ptr = crypt_data + record_size + iv_size + tag_size;

    // Initialize the iv descriptor
    RAND_bytes(iv_ptr, iv_size);

    // Encryption initialization
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, m_aes_key, iv_ptr);

    int _in_size = (int)size;

    // Plaintext encryption
    int out_size;
    EVP_EncryptUpdate(ctx, data_ptr, &out_size, (uint8_t*)data, size);

    if (crypt_size != out_size + tag_size) {
      return false;
    }

    // Get auth tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_size, tag_ptr);

    EVP_CIPHER_CTX_free(ctx);

    record_ptr[0] = 0x17;  // Content Type: Application Data
    record_ptr[1] = 0x03;  // TLS Version (Major)
    record_ptr[2] = 0x03;  // TLS Version (Minor) - TLS 1.2
    record_ptr[3] = ((crypt_size - record_size) >> 8) & 0xFF;  // Length (High Byte)
    record_ptr[4] = (crypt_size - record_size) & 0xFF;  // Length (Low Byte)

    m_pipe->send((const char*)crypt_data, crypt_size, flags);
    return true;
#else
    SSL_write(m_ssl, data, size);

    uint32_t crypt_size = record_size + iv_size + tag_size + size;
    uint8_t* buffer = new uint8_t[crypt_size];
    int bytes = BIO_read(m_out_bio, buffer, crypt_size);
    if (bytes > 0) {
      return m_pipe->send((const char*)buffer, bytes, flags);
    }

    return false;
#endif
  }

  bool TLS_SocketProxy::send(const HTTP_Request* request) {
    uint32_t request_buf_size = 0;
    const char* request_buf = HTTP_Request::build_buf(*request, &request_buf_size);
    return send(request_buf, request_buf_size, NULL) != 0;
  }

  bool TLS_SocketProxy::send(const HTTP_Response* response) {
    uint32_t request_buf_size = 0;
    const char* request_buf = HTTP_Response::build_buf(*response, &request_buf_size);
    return send(request_buf, request_buf_size, NULL) != 0;
  }

  bool TLS_SocketProxy::send(const RawPacket* packet) {
    return send(packet->message(), packet->length(), nullptr);
  }

  bool TLS_SocketProxy::proc_pending_auth()
  {
      return false;
  }

  bool TLS_SocketProxy::recv_client_hello()
  {
    return false;
  }

  bool TLS_SocketProxy::recv_server_hello()
  {
    return false;
  }

  bool TLS_SocketProxy::send_client_hello() {
    return false;
  }

  bool TLS_SocketProxy::send_server_hello()
  {
    return false;
  }

  bool TLS_SocketProxy::send_server_certificate()
  {
    return false;
  }

  bool TLS_SocketProxy::send_client_key_exchange()
  {
    return false;
  }

  bool TLS_SocketProxy::recv_change_cipher_spec()
  {
    return false;
  }

  bool TLS_SocketProxy::send_change_cipher_spec()
  {
    return false;
  }

  bool TLS_SocketProxy::send_finished()
  {
    return false;
  }

  bool TLS_SocketProxy::recv_finished()
  {
    return false;
  }

  bool TLS_SocketProxy::SSL_handshake_routine() {
    int result;

    bool initiated = false;

    while ((result = SSL_do_handshake(m_ssl)) != 1) {
      int err = SSL_get_error(m_ssl, result);
      if (err == SSL_ERROR_WANT_READ) {
        if (!initiated) {
          if (!is_server()) {
            goto send_ctrl;
          }
          else {
            goto recv_ctrl;
          }
        }

      recv_ctrl:
        uint32_t recv_buf_size = get_os_layer()->recv_buf_size();
        char* socket_buffer = new char[recv_buf_size];

        uint32_t tmp_;
        if (!m_pipe->recv(0, nullptr, &tmp_)) {
          return false;
        }

        int64_t transferred = m_pipe->sync(EPipeOperation::E_RECV);
        if (transferred <= 0) {
          fprintf(stderr, "Socket recv failed or connection closed during handshake.\n");
          return false;
        }

        // Push received TLS data into OpenSSL's read BIO
        int written = BIO_write(m_in_bio, socket_buffer, transferred);
        if (written <= 0) {
          fprintf(stderr, "BIO_write to rbio failed.\n");
          return false;
        }
      }
      else if (err == SSL_ERROR_WANT_WRITE) {
      send_ctrl:
        uint32_t send_buf_size = get_os_layer()->send_buf_size();
        char* tls_out = new char[send_buf_size];
        int pending = BIO_ctrl_pending(m_out_bio);
        while (pending > 0) {
          int bytes_to_send = BIO_read(m_out_bio, tls_out, min(pending, send_buf_size));
          if (bytes_to_send > 0) {
            if (!m_pipe->send(tls_out, bytes_to_send, nullptr)) {
              return false;
            }

            int64_t sent = m_pipe->sync(EPipeOperation::E_SEND);
            if (sent <= 0) {
              fprintf(stderr, "Socket send failed during handshake.\n");
              return false;
            }
          }
          else {
            fprintf(stderr, "BIO_read from wbio failed.\n");
            return false;
          }
          pending = BIO_ctrl_pending(m_out_bio);
        }
      }
      else {
        int ssl_err = SSL_get_error(m_ssl, result);

        if (ssl_err == SSL_ERROR_SYSCALL) {
          unsigned long err = ERR_get_error();
          if (err == 0) {
            fprintf(stderr, "SSL_ERROR_SYSCALL: probably EOF or no I/O attempted.\n");
          }
          else {
            fprintf(stderr, "OpenSSL error: %s\n", ERR_error_string(err, nullptr));
          }
        }
        return false;
      }
    }

    return true;
  }

}  // namespace netpp


/*

        char buffer[4096];
        int bytes = (uint32_t)BIO_read(m_out_bio, buffer, sizeof(buffer));
        if (bytes > 0) {
          if (!m_pipe->send(buffer, bytes, nullptr)) {
            return false;
          }
        }

        uint32_t recv_bytes;
        if (!m_pipe->recv(0, nullptr, &recv_bytes)) {
          return false;
        }

        // Wait for the data to arrive
        m_pipe->sync();

        BIO_write(m_in_bio, buffer, recv_bytes);*/