#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "network.h"
#include "socket.h"

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

    SSL_set_fd(m_ssl, (int)m_pipe->socket());
    SSL_set_blocking_mode(m_ssl, true);

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

    SSL_set_fd(m_ssl, (int)m_pipe->socket());

    return true;
  }

  void TLS_SocketProxy::close() {
    m_pipe->close();

    SSL_free(m_ssl);
    m_ssl = nullptr;
  }

  bool TLS_SocketProxy::accept(accept_cond_cb accept_cond, accept_cb accept_routine) {
    SSL_set_accept_state(m_ssl);

    bool connected = m_pipe->accept(accept_cond, accept_routine);
    if (!connected) {
      return false;
    }

    if (SSL_do_handshake(m_ssl) != 1) {
      return false;
    }

    return true;
  }

  bool TLS_SocketProxy::connect(uint64_t timeout, const NetworkFlowSpec* recv_flowspec, const NetworkFlowSpec* send_flowspec) {
    SSL_set_connect_state(m_ssl);

    bool connected = m_pipe->connect(timeout, recv_flowspec, send_flowspec);
    if (!connected) {
      return false;
    }

    if (SSL_do_handshake(m_ssl) != 1) {
      return false;
    }

    return true;
  }

  bool TLS_SocketProxy::ping()
  {
      return false;
  }

  bool TLS_SocketProxy::recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) {
    return m_pipe->recv(offset, flags, transferred_out);
  }

  bool TLS_SocketProxy::proc_post_recv(char* out_data, uint32_t out_size, const char* in_data, uint32_t in_size) {
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
  }

  // Application surrenders ownership of the buffer
  bool TLS_SocketProxy::send(const char* data, uint32_t size, uint32_t* flags) {
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

}  // namespace netpp
