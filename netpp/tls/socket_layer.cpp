#include <openssl/evp.h>
#include <openssl/rand.h>

#include "network.h"
#include "socket.h"

namespace netpp {

  bool TLS_SocketProxy::open(const char* hostname, const char* port) {
    return m_pipe->open(hostname, port);
  }

  void TLS_SocketProxy::close() {
    m_pipe->close();
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

    uint32_t crypt_size = iv_size + tag_size + size;
    uint8_t* crypt_data = (uint8_t*)malloc(crypt_size);

    // Initialize the iv descriptor
    RAND_bytes(crypt_data, iv_size);

    // Encryption initialization
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, m_aes_key, crypt_data);

    int _in_size = (int)size;

    // Plaintext encryption
    int out_size;
    EVP_EncryptUpdate(ctx, crypt_data + iv_size + tag_size, &out_size, (uint8_t*)data, size);

    if (crypt_size != out_size + tag_size) {
      return false;
    }

    // Finalize encryption
    EVP_EncryptFinal_ex(ctx, crypt_data + size, &out_size);

    if (out_size != tag_size) {
      return false;
    }

    // Get auth tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_size, crypt_data + iv_size);

    m_pipe->send((const char*)crypt_data, crypt_size, flags);

    EVP_CIPHER_CTX_free(ctx);
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

}  // namespace netpp
