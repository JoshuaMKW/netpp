#include <chrono>
#include <filesystem>

#include <iostream>
#include <string>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "network.h"
#include "security.h"
#include "proxy.h"

using namespace std::chrono_literals;

#ifndef NETPP_SKIP_TLS_CERT_VERIFY
#define NETPP_SKIP_TLS_CERT_VERIFY 0
#endif

#if NETPP_SKIP_TLS_CERT_VERIFY
#define SERVER_VERIFY_CONFIG SSL_VERIFY_NONE
#define CLIENT_VERIFY_CONFIG SSL_VERIFY_NONE
#else
#define SERVER_VERIFY_CONFIG SSL_VERIFY_PEER
#define CLIENT_VERIFY_CONFIG SSL_VERIFY_PEER
#endif

namespace netpp {

  TLS_SocketProxy::TLS_SocketProxy(ISocketPipe* pipe, const ISecurityController* security)
    : m_pipe(pipe), m_handshake_initiated(false), m_handshake_state(EAuthState::E_NONE), m_in_bio(), m_out_bio() {
    std::string key_file = security->key_file().string();
    std::string cert_file = security->cert_file().string();
    std::string ca_file = security->ca_file().string();
    std::string hostname = security->hostname();
    std::string passwd = security->password();

    if (pipe->is_server()) {
      m_tls_ctx = SSL_CTX_new(TLS_server_method());
    }
    else {
      m_tls_ctx = SSL_CTX_new(TLS_client_method());
    }
    m_ssl = nullptr;

    // Optional: Restrict protocol versions
    SSL_CTX_set_min_proto_version(m_tls_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(m_tls_ctx, TLS1_3_VERSION);

    // Set cipher list for TLS 1.2 and below
    if (!SSL_CTX_set_cipher_list(m_tls_ctx, "ECDHE-RSA-AES128-GCM-SHA256")) {
      ERR_print_errors_fp(stderr);
      SSL_CTX_free(m_tls_ctx);
      m_tls_ctx = nullptr;
      return;
    }

    // Set cipher suites for TLS 1.3
    if (!SSL_CTX_set_ciphersuites(m_tls_ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384")) {
      ERR_print_errors_fp(stderr);
      SSL_CTX_free(m_tls_ctx);
      m_tls_ctx = nullptr;
      return;
    }

    if (SSL_CTX_use_certificate_file(m_tls_ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stderr);
      SSL_CTX_free(m_tls_ctx);
      m_tls_ctx = nullptr;
      return;
    }

    if (!passwd.empty()) {
      SSL_CTX_set_default_passwd_cb_userdata(m_tls_ctx, (void*)passwd.c_str());
    }

    if (SSL_CTX_use_PrivateKey_file(m_tls_ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stderr);
      SSL_CTX_free(m_tls_ctx);
      m_tls_ctx = nullptr;
      return;
    }

    if (SSL_CTX_check_private_key(m_tls_ctx) == 0) {
      ERR_print_errors_fp(stderr);
      SSL_CTX_free(m_tls_ctx);
      m_tls_ctx = nullptr;
      return;
    }

    if (pipe->is_server()) {
      SSL_CTX_set_verify(m_tls_ctx, SERVER_VERIFY_CONFIG, NULL);

      if (SSL_CTX_load_verify_locations(m_tls_ctx, cert_file.c_str(), NULL) < 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(m_tls_ctx);
        m_tls_ctx = nullptr;
        return;
      }

      if (auto* ca_list = SSL_load_client_CA_file(ca_file.c_str())) {
        SSL_CTX_set_client_CA_list(m_tls_ctx, ca_list);
      }
    }
    else {
      SSL_CTX_set_verify(m_tls_ctx, CLIENT_VERIFY_CONFIG, NULL);

      // Load the server's certificate as a trusted CA
      if (SSL_CTX_load_verify_locations(m_tls_ctx, cert_file.c_str(), NULL) < 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(m_tls_ctx);
        m_tls_ctx = nullptr;
        return;
      }

      if (auto* ca_list = SSL_load_client_CA_file(ca_file.c_str())) {
        SSL_CTX_set_client_CA_list(m_tls_ctx, ca_list);
      }
    }
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
    BIO_set_nbio(m_in_bio, 1);
    m_out_bio = BIO_new(BIO_s_mem());
    BIO_set_nbio(m_out_bio, 1);

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
    {
      SocketLock l = acquire_lock();
      set_accept_state();
    }

    accept_cb SSL_wrapper_routine = [&](uint64_t socket) -> bool {
      return accept_routine(socket);
      };

    return m_pipe->accept(accept_cond, SSL_wrapper_routine);
  }

  bool TLS_SocketProxy::connect(uint64_t timeout, const NetworkFlowSpec* recv_flowspec, const NetworkFlowSpec* send_flowspec) {
    {
      SocketLock l = acquire_lock();
      set_connect_state();
    }

    bool connected = m_pipe->connect(timeout, recv_flowspec, send_flowspec);
    if (!connected) {
      return false;
    }

    // We call handshake here to make sure
    // the client is what goes first.
    if (proc_pending_auth(EPipeOperation::E_NONE, 0) == EAuthState::E_FAILED) {
      return false;
    }

    while (m_handshake_state != EAuthState::E_AUTHENTICATED) {
      std::this_thread::sleep_for(16ms);
      if (m_handshake_state == EAuthState::E_FAILED) {
        return false;
      }
    }

    return true;
  }

  EIOState TLS_SocketProxy::recv(uint32_t offset, uint32_t* flags, uint32_t* transferred_out) {
    if (m_handshake_state != EAuthState::E_AUTHENTICATED) {
      return EIOState::E_ERROR;
    }
    return m_pipe->recv(offset, flags, transferred_out);
  }

  int32_t TLS_SocketProxy::proc_post_recv(char* out_data, uint32_t out_size, const char* in_data, uint32_t in_size) {
    if (BIO_write(m_in_bio, in_data, in_size) != in_size) {
      return -1;
    }

    // Get the expected TLS Record size...
    uint16_t tls_rec_size;
    *((uint8_t*)(&tls_rec_size) + 0) = in_data[4];
    *((uint8_t*)(&tls_rec_size) + 1) = in_data[3];

    // If this is the case, the TLS Record
    // has not been fully received yet and
    // we should wait for more data...
    if (in_size < tls_rec_size + 5) {
      return 0;
    }

    int bytes = SSL_read(m_ssl, out_data, out_size);
    if (bytes >= 0) {
      return bytes;
    }
    else {
      unsigned long err = ERR_get_error();
      fprintf(stderr, "OpenSSL error: %s\n", ERR_error_string(err, nullptr));
    }

    return -1;
  }

  EIOState TLS_SocketProxy::send(const char* data, uint32_t size, uint32_t* flags) {
    if (m_handshake_state != EAuthState::E_AUTHENTICATED) {
      return EIOState::E_ERROR;
    }

    int processed = SSL_write(m_ssl, data, size);
    if (processed <= 0) {
      unsigned long err = ERR_get_error();
      if (err == 0) {
        fprintf(stderr, "SSL_ERROR_SYSCALL: probably EOF or no I/O attempted.\n");
      }
      else {
        fprintf(stderr, "OpenSSL error: %s\n", ERR_error_string(err, nullptr));
      }
      return EIOState::E_ERROR;
    }

    int written = BIO_ctrl_pending(m_out_bio);
    uint8_t* buffer = new uint8_t[written];

    int bytes = BIO_read(m_out_bio, buffer, written);
    if (bytes > 0) {
      return m_pipe->send((const char*)buffer, bytes, flags);
    }

    return EIOState::E_ERROR;
  }

  EIOState TLS_SocketProxy::send(const HTTP_Request* request) {
    uint32_t request_buf_size = 0;
    const char* request_buf = HTTP_Request::build_buf(*request, &request_buf_size);
    return send(request_buf, request_buf_size, nullptr);
  }

  EIOState TLS_SocketProxy::send(const HTTP_Response* response) {
    uint32_t request_buf_size = 0;
    const char* request_buf = HTTP_Response::build_buf(*response, &request_buf_size);
    return send(request_buf, request_buf_size, nullptr);
  }

  EIOState TLS_SocketProxy::send(const RawPacket* packet) {
    const char* packet_buf = RawPacket::build_buf(*packet);
    return send(packet_buf, packet->length() + 4, nullptr);
  }

  EAuthState TLS_SocketProxy::proc_pending_auth(EPipeOperation last_op, int32_t post_transferred) {
    return ssl_advance_handshake(last_op, post_transferred);
  }

  EAuthState TLS_SocketProxy::ssl_advance_handshake(EPipeOperation last_op, int32_t post_transferred) {
    int result = 0;
    int32_t recv_transferred = last_op == EPipeOperation::E_RECV ? post_transferred : 0;
    int32_t send_transferred = last_op == EPipeOperation::E_SEND ? post_transferred : 0;

    SocketLock l = acquire_lock();

    if (SSL_is_init_finished(m_ssl)) {
      return EAuthState::E_AUTHENTICATED;
    }

    EProcState proc_state = EProcState::E_READY;
    bool wants_recv = false;
    int32_t transferring = 0;

    while (proc_state == EProcState::E_READY) {
    update_handshake:
      result = SSL_do_handshake(m_ssl);
      if (result == 1) {
        // Handshake completed successfully
        if (!is_server()) {
          handshake_send_state(0, &transferring);
        }
        int pending = SSL_pending(m_ssl);
        if (pending > 0) {
          char* buf = new char[pending];
          if (SSL_read(m_ssl, buf, pending) > 0) {
            fprintf(stdout, "%d\n", pending);
          }
        }
        m_handshake_state = EAuthState::E_AUTHENTICATED;
        return EAuthState::E_AUTHENTICATED;
      }

      int err = SSL_get_error(m_ssl, result);
      if (err == SSL_ERROR_WANT_READ) {
        proc_state = handshake_recv_state(recv_transferred);
        handshake_send_state(0, &transferring);
      }
      else if (err == SSL_ERROR_WANT_WRITE) {
        if (is_server()) {
          proc_state = handshake_send_state(send_transferred, &transferring);
          wants_recv = transferring > 0;
        }
        else {
          proc_state = handshake_send_state(send_transferred, &transferring);
          wants_recv = transferring > 0;
        }
      }
      else {
        int ssl_err = SSL_get_error(m_ssl, result);

        if (ssl_err == SSL_ERROR_SYSCALL || ssl_err == SSL_ERROR_SSL) {
          unsigned long err = ERR_get_error();
          if (err == 0) {
            fprintf(stderr, "SSL_ERROR_SYSCALL: probably EOF or no I/O attempted.\n");
          }
          else {
            fprintf(stderr, "OpenSSL error: %s\n", ERR_error_string(err, nullptr));
          }
        }
        m_handshake_state = EAuthState::E_FAILED;
        return EAuthState::E_FAILED;
      }
      m_handshake_initiated = true;
      recv_transferred = 0;
      send_transferred = 0;
      continue;
    }

    m_handshake_state = proc_state == EProcState::E_FAILED
      ? EAuthState::E_FAILED : EAuthState::E_HANDSHAKE;
    return m_handshake_state;
  }

  TLS_SocketProxy::EProcState TLS_SocketProxy::handshake_send_state(int32_t post_transferred, int32_t* out_transferring) {
    uint32_t send_buf_size = get_os_layer()->send_buf_size();
    char* tls_out = new char[send_buf_size];

    int pending = BIO_ctrl_pending(m_out_bio);
    int bytes_to_send = BIO_read(m_out_bio, tls_out, min(pending, send_buf_size));
    if (bytes_to_send > 0) {
      if (is_busy(EPipeOperation::E_SEND)) {
        return EProcState::E_WAITING;
      }

      uint32_t flags_ = 0;
      EIOState state = m_pipe->send(tls_out, bytes_to_send, &flags_);

      if (state == EIOState::E_BUSY || state == EIOState::E_ERROR) {
        *out_transferring = -1;
        return EProcState::E_FAILED;
      }

      *out_transferring = bytes_to_send;
      return EProcState::E_READY;
    }

    delete[] tls_out;

    *out_transferring = 0;
    return EProcState::E_WAITING;
  }

  TLS_SocketProxy::EProcState TLS_SocketProxy::handshake_recv_state(int32_t post_transferred) {
    char* recv_buf = get_os_layer()->recv_buf();

    if (post_transferred != 0) {
      // Push received TLS data into OpenSSL's read BIO
      int written = BIO_write(m_in_bio, recv_buf, post_transferred);
      if (written <= 0) {
        fprintf(stderr, "BIO_write to rbio failed.\n");
        return EProcState::E_FAILED;
      }

      return EProcState::E_READY;
    }

    //if (is_busy(EPipeOperation::E_RECV)) {
    //  return EProcState::E_WAITING;
    //}

    uint32_t tmp_;
    uint32_t flags_ = 0;
    EIOState state = m_pipe->recv(0, &flags_, &tmp_);
    if (state == EIOState::E_ERROR) {
      return EProcState::E_FAILED;
    }
    else {
      return EProcState::E_WAITING;
    }
  }

  bool TLS_SocketProxy::set_accept_state() {
    SSL_set_accept_state(m_ssl);
    return true;
  }

  bool TLS_SocketProxy::set_connect_state() {
    SSL_set_connect_state(m_ssl);
    return true;
  }

}  // namespace netpp
