#include <filesystem>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "netpp/tls/security.h"

namespace netpp {

  TLSSecurityController::TLSSecurityController(const TLSSecurityFactory* factory)
    : m_factory(factory), m_initialized(false), m_ssl(), m_in_bio(), m_out_bio(), m_tls_ctx(), m_digested_by_crypt() {
  }

  bool TLSSecurityController::is_authenticated() const { return m_handshake_state == EAuthState::E_AUTHENTICATED; }
  bool TLSSecurityController::is_failed() const { return m_handshake_state == EAuthState::E_FAILED; }

  int TLSSecurityController::protocol() const { return (int)ESecurityProtocol::E_TLS; }

  ETransportProtocolFlags TLSSecurityController::supported_transports() const
  {
    return ETransportProtocolFlags::E_TCP;
  }

  const std::filesystem::path& TLSSecurityController::key_file() const { return m_factory->key_file(); }
  const std::filesystem::path& TLSSecurityController::cert_file() const { return m_factory->cert_file(); }
  const std::filesystem::path& TLSSecurityController::ca_file() const { return m_factory->ca_file(); }

  const std::string& TLSSecurityController::hostname() const { return m_factory->hostname(); }
  const std::string& TLSSecurityController::password() const { return m_factory->password(); }

  bool TLSSecurityController::initialize()
  {
    if (m_initialized) {
      return true;
    }

    std::string key_file = this->key_file().string();
    std::string cert_file = this->cert_file().string();
    std::string ca_file = this->ca_file().string();
    std::string hostname = this->hostname();
    std::string passwd = this->password();

    if (m_factory->is_server()) {
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
    if (!SSL_CTX_set_cipher_list(m_tls_ctx, "HIGH:!aNULL:!MD5")) {
      ERR_print_errors_fp(stderr);
      SSL_CTX_free(m_tls_ctx);
      m_tls_ctx = nullptr;
      return false;
    }

    // Set cipher suites for TLS 1.3
    if (!SSL_CTX_set_ciphersuites(m_tls_ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384")) {
      ERR_print_errors_fp(stderr);
      SSL_CTX_free(m_tls_ctx);
      m_tls_ctx = nullptr;
      return false;
    }

    if (!cert_file.empty()) {
      if (SSL_CTX_use_certificate_file(m_tls_ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(m_tls_ctx);
        m_tls_ctx = nullptr;
        return false;
      }
    }

    if (!passwd.empty()) {
      SSL_CTX_set_default_passwd_cb_userdata(m_tls_ctx, (void*)passwd.c_str());
    }

    if (!cert_file.empty()) {
      if (SSL_CTX_use_PrivateKey_file(m_tls_ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(m_tls_ctx);
        m_tls_ctx = nullptr;
        return false;
      }

      if (SSL_CTX_check_private_key(m_tls_ctx) == 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(m_tls_ctx);
        m_tls_ctx = nullptr;
        return false;
      }
    }

    if (m_factory->is_server()) {
      SSL_CTX_set_verify(m_tls_ctx, (int)m_factory->verify_flags(), NULL);

      if (!ca_file.empty()) {
        if (SSL_CTX_load_verify_locations(m_tls_ctx, ca_file.c_str(), NULL) < 1) {
          ERR_print_errors_fp(stderr);
          SSL_CTX_free(m_tls_ctx);
          m_tls_ctx = nullptr;
          return false;
        }
      }
      else {
        if (!load_system_cacerts(m_tls_ctx)) {
          ERR_print_errors_fp(stderr);
          SSL_CTX_free(m_tls_ctx);
          m_tls_ctx = nullptr;
          return false;
        }
      }
    }
    else {
      SSL_CTX_set_verify(m_tls_ctx, (int)m_factory->verify_flags(), NULL);

      // Load the server's certificate as a trusted CA
      if (!cert_file.empty()) {
        if (SSL_CTX_load_verify_locations(m_tls_ctx, cert_file.c_str(), NULL) < 1) {
          ERR_print_errors_fp(stderr);
          SSL_CTX_free(m_tls_ctx);
          m_tls_ctx = nullptr;
          return false;
        }
      }
      else {
        if (!load_system_cacerts(m_tls_ctx)) {
          ERR_print_errors_fp(stderr);
          SSL_CTX_free(m_tls_ctx);
          m_tls_ctx = nullptr;
          return false;
        }
      }

      if (auto* ca_list = SSL_load_client_CA_file(ca_file.c_str())) {
        SSL_CTX_set_client_CA_list(m_tls_ctx, ca_list);
      }
    }

    m_ssl = SSL_new(m_tls_ctx);
    if (!m_ssl) {
      ERR_print_errors_fp(stderr);
      SSL_CTX_free(m_tls_ctx);
      m_tls_ctx = nullptr;
      return false;
    }

    if (!hostname.empty()) {
      SSL_set_tlsext_host_name(m_ssl, hostname.c_str());
    }

    m_in_bio = BIO_new(BIO_s_mem());
    BIO_set_nbio(m_in_bio, 1);
    m_out_bio = BIO_new(BIO_s_mem());
    BIO_set_nbio(m_out_bio, 1);

    SSL_set_bio(m_ssl, m_in_bio, m_out_bio);

    // Set the memory BIO to NOT automatically retry, so we handle logic manually
    BIO_set_mem_eof_return(m_in_bio, -1);

    m_initialized = true;
    m_handshake_state = EAuthState::E_NONE;
    return true;
  }

  void TLSSecurityController::deinitialize()
  {
    if (!m_initialized) {
      return;
    }

    SSL_CTX_free(m_tls_ctx);
    m_tls_ctx = nullptr;

    SSL_free(m_ssl);
    m_ssl = nullptr;

    m_initialized = false;
    m_handshake_state = EAuthState::E_NONE;
  }

  bool TLSSecurityController::set_accept_state()
  {
    if (!m_initialized) {
      return false;
    }

    SSL_set_accept_state(m_ssl);
    return true;
  }

  bool TLSSecurityController::set_connect_state()
  {
    if (!m_initialized) {
      return false;
    }

    SSL_set_connect_state(m_ssl);
    return true;
  }

  EAuthState TLSSecurityController::advance_handshake(ISocketPipe* pipe, EPipeOperation last_op, int32_t post_transferred)
  {
    int result = 0;
    int32_t recv_transferred = last_op == EPipeOperation::E_RECV ? post_transferred : 0;
    int32_t send_transferred = last_op == EPipeOperation::E_SEND ? post_transferred : 0;

    EProcState proc_state = EProcState::E_READY;
    bool wants_recv = false;
    int32_t transferring = 0;

    SocketLock l = pipe->acquire_lock();

    if (last_op == EPipeOperation::E_RECV && post_transferred > 0) {
      char* recv_buf = pipe->get_os_layer()->recv_buf();
      int written = BIO_write(m_in_bio, recv_buf, post_transferred);
      if (written <= 0) {
        // Handle Fatal Error
        return EAuthState::E_FAILED;
      }
    }

    while (proc_state == EProcState::E_READY) {
      result = SSL_do_handshake(m_ssl);
      if (result == 1) {
        // Handshake completed successfully

        if (m_handshake_state == EAuthState::E_AUTHENTICATED) {
          return m_handshake_state;
        }

        //if (!m_factory->is_server()) {
        //  handshake_send_state(pipe, 0, &transferring);
        //}

#if 0
        proc_state = handshake_recv_state(pipe, transferred);
        handshake_send_state(pipe, 0, &transferring);

        if (proc_state == EProcState::E_FINISHED) {
          m_handshake_state = EAuthState::E_AUTHENTICATED;
          return EAuthState::E_AUTHENTICATED;
        }
#else
        m_handshake_state = EAuthState::E_AUTHENTICATED;
        return m_handshake_state;
#endif
      }
      else {
        // The handshake either errored or is searching for more data
        int err = SSL_get_error(m_ssl, result);
        if (err == SSL_ERROR_WANT_READ) {
          proc_state = handshake_recv_state(pipe, recv_transferred);
          handshake_send_state(pipe, 0, &transferring);
        }
        else if (err == SSL_ERROR_WANT_WRITE) {
          if (m_factory->is_server()) {
            proc_state = handshake_send_state(pipe, send_transferred, &transferring);
            wants_recv = transferring > 0;
          }
          else {
            proc_state = handshake_send_state(pipe, send_transferred, &transferring);
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

  static bool calculate_iosize_from_tls_record_vector(const char* data, size_t data_size, size_t& isize, size_t& osize);

  ESecurityState TLSSecurityController::decrypt(const char* tls_data, uint32_t tls_size, decrypt_cb on_decrypt)
  {
    m_digested_by_crypt = 0;

    if (m_handshake_state != EAuthState::E_AUTHENTICATED) {
      return ESecurityState::E_FAILED;
    }

    if (tls_data == nullptr) {
      return ESecurityState::E_FAILED;
    }

    size_t rsize, wsize;
    if (!calculate_iosize_from_tls_record_vector(tls_data, tls_size, rsize, wsize)) {
      return ESecurityState::E_WANTS_DATA;
    }

    m_digested_by_crypt = rsize;

    // 1. Feed new data into OpenSSL (if any)
    if (tls_size > 0) {
      int written = BIO_write(m_in_bio, tls_data, (int)tls_size);
      if (written <= 0) {
        return ESecurityState::E_FAILED; // BIO failure
      }
    }

    char* decrypt_out = static_cast<char*>(malloc(wsize));

    size_t total_decrypted = 0;
    size_t total_processed_delta = 0;
    int beg_proc_read = BIO_number_read(m_in_bio);

    while (rsize - total_processed_delta > 0) {
      int ret_val = SSL_read(m_ssl, decrypt_out + total_decrypted, rsize - total_decrypted);

      if (ret_val > 0) {
        total_processed_delta = BIO_number_read(m_in_bio) - beg_proc_read;
        total_decrypted += ret_val;
      }
      else {
        int ssl_err = SSL_get_error(m_ssl, ret_val);

        // Case A: No more data available right now (Normal Exit)
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
          return ESecurityState::E_WANTS_DATA;
        }

        // Case B: Peer closed connection gracefully (EOF)
        if (ssl_err == SSL_ERROR_ZERO_RETURN) {
          break;
        }

        // Case C: Actual Fatal Error
        unsigned long err = ERR_get_error();
        // If checking syscall error, sometimes queue is empty, meaning EOF/Connection Reset
        if (ssl_err == SSL_ERROR_SYSCALL && err == 0) {
          break; // Treat as dirty EOF
        }

        fprintf(stderr, "OpenSSL Fatal error: %s\n", ERR_error_string(err, nullptr));
        return ESecurityState::E_FAILED;
      }
    }

    if (total_decrypted <= 0) {
      return ESecurityState::E_FAILED;
    }

    return
      on_decrypt(decrypt_out, total_decrypted) ? ESecurityState::E_SUCCEEDED : ESecurityState::E_FAILED;
  }

  ESecurityState TLSSecurityController::encrypt(const char* data, uint32_t size, encrypt_cb on_encrypt)
  {
    if (m_handshake_state != EAuthState::E_AUTHENTICATED) {
      return ESecurityState::E_FAILED;
    }

    if (data == nullptr || size == 0) {
      return ESecurityState::E_FAILED;
    }

    if (!on_encrypt) {
      return ESecurityState::E_FAILED;
    }

    int processed = SSL_write(m_ssl, data, (int)size);
    if (processed <= 0) {
      unsigned long err = ERR_get_error();
      if (err == 0) {
        fprintf(stderr, "SSL_ERROR_SYSCALL: probably EOF or no I/O attempted.\n");
      }
      else {
        fprintf(stderr, "OpenSSL error: %s\n", ERR_error_string(err, nullptr));
      }
      return ESecurityState::E_FAILED;
    }

    int written = (int)BIO_ctrl_pending(m_out_bio);
    char* encrypt_out = (char*)malloc(written);

    int bytes = BIO_read(m_out_bio, encrypt_out, written);
    if (bytes <= 0) {
      free(encrypt_out);
      return ESecurityState::E_FAILED;
    }

    // encrypt_out passes ownership to callback for optimization purposes
    return on_encrypt(encrypt_out, bytes) ? ESecurityState::E_SUCCEEDED : ESecurityState::E_FAILED;
  }

  uint32_t TLSSecurityController::get_digested_by_crypt() const {
    return m_digested_by_crypt;
  }

  TLSSecurityController::EProcState
    TLSSecurityController::handshake_send_state(ISocketPipe* pipe, int32_t post_transferred, int32_t* out_transferring)
  {
    uint32_t send_buf_size = pipe->get_os_layer()->send_buf_size();
    char* tls_out = new char[send_buf_size];

    int pending = (int)BIO_ctrl_pending(m_out_bio);
    int bytes_to_send = BIO_read(m_out_bio, tls_out, min(pending, (int)send_buf_size));
    if (bytes_to_send > 0) {
      if (pipe->is_busy(EPipeOperation::E_SEND)) {
        return EProcState::E_WAITING;
      }

      // "Insecure" send, because it is pre-encrypted handshake data
      // This prevents the encrypted handshake data from being encrypted again
      uint32_t flags_ = (uint32_t)ESendFlags::E_FORCE_INSECURE;
      EIOState state = pipe->send(tls_out, bytes_to_send, &flags_);

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

  TLSSecurityController::EProcState
    TLSSecurityController::handshake_recv_state(ISocketPipe* pipe, int32_t post_transferred)
  {
    char* recv_buf = pipe->get_os_layer()->recv_buf();

    if (post_transferred != 0) {
      // Push received TLS data into OpenSSL's read BIO
      int written = BIO_write(m_in_bio, recv_buf, post_transferred);
      if (written <= 0) {
        fprintf(stderr, "BIO_write to rbio failed.\n");
        return EProcState::E_FAILED;
      }

      //if (is_tls_record_finish(recv_buf)) {
      //  return EProcState::E_FINISHED;
      //}

      return EProcState::E_READY;
    }

    //if (is_busy(EPipeOperation::E_RECV)) {
    //  return EProcState::E_WAITING;
    //}

    uint32_t tmp_;
    uint32_t flags_ = 0;
    EIOState state = pipe->recv(0, &flags_, &tmp_);
    if (state == EIOState::E_ERROR) {
      return EProcState::E_FAILED;
    }
    else {
      return EProcState::E_WAITING;
    }
  }

  void TLSSecurityController::on_error(error_cb cb) { m_error_cb = cb; }
  void TLSSecurityController::on_verify(verify_cb cb) { m_verify_cb = cb; }

  void TLSSecurityController::emit_error(const std::string& error) { m_error_cb(error); }
  void TLSSecurityController::emit_verify() { m_verify_cb(); }

  bool TLSSecurityController::is_tls_record_finish(const char* record)
  {
    return record[0] == '\x16' && record[3] == '\x00' && record[4] == '\x40';
  }

  TLSSecurityFactory::TLSSecurityFactory(
    bool is_server, const std::filesystem::path& key_file, const std::filesystem::path& cert_file,
    const std::filesystem::path& ca_file, const std::string& hostname, const std::string& password, ETLSVerifyFlags verify_flags)
    : m_is_server(is_server), m_key_file(key_file), m_cert_file(cert_file), m_ca_file(ca_file), m_hostname(hostname), m_password(password), m_verify_flags(verify_flags)
  {
  }

  bool calculate_iosize_from_tls_record_vector(const char* data, size_t data_size, size_t& isize, size_t& osize)
  {
    isize = 0;
    osize = 0;

    size_t offset = 0;
    while (offset + 5 <= data_size) {
      // TLS record header is 5 bytes
      // Byte 0: Content Type
      // Byte 1-2: Version
      // Byte 3-4: Length (Big Endian)

      uint16_t length = (static_cast<uint8_t>(data[offset + 3]) << 8) | static_cast<uint8_t>(data[offset + 4]);
      // Check if the remaining data is enough for the current record
      if (offset + 5 + length > data_size) {
        return false; // Incomplete record
      }

      isize += length + 5;
      osize += length + 2048 + 5;
      offset += static_cast<size_t>(5 + length); // Move to the next record
    }

    return true;
  }
}
