#pragma once

#include <openssl/ssl.h>

#include "netpp/netpp.h"
#include "netpp/socket.h"

namespace netpp {

  enum class EDTLSVerifyFlags {
    VERIFY_NONE = SSL_VERIFY_NONE,
    VERIFY_PEER = SSL_VERIFY_PEER,
    VERIFY_FAIL_IF_NO_PEER_CERT = SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
    VERIFY_CLIENT_ONCE = SSL_VERIFY_CLIENT_ONCE,
    VERIFY_POST_HANDSHAKE = SSL_VERIFY_POST_HANDSHAKE,
  };
  NETPP_BITWISE_ENUM(EDTLSVerifyFlags);

  class DTLSSecurityFactory;

  class DTLSSecurityController final : public ISecurityController {
  public:
    DTLSSecurityController(const DTLSSecurityFactory* factory);
    ~DTLSSecurityController() = default;

    bool is_authenticated() const override;
    bool is_failed() const override;

    int protocol() const override;
    ETransportProtocolFlags supported_transports() const override;

    const std::filesystem::path& key_file() const override;
    const std::filesystem::path& cert_file() const override;
    const std::filesystem::path& ca_file() const override;

    const std::string& hostname() const override;
    const std::string& password() const override;

    bool initialize() override;
    void deinitialize() override;

    bool set_accept_state();
    bool set_connect_state();

    int64_t decrypt(const char* data, size_t size, char** decrypt_out) override;
    int64_t encrypt(const char* data, size_t size, char** encrypt_out) override;

    virtual EAuthState advance_handshake(ISocketPipe* pipe, EPipeOperation last_op, int32_t post_transferred) override;

    enum class EProcState {
      E_FAILED,
      E_WAITING,
      E_READY,
      E_FINISHED,
    };

    EProcState handshake_send_state(ISocketPipe* pipe, int32_t post_transferred, int32_t* out_transferring);
    EProcState handshake_recv_state(ISocketPipe* pipe, int32_t post_transferred);

    void on_error(error_cb cb) override;
    void on_verify(verify_cb cb) override;

  protected:
    void emit_error(const std::string& error) override;
    void emit_verify() override;

    static bool is_tls_record_finish(const char* record);

  private:
    const DTLSSecurityFactory* m_factory;

    error_cb m_error_cb;
    verify_cb m_verify_cb;

    std::atomic<bool> m_initialized;
    SSL_CTX* m_dtls_ctx;
    SSL* m_ssl;
    BIO* m_in_bio;
    BIO* m_out_bio;
    BIO_ADDR* m_client;
    std::atomic<bool> m_handshake_initiated;
    std::atomic<EAuthState> m_handshake_state;
  };

  class DTLSSecurityFactory : public ISecurityFactory {
  public:
    DTLSSecurityFactory(
      bool is_server,
      const std::filesystem::path& key_file,
      const std::filesystem::path& cert_file,
      const std::filesystem::path& ca_file,
      const std::string& hostname,
      const std::string& password,
      EDTLSVerifyFlags verify_flags = EDTLSVerifyFlags::VERIFY_PEER
    );
    ~DTLSSecurityFactory() override = default;

    ISecurityController* create_controller() override {
      return new DTLSSecurityController(this);
    }

    bool is_server() const override { return m_is_server; }
    int protocol() const override { return (int)ESecurityProtocol::E_TLS; }
    ETransportProtocolFlags supported_transports() const override { return ETransportProtocolFlags::E_TCP; }

    const std::filesystem::path& key_file() const override { return m_key_file; }
    const std::filesystem::path& cert_file() const override { return m_cert_file; }
    const std::filesystem::path& ca_file() const override { return m_ca_file; }

    const std::string& hostname() const override { return m_hostname; }
    const std::string& password() const override { return m_password; }

    EDTLSVerifyFlags verify_flags() const { return m_verify_flags; }

  private:
    bool m_is_server;

    std::filesystem::path m_key_file;
    std::filesystem::path m_cert_file;
    std::filesystem::path m_ca_file;
    std::string m_hostname;
    std::string m_password;
    EDTLSVerifyFlags m_verify_flags;
  };
}
