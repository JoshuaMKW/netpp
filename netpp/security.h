#pragma once

#include <filesystem>
#include <functional>
#include <string>

#include "netpp/sockenum.h"

#include <openssl/ssl.h>

namespace netpp {

  class ISocketPipe;

  enum class EAuthState {
    E_FAILED = -1,
    E_NONE,
    E_HANDSHAKE,
    E_AUTHENTICATED,
  };

  enum class ESecurityState {
    E_FAILED = -1,
    E_NONE,
    E_SUCCEEDED,
    E_WANTS_DATA,
  };

  enum class ESecurityProtocol {
    E_NONE = -1,
    E_TLS,
    E_DTLS,
  };

  enum class ETransportProtocolFlags {
    E_NONE = 0,
    E_TCP = (1 << 0),
    E_UDP = (1 << 1),
  };
  NETPP_BITWISE_ENUM(ETransportProtocolFlags)

    class NETPP_API ISecurityController {
    public:
      using error_cb = std::function<void(const std::string&)>;
      using verify_cb = std::function<void()>;

      virtual ~ISecurityController() = default;

      virtual bool is_authenticated() const = 0;
      virtual bool is_failed() const = 0;

      // Cast to ESecurityProtocol for default protocols
      virtual int protocol() const = 0;
      virtual ETransportProtocolFlags supported_transports() const = 0;

      virtual const std::filesystem::path& key_file() const = 0;
      virtual const std::filesystem::path& cert_file() const = 0;
      virtual const std::filesystem::path& ca_file() const = 0;

      virtual const std::string& hostname() const = 0;
      virtual const std::string& password() const = 0;

      virtual bool initialize() = 0;
      virtual void deinitialize() = 0;

      virtual bool set_accept_state() = 0;
      virtual bool set_connect_state() = 0;

      using decrypt_cb = std::function<bool(const char* decrypted, uint32_t decrypted_size)>;
      using encrypt_cb = std::function<bool(const char* encrypted, uint32_t encrypted_size)>;
      virtual ESecurityState decrypt(const char* tls_data, uint32_t tls_size, decrypt_cb on_decrypt) = 0;
      virtual ESecurityState encrypt(const char* data, uint32_t size, encrypt_cb on_encrypt) = 0;
      virtual uint32_t get_digested_by_crypt() const = 0;

      virtual EAuthState advance_handshake(ISocketPipe* pipe, EPipeOperation last_op, int32_t post_transferred) = 0;

      virtual void on_error(error_cb cb) = 0;
      virtual void on_verify(verify_cb cb) = 0;

    protected:
      virtual void emit_error(const std::string& error) = 0;
      virtual void emit_verify() = 0;
  };

  class NETPP_API ISecurityFactory {
  public:
    virtual ~ISecurityFactory() = default;

    virtual ISecurityController* create_controller() = 0;

    virtual bool is_server() const = 0;
    virtual int protocol() const = 0;
    virtual ETransportProtocolFlags supported_transports() const = 0;

    virtual const std::filesystem::path& key_file() const = 0;
    virtual const std::filesystem::path& cert_file() const = 0;
    virtual const std::filesystem::path& ca_file() const = 0;

    virtual const std::string& hostname() const = 0;
    virtual const std::string& password() const = 0;
  };

  bool generate_client_key_rsa_2048(
    const std::filesystem::path& key_file,
    const std::filesystem::path& csr_file,
    const std::string& country,
    const std::string& organization,
    const std::string& cn = "",
    const std::string& password = "");

  bool generate_client_key_rsa_4096(
    const std::filesystem::path& key_file,
    const std::filesystem::path& csr_file,
    const std::string& country,
    const std::string& organization,
    const std::string& cn = "",
    const std::string& password = "");

  bool load_system_cacerts(SSL_CTX* ctx);

}