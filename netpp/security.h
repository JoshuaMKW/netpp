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

    virtual int64_t decrypt(const char* data, size_t size, char** decrypt_out) = 0;
    virtual int64_t encrypt(const char* data, size_t size, char** encrypt_out) = 0;

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