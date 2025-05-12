#pragma once

#include <filesystem>
#include <functional>

namespace netpp {

  enum class ESecurityProtocol {
    E_NONE = -1,
    E_TLS,
    E_SSL,
  };

  class ISecurityController {
  public:
    using error_cb = std::function<void(const std::string&)>;
    using verify_cb = std::function<void()>;

    virtual ~ISecurityController() = default;

    virtual ESecurityProtocol protocol() const = 0;

    virtual const std::filesystem::path& key_file() const = 0;
    virtual const std::filesystem::path& cert_file() const = 0;
    virtual const std::filesystem::path& ca_file() const = 0;

    virtual const std::string& hostname() const = 0;
    virtual const std::string& password() const = 0;

    virtual void on_error(error_cb cb) = 0;
    virtual void on_verify(verify_cb cb) = 0;

  protected:
    virtual void emit_error(const std::string& error) = 0;
    virtual void emit_verify() = 0;
  };

}