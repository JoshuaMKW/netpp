#pragma once

#include "security.h"

namespace netpp {

  class TLSSecurityController final : public ISecurityController {
  public:
    TLSSecurityController(
      const std::filesystem::path& key_file,
      const std::filesystem::path& cert_file,
      const std::filesystem::path& ca_file,
      const std::string& hostname,
      const std::string& password
    );
    ~TLSSecurityController() = default;

    ESecurityProtocol protocol() const override;

    const std::filesystem::path& key_file() const override;
    const std::filesystem::path& cert_file() const override;
    const std::filesystem::path& ca_file() const override;

    const std::string& hostname() const override;
    const std::string& password() const override;

    void on_error(error_cb cb) override;
    void on_verify(verify_cb cb) override;

  protected:
    void emit_error(const std::string& error) override;
    void emit_verify() override;

  private:
    std::filesystem::path m_key_file;
    std::filesystem::path m_cert_file;
    std::filesystem::path m_ca_file;
    std::string m_hostname;
    std::string m_password;
    error_cb m_error_cb;
    verify_cb m_verify_cb;
  };

}
