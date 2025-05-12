#include <filesystem>

#include "tls/controller.h"

namespace netpp {

  TLSSecurityController::TLSSecurityController(
    const std::filesystem::path& key_file,
    const std::filesystem::path& cert_file,
    const std::filesystem::path& ca_file,
    const std::string& hostname,
    const std::string& password
  ) : m_key_file(key_file), m_cert_file(cert_file), m_ca_file(ca_file), m_hostname(hostname), m_password(password) {}

  ESecurityProtocol TLSSecurityController::protocol() const { return ESecurityProtocol::E_TLS; }

  const std::filesystem::path& TLSSecurityController::key_file() const { return m_key_file; }
  const std::filesystem::path& TLSSecurityController::cert_file() const { return m_cert_file; }
  const std::filesystem::path& TLSSecurityController::ca_file() const { return m_ca_file; }

  const std::string& TLSSecurityController::hostname() const { return m_hostname; }
  const std::string& TLSSecurityController::password() const { return m_password; }

  void TLSSecurityController::on_error(error_cb cb) { m_error_cb = cb; }
  void TLSSecurityController::on_verify(verify_cb cb) { m_verify_cb = cb; }

  void TLSSecurityController::emit_error(const std::string& error) { m_error_cb(error); }
  void TLSSecurityController::emit_verify() { m_verify_cb(); }

}
