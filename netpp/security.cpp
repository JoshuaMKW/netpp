#include "netpp/security.h"
#include <openssl/ssl.h>

#ifdef _WIN32
#include <Windows.h>
static std::string get_device_serial() {
  char value[255];
  DWORD BufferSize = 255;

  // Open the registry key
  HKEY hKey;
  long lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey);

  if (lResult == ERROR_SUCCESS) {
    // Read the "MachineGuid" value
    RegQueryValueExA(hKey, "MachineGuid", NULL, NULL, (LPBYTE)&value, &BufferSize);
    RegCloseKey(hKey);
    return std::string(value);
  }
  return "";
}
#elif defined(__linux__)
#include <fstream>
static std::string get_device_serial() {
  std::ifstream file("/etc/machine-id");
  if (file.is_open()) {
    std::string line;
    std::getline(file, line);
    file.close();
    return line;
  }
  return "";
}
#endif

static bool generate_client_key_rsa(
  const std::filesystem::path& key_file,
  const std::filesystem::path& csr_file,
  const std::string& country,
  const std::string& organization,
  const std::string& cn,
  const std::string& password,
  int bits) {
  // Create the context for the key generation
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (!ctx)
    return false;

  // Initialize the key generation
  if (EVP_PKEY_keygen_init(ctx) <= 0)
    return false;

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
    return false;

  // Generate the key
  EVP_PKEY* pkey = NULL;
  if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    return false;

  // Clean up the context (we don't need it anymore)
  EVP_PKEY_CTX_free(ctx);


  X509_REQ* req = X509_REQ_new();
  if (!req)
    return false;

  // Set the version (0 for version 1)
  if (X509_REQ_set_version(req, 0) != 1)
    return false;

  // Set the subject details (Who is requesting this cert?)
  // C=Country, O=Organization, CN=Common Name (Unique ID or Hostname)
  X509_NAME* name = X509_REQ_get_subject_name(req);
  X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)country.c_str(), -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)organization.c_str(), -1, -1, 0);

  if (cn.empty()) {
    std::string device_serial = get_device_serial();
    if (device_serial.empty()) {
      return false;
    }
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)device_serial.c_str(), -1, -1, 0);
  }
  else {
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)cn.c_str(), -1, -1, 0);
  }

  // Attach the Public Key to the Request
  if (X509_REQ_set_pubkey(req, pkey) != 1)
    return false;

  // Sign the Request with the Private Key (using SHA-256)
  if (X509_REQ_sign(req, pkey, EVP_sha256()) <= 0)
    return false;


  // Save Private Key
  BIO* key_bio = BIO_new_file(key_file.string().c_str(), "wb");
  if (key_bio) {
    // Write unencrypted key (PEM format)
    PEM_write_bio_PrivateKey(key_bio, pkey, NULL, NULL, 0, NULL, NULL);
    BIO_free(key_bio);
  }

  // Save CSR
  BIO* csr_bio = BIO_new_file(csr_file.string().c_str(), "wb");
  if (csr_bio) {
    PEM_write_bio_X509_REQ(csr_bio, req);
    BIO_free(csr_bio);
  }

  // Cleanup
  X509_REQ_free(req);
  EVP_PKEY_free(pkey);

  return true;
}

#ifdef _WIN32

#include <wincrypt.h>

#pragma comment(lib, "Crypt32.lib")

static bool add_windows_root_certs(SSL_CTX* ctx) {
  X509_STORE* store = SSL_CTX_get_cert_store(ctx);

  // Open the Windows "ROOT" system store
  HCERTSTORE hStore = CertOpenSystemStore(0, "ROOT");
  if (!hStore)
    return false;

  PCCERT_CONTEXT pContext = NULL;

  // Iterate over every certificate in the Windows store
  while ((pContext = CertEnumCertificatesInStore(hStore, pContext))) {
    // Windows gives us the certificate as a binary DER blob
    const unsigned char* der_data = pContext->pbCertEncoded;
    long der_len = pContext->cbCertEncoded;

    // Convert DER blob to OpenSSL X509 structure
    // Note: d2i_X509 moves the pointer, so we pass a temporary copy
    const unsigned char* p = der_data;
    X509* x509 = d2i_X509(NULL, &p, der_len);

    if (x509) {
      // Add to OpenSSL store
      X509_STORE_add_cert(store, x509);
      X509_free(x509); // OpenSSL increments the ref count, so we free our copy
    }
  }

  CertFreeCertificateContext(pContext);
  CertCloseStore(hStore, 0);

  return true;
}
#endif

namespace netpp {

  bool generate_client_key_rsa_2048(
    const std::filesystem::path& key_file,
    const std::filesystem::path& csr_file,
    const std::string& country,
    const std::string& organization,
    const std::string& cn,
    const std::string& password) {
    return generate_client_key_rsa(key_file, csr_file, country, organization, cn, password, 2048);
  }

  bool generate_client_key_rsa_4096(
    const std::filesystem::path& key_file,
    const std::filesystem::path& csr_file,
    const std::string& country,
    const std::string& organization,
    const std::string& cn,
    const std::string& password) {
    return generate_client_key_rsa(key_file, csr_file, country, organization, cn, password, 4096);
  }

  bool load_system_cacerts(SSL_CTX* ctx) {
#ifdef _WIN32
    return add_windows_root_certs(ctx);
#else
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
      return false;
    }
    return true;
#endif
  }

}