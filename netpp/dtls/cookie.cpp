#include "netpp/dtls/cookie.h"

#include <random>
#include <stddef.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define EVP_MAX_MD_SIZE_256 32

namespace netpp {

  /*
  Vault that contains the secrets
  */
  static unsigned char ck_secrets_vault[CK_SECRET_MAX][CK_SECRET_LEN];

  static unsigned char* HMAC_SHA256_Calc(const void* secret, size_t secret_len, const unsigned char* data, size_t data_len, unsigned char* out, unsigned int* out_len) {
    return HMAC(EVP_sha256(), secret, secret_len, data, data_len, out, out_len);
  }

  bool cookie_generate(const unsigned char* data, size_t data_len, unsigned char* cookie, unsigned int* clen) {
    HMAC_SHA256_Calc(cookie_secrets_random(), CK_SECRET_LEN, data, data_len, cookie, clen);
    return true;
  }

  /*
  Creates and stores an amount of secrets
  into the vault
  */
  size_t cookie_secrets_generate(size_t amount) {
    size_t limit = amount < CK_SECRET_MAX ? amount : CK_SECRET_MAX;
    for (size_t i = 0; i < limit; ++i) {
      if (!RAND_bytes(ck_secrets_vault[i], CK_SECRET_LEN)) {
        return i;
      }
    }
    return limit;
  }

  /*
  Returns the amount of secrets in the vault
  */
  size_t cookie_secrets_count() {
    return sizeof(ck_secrets_vault) / sizeof(ck_secrets_vault[0]);
  }

  /*
  Picks a random secret off the vault
  */
  unsigned char* cookie_secrets_random() {
    size_t count = cookie_secrets_count();

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, count);

    return ck_secrets_vault[dist(gen)];
  }

  /*
  Tests whether cookie matches on of the secrets
  in the vault
  */
  bool cookie_secrets_exist(const unsigned char* data, size_t dlen,
    const unsigned char* cookie, size_t clen) {
    size_t count = cookie_secrets_count();

    unsigned int reslen = 0;
    unsigned char result[EVP_MAX_MD_SIZE_256];

    for (size_t i = 0; i < count; ++i) {
      if (ck_secrets_vault[i] == nullptr) {
        continue;
      }

      memset(&result, 0, sizeof(result));

      HMAC_SHA256_Calc(ck_secrets_vault[i], CK_SECRET_LEN, data, dlen, result, &reslen);

      if (clen == reslen && memcmp(result, cookie, reslen) == 0) {
        return true;
      }
    }

    return false;
  }

}