#pragma once

#define CK_SECRET_MAX 256
#define CK_SECRET_LEN 32

namespace netpp {

  /*
  Generates a cookie using a random secret
  */
  bool cookie_generate(const unsigned char* data, size_t dlen, unsigned char* cookie, unsigned int* clen);

  /*
  Creates and stores an amount of secrets
  into the vault
  */
  size_t cookie_secrets_generate(size_t amount);

  /*
  Returns the amount of secrets in the vault
  */
  size_t cookie_secrets_count(void);

  /*
  Picks a random secret off the vault
  */
  unsigned char* cookie_secrets_random(void);

  /*
  Tests whether cookie matches on of the secrets
  in the vault
  */
  bool cookie_secrets_exist(const unsigned char* data, size_t dlen,
    const unsigned char* cookie, size_t clen);

}
