#include "dtls_bio.h"

#include <openssl/ssl.h>

static int dgram_write(BIO* h, const char* buf, int num);
static int dgram_read(BIO* h, char* buf, int size);
static int dgram_puts(BIO* h, const char* str);
static long dgram_ctrl(BIO* h, int cmd, long arg1, void* arg2);
static int dgram_new(BIO* h);
static int dgram_free(BIO* data);
static int dgram_clear(BIO* bio);