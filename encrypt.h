#ifndef CRYPTO_H
#define CRYPTO_H
#include <stdbool.h>

#define AES_BLOCK_SZ 16

struct crypto_result {
  int ret;
  uint8_t output[AES_BLOCK_SZ];
};

struct crypto_result handle_encryption(uint8_t *data, uint8_t *key, bool encrypt);

struct crypto_result handle_encryption_cbc(uint8_t *data, uint8_t *key, uint8_t *iv, bool encrypt);

#endif //CRYPTO_H
