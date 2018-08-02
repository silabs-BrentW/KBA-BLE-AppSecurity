#include <string.h>

#include MBEDTLS_CONFIG_FILE
#include "aes.h"
#include "encrypt.h"

//#define TEST_CODE 1
mbedtls_aes_context aes_ctx;

//FIX this example uses ECB. Maybe we should switch to CBC or even better CTR mode
// It would also be better to pass in the data as an array
#ifdef TEST_CODE
void encrypt_data()
{
    uint8_t key[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};                     
    uint8_t data[] = "0123456789abcd!!";//{0xf3,0x44,0x81,0xec,0x3c,0xc6,0x27,0xba,0xcd,0x5d,0xc3,0xfb,0x08,0xf2,0x73,0xe6};
    uint8_t comparison[AES_BLOCK_SZ] = {0x03,0x36,0x76,0x3e,0x96,0x6d,0x92,0x59,0x5a,0x56,0x7c,0xc9,0xce,0x53,0x7f,0x5e};
    uint8_t data_encrypted[AES_BLOCK_SZ];
    uint8_t data_decrypted[AES_BLOCK_SZ];
    int ret;

    //encrypt
    
    do {
      ret = mbedtls_aes_setkey_enc( &aes_ctx, key, 128 );
    } while ((MBEDTLS_ERR_DEVICE_BUSY == ret));

    do {
      ret = mbedtls_aes_crypt_ecb(&aes_ctx,
                                  MBEDTLS_AES_ENCRYPT,
                                  data,
                                  data_encrypted);
    } while ((MBEDTLS_ERR_DEVICE_BUSY == ret));
    if (ret) {
      while(1);
    }
    
//    if (memcmp(comparison, data_encrypted,AES_BLOCK_SZ)) {
//      while(1);
//    }
    
    //decrypt
    do {
      ret = mbedtls_aes_setkey_dec( &aes_ctx, key, 128 );
    } while ((MBEDTLS_ERR_DEVICE_BUSY == ret));

    do {
      ret = mbedtls_aes_crypt_ecb(&aes_ctx,
                                  MBEDTLS_AES_DECRYPT,
                                  data_encrypted,
                                  data_decrypted);
    } while ((MBEDTLS_ERR_DEVICE_BUSY == ret));
//    if (ret) {
//      while(1);
//    }
//    
    if (memcmp(data, data_decrypted,AES_BLOCK_SZ)) {
      while(1);
    }
}
#endif



struct crypto_result handle_encryption(uint8_t *data, uint8_t *key, bool mode)
{
  
  struct crypto_result result;
 
  /*MBEDTLS implementation seems to have changed so that there is no longer any return value
   * to indicate busy, only success or invalid key length*/
 // do {
      if(mode)
      {
        result.ret = mbedtls_aes_setkey_enc( &aes_ctx, key, 128 );
      }
      else
      {
        result.ret = mbedtls_aes_setkey_dec( &aes_ctx, key, 128 );
      }
      
   // } //while ((MBEDTLS_ERR_DEVICE_BUSY == result.ret));

    //do {
      result.ret = mbedtls_aes_crypt_ecb(&aes_ctx,
                                  mode,
                                  data,
                                  result.output);
   // } while ((MBEDTLS_ERR_DEVICE_BUSY == result.ret));
   
 
    return result;
  
}


struct crypto_result handle_encryption_cbc(uint8_t *data,  uint8_t *key, uint8_t *iv, bool mode)
{
  
  struct crypto_result result;
 
  
  //do {
      if(mode) {
        result.ret = mbedtls_aes_setkey_enc( &aes_ctx, key, 128 );
      }
      else {
        result.ret = mbedtls_aes_setkey_dec( &aes_ctx, key, 128 );
      }
      
   // } while ((MBEDTLS_ERR_DEVICE_BUSY == result.ret));

   // do {
      result.ret = mbedtls_aes_crypt_cbc(&aes_ctx, mode, 16, iv, data, result.output);
   // } while ((MBEDTLS_ERR_DEVICE_BUSY == result.ret));
   
 
    return result;
  
}


