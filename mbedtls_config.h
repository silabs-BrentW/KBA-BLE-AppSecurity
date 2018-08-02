/*
 * Minimal configuration for AES test on SiliconLabs devices incorporating
 * CRYPTO hardware accelerator.
 *
 */

// *** BW notes version ***

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

#if !defined( NO_CRYPTO_ACCELERATION )
/* SiliconLabs plugins with CRYPTO acceleration support. */
#define MBEDTLS_SLCL_PLUGINS  //***TODO: remove -- deprecated
#define MBEDTLS_MPI_MODULAR_DIVISION_ALT  //*** TODO: remove -- deprecated
#define MBEDTLS_AES_ALT
#define MBEDTLS_CRYPTO_DEVICE_PREEMPTION

//*** TODO: add hardware TRNG acceleration support macros
//*** TODO: add some form of authentication support
//*** TODO: add some form of ECDHE key exchange support

#endif

/* mbed TLS modules */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CFB
#define MBEDTLS_CIPHER_MODE_CTR

/* Save RAM at the expense of ROM */
#define MBEDTLS_AES_ROM_TABLES

/* Save RAM by adjusting to our exact needs */
#define MBEDTLS_ECP_MAX_BITS   384
#define MBEDTLS_MPI_MAX_SIZE    48 // 384 bits is 48 bytes

/* 
   Set MBEDTLS_ECP_WINDOW_SIZE to configure
   ECC point multiplication window size, see ecp.h:
   2 = Save RAM at the expense of speed
   3 = Improve speed at the expense of RAM
   4 = Optimize speed at the expense of RAM
*/
//*** TODO: ECP_WINDOW_SIZE doesn't do anything with AES, and the original example didn't use anything but AES, so why is this here?
#define MBEDTLS_ECP_WINDOW_SIZE        3
#define MBEDTLS_ECP_FIXED_POINT_OPTIM  0

/* Significant speed benefit at the expense of some ROM */

//*** TODO: Why is this optimization commented out, especially if using ECP?
//#define MBEDTLS_ECP_NIST_OPTIM

/*
 * You should adjust this to the exact number of sources you're using: default
 * is the "mbedtls_platform_entropy_poll" source, but you may want to add other ones.
 * Minimum is 2 for the entropy test suite.
 */
#define MBEDTLS_ENTROPY_MAX_SOURCES 2

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CONFIG_H */
