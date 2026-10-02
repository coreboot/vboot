/* Copyright 2010 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/* C port of DumpPublicKey.java from the Android Open source project with
 * support for additional RSA key sizes. (platform/system/core,git/libmincrypt
 * /tools/DumpPublicKey.java). Uses the OpenSSL X509 and BIGNUM library.
 */

#include <openssl/pem.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "openssl_compat.h"
#include "util_misc.h"

/* Command line tool to extract RSA public keys from X.509 certificates
 * and output a pre-processed version of keys for use by RSA verification
 * routines.
 */

static int check(RSA* key) {
  const BIGNUM *n, *e;
  int public_exponent, modulus;

  RSA_get0_key(key, &n, &e, NULL);
  public_exponent = BN_get_word(e);
  modulus = BN_num_bits(n);

  if (public_exponent != 3 && public_exponent != 65537) {
    fprintf(stderr,
            "WARNING: Public exponent should be 3 or 65537 (but is %d).\n",
            public_exponent);
  }

  if (modulus != 1024 && modulus != 2048 && modulus != 3072 && modulus != 4096
      && modulus != 8192) {
    fprintf(stderr, "ERROR: Unknown modulus length = %d.\n", modulus);
    return 0;
  }
  return 1;
}

int main(int argc, char* argv[]) {
  int cert_mode = 0;
  FILE* fp;
  X509* cert = NULL;
  RSA* pubkey = NULL;
  EVP_PKEY* key;
  char *progname;
  uint8_t *buf = NULL;
  uint32_t size;

  if (argc != 3 || (strcmp(argv[1], "-cert") && strcmp(argv[1], "-pub"))) {
    progname = strrchr(argv[0], '/');
    if (progname)
      progname++;
    else
      progname = argv[0];
    fprintf(stderr, "Usage: %s <-cert | -pub> <file>\n", progname);
    return -1;
  }

  if (!strcmp(argv[1], "-cert"))
    cert_mode = 1;

  fp = fopen(argv[2], "r");

  if (!fp) {
    fprintf(stderr, "Couldn't open file %s!\n", argv[2]);
    return -1;
  }

  if (cert_mode) {
    /* Read the certificate */
    if (!PEM_read_X509(fp, &cert, NULL, NULL)) {
      fprintf(stderr, "Couldn't read certificate.\n");
      goto fail;
    }

    /* Get the public key from the certificate. */
    key = X509_get_pubkey(cert);

    /* Convert to a RSA_style key. */
    if (!(pubkey = EVP_PKEY_get1_RSA(key))) {
      fprintf(stderr, "Couldn't convert to a RSA style key.\n");
      goto fail;
    }
  } else {
    /* Read the pubkey in .PEM format. */
    if (!(pubkey = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL))) {
      fprintf(stderr, "Couldn't read public key file.\n");
      goto fail;
    }
  }

  if (check(pubkey) && !vb_keyb_from_rsa(pubkey, &buf, &size)) {
    if (write(STDOUT_FILENO, buf, size) != (ssize_t)size)
      fprintf(stderr, "Couldn't write output.\n");
    free(buf);
  }

fail:
  X509_free(cert);
  RSA_free(pubkey);
  fclose(fp);

  return 0;
}
