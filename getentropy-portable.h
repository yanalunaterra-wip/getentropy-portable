#ifndef GETENTROPY_PORTABLE_H
#define GETENTROPY_PORTABLE_H

#ifdef _WIN32
#include <errno.h>
#include <stdint.h>
#include <windows.h>

int getentropy(void *buf, size_t len) {
  HCRYPTPROV provider;

  if (len > 256) {
    errno = EIO;
    return -1;
  }

  if (CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL,
                          CRYPT_VERIFYCONTEXT) == 0)
    goto fail;

  if (CryptGenRandom(provider, len, buf) == 0) {
    CryptReleaseContext(provider, 0);
    goto fail;
  }

  CryptReleaseContext(provider, 0);
  return 0;

fail:
  errno = EIO;
  return -1;
}
#endif

#endif /* GETENTROPY_PORTABLE_H */
