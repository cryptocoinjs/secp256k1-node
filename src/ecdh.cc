#include <node.h>
#include <nan.h>
#include <secp256k1.h>

#include "util.h"
#include "ecdh_secp256k1.h"

extern secp256k1_context* secp256k1ctx;

NAN_METHOD(ecdh_sha256) {
  Nan::HandleScope scope;

  HANDLE_ARG_PUBLIC_KEY(0)
  HANDLE_ARG_PRIVATE_KEY(1)

  unsigned char output[32];
  if (secp256k1_ecdh_sha256(secp256k1ctx, &output[0], &public_key, &private_key[0]) == 0) {
    return Nan::ThrowError(ECDH_FAIL);
  }

  RETURN_BUFFER(output, 32)
}

NAN_METHOD(ecdh_unsafe) {
  Nan::HandleScope scope;

  HANDLE_ARG_PUBLIC_KEY(0)
  HANDLE_ARG_PRIVATE_KEY(1)
  HANDLE_ARG_COMPRESSED(2)

  secp256k1_pubkey new_public_key;
  if (secp256k1_ecdh_unsafe(secp256k1ctx, &new_public_key, &public_key, &private_key[0]) == 0) {
    return Nan::ThrowError(ECDH_FAIL);
  }

  RETURN_PUBLIC_KEY(new_public_key)
}
