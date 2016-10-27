#include <node.h>
#include <nan.h>
#include <secp256k1.h>
#include <lax_der_parsing.h>

#include "messages.h"
#include "util.h"

extern secp256k1_context* secp256k1ctx;

NAN_METHOD(ecdsa_signature_normalize) {
  Nan::HandleScope scope;

  HANDLE_ARG_ECDSA_SIGNATURE(0)

  secp256k1_ecdsa_signature sigout;
  secp256k1_ecdsa_signature_normalize(secp256k1ctx, &sigout, &signature);

  unsigned char output[64];
  secp256k1_ecdsa_signature_serialize_compact(secp256k1ctx, &output[0], &sigout);

  RETURN_BUFFER(output, 64)
}

NAN_METHOD(ecdsa_signature_export) {
  Nan::HandleScope scope;

  HANDLE_ARG_ECDSA_SIGNATURE(0)

  unsigned char output[72];
  size_t output_length = 72;
  if (secp256k1_ecdsa_signature_serialize_der(secp256k1ctx, &output[0], &output_length, &signature) == 0) {
    return Nan::ThrowError(ECDSA_SIGNATURE_SERIALIZE_DER_FAIL);
  }

  RETURN_BUFFER(output, output_length)
}

NAN_METHOD(ecdsa_signature_import) {
  Nan::HandleScope scope;

  HANDLE_ARG_ECDSA_SIGNATURE_DER(0)

  secp256k1_ecdsa_signature signature;
  if (secp256k1_ecdsa_signature_parse_der(secp256k1ctx, &signature, signature_der, signature_der_length) == 0) {
    return Nan::ThrowError(ECDSA_SIGNATURE_PARSE_DER_FAIL);
  }

  unsigned char output[64];
  secp256k1_ecdsa_signature_serialize_compact(secp256k1ctx, &output[0], &signature);

  RETURN_BUFFER(output, 64)
}

NAN_METHOD(ecdsa_signature_import_lax) {
  Nan::HandleScope scope;

  HANDLE_ARG_ECDSA_SIGNATURE_DER(0)

  secp256k1_ecdsa_signature signature;
  if (ecdsa_signature_parse_der_lax(secp256k1ctx, &signature, signature_der, signature_der_length) == 0) {
    return Nan::ThrowError(ECDSA_SIGNATURE_PARSE_DER_FAIL);
  }

  unsigned char output[64];
  secp256k1_ecdsa_signature_serialize_compact(secp256k1ctx, &output[0], &signature);

  RETURN_BUFFER(output, 64)
}
