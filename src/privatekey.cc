#include <node.h>
#include <nan.h>
#include <secp256k1.h>
#include <lax_der_privatekey_parsing.h>

#include "messages.h"
#include "util.h"

extern secp256k1_context* secp256k1ctx;

NAN_METHOD(private_key_verify) {
  Nan::HandleScope scope;

  HANDLE_ARG_BUFFER(0, private_key, EC_PRIVATE_KEY_TYPE_INVALID)

  if (node::Buffer::Length(private_key_buffer) != 32) {
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
  }

  int result = secp256k1_ec_seckey_verify(secp256k1ctx, private_key);

  RETURN_BOOLEAN(result)
}

NAN_METHOD(private_key_export) {
  Nan::HandleScope scope;

  HANDLE_ARG_PRIVATE_KEY(0)
  HANDLE_ARG_COMPRESSED(1)

  // hack for compressed (only for ec_privkey_export_der)
  compressed = compressed == SECP256K1_EC_COMPRESSED ? 1 : 0;

  unsigned char output[279];
  size_t output_length;
  if (ec_privkey_export_der(secp256k1ctx, &output[0], &output_length, private_key, compressed) == 0) {
    return Nan::ThrowError(EC_PRIVATE_KEY_EXPORT_DER_FAIL);
  }

  RETURN_BUFFER(output, output_length)
}

NAN_METHOD(private_key_import) {
  Nan::HandleScope scope;

  HANDLE_ARG_BUFFER(0, input, EC_PRIVATE_KEY_TYPE_INVALID)
  CHECK_BUFFER_LENGTH_GT_ZERO(input_buffer, EC_PRIVATE_KEY_LENGTH_INVALID)
  size_t input_length = node::Buffer::Length(input_buffer);

  unsigned char private_key[32];
  if (ec_privkey_import_der(secp256k1ctx, &private_key[0], input, input_length) == 0) {
    return Nan::ThrowError(EC_PRIVATE_KEY_IMPORT_DER_FAIL);
  }

  RETURN_BUFFER(private_key, 32)
}

NAN_METHOD(private_key_tweak_add) {
  Nan::HandleScope scope;

  HANDLE_ARG_PRIVATE_KEY(0)
  HANDLE_ARG_TWEAK(1)

  unsigned char output[32];
  memcpy(&output[0], &private_key[0], 32);

  if (secp256k1_ec_privkey_tweak_add(secp256k1ctx, &output[0], tweak) == 0) {
    return Nan::ThrowError(EC_PRIVATE_KEY_TWEAK_ADD_FAIL);
  }

  RETURN_BUFFER(output, 32)
}

NAN_METHOD(private_key_tweak_mul) {
  Nan::HandleScope scope;

  HANDLE_ARG_PRIVATE_KEY(0)
  HANDLE_ARG_TWEAK(1)

  unsigned char output[32];
  memcpy(&output[0], &private_key[0], 32);

  if (secp256k1_ec_privkey_tweak_mul(secp256k1ctx, &output[0], tweak) == 0) {
    return Nan::ThrowError(EC_PRIVATE_KEY_TWEAK_MUL_FAIL);
  }

  RETURN_BUFFER(output, 32)
}
