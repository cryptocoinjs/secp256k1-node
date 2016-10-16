#include <memory>
#include <node.h>
#include <nan.h>
#include <secp256k1.h>
#include <secp256k1_schnorr.h>

#include "nonce_function.h"
#include "messages.h"
#include "util.h"

extern secp256k1_context* secp256k1ctx;
extern v8::Local<v8::Function> noncefn_callback;

NAN_METHOD(schnorr_sign) {
  Nan::HandleScope scope;

  HANDLE_ARG_MESSAGE(0)
  HANDLE_ARG_PRIVATE_KEY(1)
  HANDLE_ARG_NONCE_FUNCTION(2)
  HANDLE_ARG_NONCE_DATA(3)

  unsigned char signature[64];
  if (secp256k1_schnorr_sign(secp256k1ctx, &signature[0], message, private_key, noncefn, noncedata) == 0) {
    return Nan::ThrowError(SCHNORR_SIGN_FAIL);
  }

  RETURN_BUFFER(signature, 64)
}

NAN_METHOD(schnorr_verify) {
  Nan::HandleScope scope;

  HANDLE_ARG_SCHNORR_SIGNATURE(0)
  HANDLE_ARG_MESSAGE(1)
  HANDLE_ARG_PUBLIC_KEY(2)

  int result = secp256k1_schnorr_verify(secp256k1ctx, &signature[0], message, &public_key);

  RETURN_BOOLEAN(result)
}

NAN_METHOD(schnorr_recover) {
  Nan::HandleScope scope;

  HANDLE_ARG_SCHNORR_SIGNATURE(0)
  HANDLE_ARG_MESSAGE(1)
  HANDLE_ARG_COMPRESSED(2)

  secp256k1_pubkey public_key;
  if (secp256k1_schnorr_recover(secp256k1ctx, &public_key, &signature[0], message) == 0) {
    return Nan::ThrowError(SCHNORR_RECOVER_FAIL);
  }

  RETURN_PUBLIC_KEY(public_key)
}

NAN_METHOD(schnorr_generate_nonce_pair) {
  Nan::HandleScope scope;

  HANDLE_ARG_MESSAGE(0)
  HANDLE_ARG_PRIVATE_KEY(1)
  HANDLE_ARG_NONCE_FUNCTION(2)
  HANDLE_ARG_NONCE_DATA(3)
  HANDLE_ARG_COMPRESSED(4)

  secp256k1_pubkey pubnonce;
  unsigned char privnonce[32];
  if (secp256k1_schnorr_generate_nonce_pair(secp256k1ctx, &pubnonce, &privnonce[0], message, private_key, noncefn, noncedata) == 0) {
    return Nan::ThrowError(SCHNORR_GENERATE_NONCE_PAIR_FAIL);
  }

  unsigned char pubnonce_output[65];
  size_t pubnonce_output_length = 65;
  secp256k1_ec_pubkey_serialize(secp256k1ctx, &pubnonce_output[0], &pubnonce_output_length, &pubnonce, compressed);

  v8::Local<v8::Object> obj = Nan::New<v8::Object>();
  obj->Set(NEW_STRING("pubnonce"), COPY_BUFFER(&pubnonce_output[0], pubnonce_output_length));
  obj->Set(NEW_STRING("privnonce"), COPY_BUFFER(&privnonce[0], 32));
  info.GetReturnValue().Set(obj);
}

NAN_METHOD(schnorr_partial_sign) {
  Nan::HandleScope scope;

  HANDLE_ARG_MESSAGE(0)
  HANDLE_ARG_PRIVATE_KEY(1)

  // pubnonce
  v8::Local<v8::Object> pubnonce_buffer = info[2].As<v8::Object>();
  CHECK_TYPE_BUFFER(pubnonce_buffer, EC_PUBLIC_KEY_TYPE_INVALID)
  CHECK_BUFFER_LENGTH2(pubnonce_buffer, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID)
  const unsigned char* pubnonce_raw = (const unsigned char*) node::Buffer::Data(pubnonce_buffer);
  size_t pubnonce_raw_length = node::Buffer::Length(pubnonce_buffer);

  secp256k1_pubkey pubnonce;
  if (secp256k1_ec_pubkey_parse(secp256k1ctx, &pubnonce, pubnonce_raw, pubnonce_raw_length) == 0) {
    return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);
  }

  // privnonce
  v8::Local<v8::Object> privnonce_buffer = info[3].As<v8::Object>();
  CHECK_TYPE_BUFFER(privnonce_buffer, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(privnonce_buffer, 32, EC_PRIVATE_KEY_LENGTH_INVALID);
  const unsigned char* privnonce = (const unsigned char*) node::Buffer::Data(privnonce_buffer);

  // combine
  unsigned char signature[64];
  if (secp256k1_schnorr_partial_sign(secp256k1ctx, &signature[0], message, private_key, &pubnonce, privnonce) != 1) {
    return Nan::ThrowError(SCHNORR_PARTIAL_SIGN_FAIL);
  }

  info.GetReturnValue().Set(COPY_BUFFER(&signature[0], 64));
}

NAN_METHOD(schnorr_partial_combine) {
  Nan::HandleScope scope;

  v8::Local<v8::Array> signature_buffers = info[0].As<v8::Array>();
  CHECK_TYPE_ARRAY(signature_buffers, SCHNORR_SIGNATURES_TYPE_INVALID);
  CHECK_LENGTH_GT_ZERO(signature_buffers, SCHNORR_SIGNATURES_LENGTH_INVALID);
  unsigned int signatures_count = signature_buffers->Length();

  std::unique_ptr<unsigned char*[]> signatures(new unsigned char*[signatures_count]);
  for (unsigned int i = 0; i < signatures_count; ++i) {
    v8::Local<v8::Object> signature_buffer = v8::Local<v8::Object>::Cast(signature_buffers->Get(i));
    CHECK_TYPE_BUFFER(signature_buffer, SCHNORR_SIGNATURE_TYPE_INVALID);
    CHECK_BUFFER_LENGTH(signature_buffer, 64, SCHNORR_SIGNATURE_LENGTH_INVALID);

    signatures[i] = (unsigned char*) node::Buffer::Data(signature_buffer);
  }

  unsigned char signature[64];
  if (secp256k1_schnorr_partial_combine(secp256k1ctx, &signature[0], signatures.get(), signatures_count) != 1) {
    return Nan::ThrowError(SCHNORR_PARTIAL_COMBINE_FAIL);
  }

  info.GetReturnValue().Set(COPY_BUFFER(&signature[0], 64));
}
