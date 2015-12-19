#include <node.h>
#include <nan.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#include "messages.h"
#include "util.h"


extern secp256k1_context* secp256k1ctx;

NAN_METHOD(ecdh) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> pubkey_buffer = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(pubkey_buffer, EC_PUBLIC_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH2(pubkey_buffer, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID);
  const unsigned char* public_key_input = (unsigned char*) node::Buffer::Data(pubkey_buffer);
  size_t public_key_input_length = node::Buffer::Length(pubkey_buffer);

  v8::Local<v8::Object> private_key_buffer = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(private_key_buffer, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(private_key_buffer, 32, EC_PRIVATE_KEY_LENGTH_INVALID);
  const unsigned char* private_key = (const unsigned char*) node::Buffer::Data(private_key_buffer);

  secp256k1_pubkey public_key;
  if (secp256k1_ec_pubkey_parse(secp256k1ctx, &public_key, public_key_input, public_key_input_length) == 0) {
    return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);
  }

  unsigned char output[32];
  if (secp256k1_ecdh(secp256k1ctx, &output[0], &public_key, private_key) == 0) {
    return Nan::ThrowError(ECDH_FAIL);
  }

  info.GetReturnValue().Set(COPY_BUFFER(&output[0], 32));
}
