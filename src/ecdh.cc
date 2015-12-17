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
  CHECK_TYPE_BUFFER(pubkey_buffer, EC_PUBKEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH2(pubkey_buffer, 33, 65, EC_PUBKEY_LENGTH_INVALID);
  const unsigned char* pubkey_input = (unsigned char*) node::Buffer::Data(pubkey_buffer);
  size_t pubkey_inputlen = node::Buffer::Length(pubkey_buffer);

  v8::Local<v8::Object> seckey_buffer = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(seckey_buffer, EC_PRIVKEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(seckey_buffer, 32, EC_PRIVKEY_LENGTH_INVALID);
  const unsigned char* seckey = (const unsigned char*) node::Buffer::Data(seckey_buffer);

  secp256k1_pubkey pubkey;
  if (secp256k1_ec_pubkey_parse(secp256k1ctx, &pubkey, pubkey_input, pubkey_inputlen) == 0) {
    return Nan::ThrowError(EC_PUBKEY_PARSE_FAIL);
  }

  unsigned char output[32];
  if (secp256k1_ecdh(secp256k1ctx, &output[0], &pubkey, seckey) == 0) {
    return Nan::ThrowError(ECDH_FAIL);
  }

  info.GetReturnValue().Set(COPY_BUFFER(&output[0], 32));
}
