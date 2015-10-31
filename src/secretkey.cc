#include <node.h>
#include <nan.h>
#include <secp256k1.h>
// #include <lax_der_privatekey_parsing.h>

#include "messages.h"
#include "util.h"


extern secp256k1_context* secp256k1ctx;

NAN_METHOD(secretKeyVerify) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> seckey_buffer = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(seckey_buffer, EC_PRIVKEY_TYPE_INVALID);

  if (node::Buffer::Length(seckey_buffer) != 32) {
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
  }

  const unsigned char* seckey = (const unsigned char*) node::Buffer::Data(seckey_buffer);
  int result = secp256k1_ec_seckey_verify(secp256k1ctx, seckey);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(secretKeyExport) {
  Nan::HandleScope scope;
  // TODO
  return Nan::ThrowError("Not implemented now.");
}

NAN_METHOD(secretKeyImport) {
  Nan::HandleScope scope;
  // TODO
  return Nan::ThrowError("Not implemented now.");
}

NAN_METHOD(secretKeyTweakAdd) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> seckey_buffer = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(seckey_buffer, EC_PRIVKEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(seckey_buffer, 32, EC_PRIVKEY_LENGTH_INVALID);

  v8::Local<v8::Object> tweak_buffer = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(tweak_buffer, TWEAK_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(tweak_buffer, 32, TWEAK_LENGTH_INVALID);

  unsigned char* seckey = (unsigned char *) node::Buffer::Data(seckey_buffer);
  const unsigned char* tweak = (unsigned char *) node::Buffer::Data(tweak_buffer);
  if (secp256k1_ec_privkey_tweak_add(secp256k1ctx, seckey, tweak) == 0) {
    return Nan::ThrowError(EC_PRIVKEY_TWEAK_ADD_FAIL);
  }

  info.GetReturnValue().Set(COPY_BUFFER(seckey, 32));
}

NAN_METHOD(secretKeyTweakMul) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> seckey_buffer = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(seckey_buffer, EC_PRIVKEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(seckey_buffer, 32, EC_PRIVKEY_LENGTH_INVALID);

  v8::Local<v8::Object> tweak_buffer = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(tweak_buffer, TWEAK_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(tweak_buffer, 32, TWEAK_LENGTH_INVALID);

  unsigned char* seckey = (unsigned char *) node::Buffer::Data(seckey_buffer);
  const unsigned char* tweak = (unsigned char *) node::Buffer::Data(tweak_buffer);
  if (secp256k1_ec_privkey_tweak_mul(secp256k1ctx, seckey, tweak) == 0) {
    return Nan::ThrowError(EC_PRIVKEY_TWEAK_MUL_FAIL);
  }

  info.GetReturnValue().Set(COPY_BUFFER(seckey, 32));
}
