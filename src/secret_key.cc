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
  if (node::Buffer::Length(seckey_buffer) != 32) {
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
  }

  const unsigned char* seckey = (const unsigned char*) node::Buffer::Data(seckey_buffer);
  int result = secp256k1_ec_seckey_verify(secp256k1ctx, seckey);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(secretKeyExport) {
  Nan::HandleScope scope;
  return Nan::ThrowError("Not implemented now.");
}

NAN_METHOD(secretKeyImport) {
  Nan::HandleScope scope;
  return Nan::ThrowError("Not implemented now.");
}

NAN_METHOD(secretKeyTweakAdd) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> seckey_buffer = info[0].As<v8::Object>();
  if (node::Buffer::Length(seckey_buffer) != 32) {
    return Nan::ThrowError(PRIVKEY_LENGTH_INVALID);
  }

  v8::Local<v8::Object> tweak_buffer = info[1].As<v8::Object>();
  if (node::Buffer::Length(tweak_buffer) != 32) {
    return Nan::ThrowError(TWEAK_LENGTH_INVALID);
  }

  unsigned char* seckey = (unsigned char *) node::Buffer::Data(seckey_buffer);
  const unsigned char* tweak = (unsigned char *) node::Buffer::Data(tweak_buffer);
  int results = secp256k1_ec_privkey_tweak_add(secp256k1ctx, seckey, tweak);
  if (results == 0) {
    return Nan::ThrowError(EC_PRIVKEY_TWEAK_ADD_FAIL);
  }

  info.GetReturnValue().Set(copyBuffer((const char*) seckey, 32));
}

NAN_METHOD(secretKeyTweakMul) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> seckey_buffer = info[0].As<v8::Object>();
  if (node::Buffer::Length(seckey_buffer) != 32) {
    return Nan::ThrowError(PRIVKEY_LENGTH_INVALID);
  }

  v8::Local<v8::Object> tweak_buffer = info[1].As<v8::Object>();
  if (node::Buffer::Length(tweak_buffer) != 32) {
    return Nan::ThrowError(TWEAK_LENGTH_INVALID);
  }

  unsigned char* seckey = (unsigned char *) node::Buffer::Data(seckey_buffer);
  const unsigned char* tweak = (unsigned char *) node::Buffer::Data(tweak_buffer);
  int results = secp256k1_ec_privkey_tweak_mul(secp256k1ctx, seckey, tweak);
  if (results == 0) {
    return Nan::ThrowError(EC_PRIVKEY_TWEAK_MUL_FAIL);
  }

  info.GetReturnValue().Set(copyBuffer((const char*) seckey, 32));
}
