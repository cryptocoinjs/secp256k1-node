#include <node.h>
#include <nan.h>
#include <secp256k1.h>
// #include <lax_der_privatekey_parsing.h>

#include "messages.h"
#include "util.h"


extern secp256k1_context* secp256k1ctx;

NAN_METHOD(secretKeyVerify) {
  Nan::HandleScope scope;

  const unsigned char* seckey = (const unsigned char*) node::Buffer::Data(info[0]);
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

  unsigned char* seckey = (unsigned char *) node::Buffer::Data(info[0].As<v8::Object>());
  const unsigned char* tweak = (unsigned char *) node::Buffer::Data(info[1].As<v8::Object>());
  int results = secp256k1_ec_privkey_tweak_add(secp256k1ctx, seckey, tweak);
  if (results == 0) {
    return Nan::ThrowError(EC_PRIVKEY_TWEAK_ADD_FAIL);
  }

  info.GetReturnValue().Set(copyBuffer((const char*) seckey, 32));
}

NAN_METHOD(secretKeyTweakMul) {
  Nan::HandleScope scope;

  unsigned char* seckey = (unsigned char *) node::Buffer::Data(info[0].As<v8::Object>());
  const unsigned char* tweak = (unsigned char *) node::Buffer::Data(info[1].As<v8::Object>());
  int results = secp256k1_ec_privkey_tweak_mul(secp256k1ctx, seckey, tweak);
  if (results == 0) {
    return Nan::ThrowError(EC_PRIVKEY_TWEAK_MUL_FAIL);
  }

  info.GetReturnValue().Set(copyBuffer((const char*) seckey, 32));
}
