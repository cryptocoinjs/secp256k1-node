#include <node.h>
#include <nan.h>
#include <secp256k1.h>

#include "messages.h"
#include "util.h"

extern secp256k1_context* secp256k1ctx;

NAN_METHOD(publicKeyCreate) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> seckey_buffer = info[0].As<v8::Object>();
  if (node::Buffer::Length(seckey_buffer) != 32) {
    return Nan::ThrowError(PRIVKEY_LENGTH_INVALID);
  }

  secp256k1_pubkey pubkey;
  const unsigned char* seckey = (const unsigned char*) node::Buffer::Data(seckey_buffer);
  int results = secp256k1_ec_pubkey_create(secp256k1ctx, &pubkey, seckey);
  if(results == 0) {
    return Nan::ThrowError(EC_PUBKEY_CREATE_FAIL);
  }

  unsigned char output[33];
  size_t outputlen;
  secp256k1_ec_pubkey_serialize(secp256k1ctx, &output[0], &outputlen, &pubkey, SECP256K1_EC_COMPRESSED);

  info.GetReturnValue().Set(copyBuffer((const char*) &output[0], 33));
}

NAN_METHOD(publicKeyConvert) {
  Nan::HandleScope scope;

  secp256k1_pubkey pubkey;
  if (pubkey_buffer_parse(info[0].As<v8::Object>(), &pubkey) == 0) {
    return Nan::ThrowError(EC_PUBKEY_PARSE_FAIL);
  }

  unsigned char output[65];
  size_t outputlen;
  unsigned int flags = info[1]->BooleanValue() ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
  secp256k1_ec_pubkey_serialize(secp256k1ctx, &output[0], &outputlen, &pubkey, flags);

  info.GetReturnValue().Set(copyBuffer((const char*) &output[0], outputlen));
}

NAN_METHOD(publicKeyVerify) {
  Nan::HandleScope scope;

  secp256k1_pubkey pubkey;
  int result = pubkey_buffer_parse(info[0].As<v8::Object>(), &pubkey);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(publicKeyTweakAdd) {
  Nan::HandleScope scope;

  secp256k1_pubkey pubkey;
  if (pubkey_buffer_parse(info[0].As<v8::Object>(), &pubkey) == 0) {
    return Nan::ThrowError(EC_PUBKEY_PARSE_FAIL);
  }

  v8::Local<v8::Object> tweak_buffer = info[1].As<v8::Object>();
  if (node::Buffer::Length(tweak_buffer) != 32) {
    return Nan::ThrowError(TWEAK_LENGTH_INVALID);
  }

  const unsigned char* tweak = (const unsigned char *) node::Buffer::Data(tweak_buffer);
  int results = secp256k1_ec_pubkey_tweak_add(secp256k1ctx, &pubkey, tweak);
  if (results == 0) {
    return Nan::ThrowError(EC_PUBKEY_TWEAK_ADD_FAIL);
  }

  unsigned char output[33];
  size_t outputlen;
  secp256k1_ec_pubkey_serialize(secp256k1ctx, &output[0], &outputlen, &pubkey, SECP256K1_EC_COMPRESSED);

  info.GetReturnValue().Set(copyBuffer((const char*) &output[0], outputlen));
}

NAN_METHOD(publicKeyTweakMul) {
  Nan::HandleScope scope;

  secp256k1_pubkey pubkey;
  if (pubkey_buffer_parse(info[0].As<v8::Object>(), &pubkey) == 0) {
    return Nan::ThrowError(EC_PUBKEY_PARSE_FAIL);
  }

  v8::Local<v8::Object> tweak_buffer = info[1].As<v8::Object>();
  if (node::Buffer::Length(tweak_buffer) != 32) {
    return Nan::ThrowError(TWEAK_LENGTH_INVALID);
  }

  const unsigned char* tweak = (const unsigned char *) node::Buffer::Data(tweak_buffer);
  int results = secp256k1_ec_pubkey_tweak_mul(secp256k1ctx, &pubkey, tweak);
  if (results == 0) {
    return Nan::ThrowError(EC_PUBKEY_TWEAK_MUL_FAIL);
  }

  unsigned char output[33];
  size_t outputlen;
  secp256k1_ec_pubkey_serialize(secp256k1ctx, &output[0], &outputlen, &pubkey, SECP256K1_EC_COMPRESSED);

  info.GetReturnValue().Set(copyBuffer((const char*) &output[0], outputlen));
}

NAN_METHOD(publicKeyCombine) {
  Nan::HandleScope scope;

  v8::Local<v8::Array> buffers = info[0].As<v8::Array>();
  secp256k1_pubkey* public_keys = new secp256k1_pubkey[buffers->Length()];
  secp256k1_pubkey** ins = new secp256k1_pubkey*[buffers->Length()];
  for (unsigned int i = 0; i < buffers->Length(); ++i) {
    ins[i] = &public_keys[i];

    if (pubkey_buffer_parse(v8::Local<v8::Object>::Cast(buffers->Get(i)), ins[i]) == 0) {
      return Nan::ThrowError(EC_PUBKEY_PARSE_FAIL);
    }
  }

  secp256k1_pubkey pubkey;
  int result = secp256k1_ec_pubkey_combine(secp256k1ctx, &pubkey, ins, buffers->Length());
  delete[] public_keys;
  delete[] ins;
  if (result == 0) {
    return Nan::ThrowError(EC_PUBKEY_COMBINE_FAIL);
  }

  unsigned char output[33];
  size_t outputlen;
  secp256k1_ec_pubkey_serialize(secp256k1ctx, &output[0], &outputlen, &pubkey, SECP256K1_EC_COMPRESSED);

  info.GetReturnValue().Set(copyBuffer((const char*) &output[0], outputlen));
}
