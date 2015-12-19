#include <node.h>
#include <nan.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "messages.h"
#include "util.h"


extern secp256k1_context* secp256k1ctx;

NAN_METHOD(sign) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> msg32_buffer = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(msg32_buffer, MSG32_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(msg32_buffer, 32, MSG32_LENGTH_INVALID);
  const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(msg32_buffer);

  v8::Local<v8::Object> private_buffer = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(private_buffer, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(private_buffer, 32, EC_PRIVATE_KEY_LENGTH_INVALID);
  const unsigned char* private_key = (const unsigned char*) node::Buffer::Data(private_buffer);

  secp256k1_ecdsa_recoverable_signature sig;
  if (secp256k1_ecdsa_sign_recoverable(secp256k1ctx, &sig, msg32, private_key, NULL, NULL) == 0) {
    return Nan::ThrowError(ECDSA_SIGN_FAIL);
  }

  unsigned char output[64];
  int recid;
  secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1ctx, &output[0], &recid, &sig);

  v8::Local<v8::Object> obj = Nan::New<v8::Object>();
  obj->Set(Nan::New<v8::String>("signature").ToLocalChecked(), COPY_BUFFER(&output[0], 64));
  obj->Set(Nan::New<v8::String>("recovery").ToLocalChecked(), Nan::New<v8::Number>(recid));
  info.GetReturnValue().Set(obj);
}

NAN_METHOD(verify) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> msg32_buffer = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(msg32_buffer, MSG32_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(msg32_buffer, 32, MSG32_LENGTH_INVALID);
  const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(msg32_buffer);

  v8::Local<v8::Object> sig_input_buffer = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(sig_input_buffer, ECDSA_SIGNATURE_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(sig_input_buffer, 64, ECDSA_SIGNATURE_LENGTH_INVALID);
  const unsigned char* sig_input = (unsigned char*) node::Buffer::Data(sig_input_buffer);

  v8::Local<v8::Object> public_key_buffer = info[2].As<v8::Object>();
  CHECK_TYPE_BUFFER(public_key_buffer, EC_PUBLIC_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH2(public_key_buffer, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID);
  const unsigned char* public_key_input = (unsigned char*) node::Buffer::Data(public_key_buffer);
  size_t public_key_input_length = node::Buffer::Length(public_key_buffer);

  secp256k1_ecdsa_signature sig;
  if (secp256k1_ecdsa_signature_parse_compact(secp256k1ctx, &sig, sig_input) == 0) {
    return Nan::ThrowError(ECDSA_SIGNATURE_PARSE_FAIL);
  }

  secp256k1_pubkey public_key;
  if (secp256k1_ec_pubkey_parse(secp256k1ctx, &public_key, public_key_input, public_key_input_length) == 0) {
    return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);
  }

  int result = secp256k1_ecdsa_verify(secp256k1ctx, &sig, msg32, &public_key);
  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(recover) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> msg32_buffer = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(msg32_buffer, MSG32_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(msg32_buffer, 32, MSG32_LENGTH_INVALID);
  const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(msg32_buffer);

  v8::Local<v8::Object> sig_input_buffer = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(sig_input_buffer, ECDSA_SIGNATURE_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(sig_input_buffer, 64, ECDSA_SIGNATURE_LENGTH_INVALID);
  const unsigned char* sig_input = (unsigned char*) node::Buffer::Data(sig_input_buffer);

  v8::Local<v8::Object> recid_object = info[2].As<v8::Object>();
  CHECK_TYPE_NUMBER(recid_object, ECDSA_SIGNATURE_RECOVERY_ID_TYPE_INVALID);
  CHECK_NUMBER_IN_INTERVAL(recid_object, -1, 4, ECDSA_SIGNATURE_RECOVERY_ID_VALUE_INVALID);
  int recid = recid_object->IntegerValue();

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  UPDATE_COMPRESSED_VALUE(flags, info[3], SECP256K1_EC_COMPRESSED, SECP256K1_EC_UNCOMPRESSED);

  secp256k1_ecdsa_recoverable_signature sig;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1ctx, &sig, sig_input, recid) == 0) {
    return Nan::ThrowError(ECDSA_SIGNATURE_PARSE_FAIL);
  }

  secp256k1_pubkey public_key;
  if (secp256k1_ecdsa_recover(secp256k1ctx, &public_key, &sig, msg32) == 0) {
    return Nan::ThrowError(ECDSA_RECOVER_FAIL);
  }

  unsigned char output[65];
  size_t output_length = 65;
  secp256k1_ec_pubkey_serialize(secp256k1ctx, &output[0], &output_length, &public_key, flags);
  info.GetReturnValue().Set(COPY_BUFFER(&output[0], output_length));
}
