#ifndef _SECP256K1_NODE_UTIL_
# define _SECP256K1_NODE_UTIL_

#include <node.h>
#include <nan.h>
#include <secp256k1.h>

#include "messages.h"

// TypeError
#define CHECK_TYPE_ARRAY(value, message) \
  if (!value->IsArray()) { \
    return Nan::ThrowTypeError(message); \
  }

#define CHECK_TYPE_BOOLEAN(value, message) \
  if (!value->IsBoolean() && !value->IsBooleanObject()) { \
    return Nan::ThrowTypeError(message); \
  }

#define CHECK_TYPE_BUFFER(value, message) \
  if (!node::Buffer::HasInstance(value)) { \
    return Nan::ThrowTypeError(message); \
  }

#define CHECK_TYPE_FUNCTION(value, message) \
  if (!value->IsFunction()) { \
    return Nan::ThrowTypeError(message); \
  }

#define CHECK_TYPE_NUMBER(value, message) \
  if (!value->IsNumber() && !value->IsNumberObject()) { \
    return Nan::ThrowTypeError(message); \
  }

// RangeError
#define CHECK_BUFFER_LENGTH(buffer, length, message) \
  if (node::Buffer::Length(buffer) != length) { \
    return Nan::ThrowRangeError(message); \
  }

#define CHECK_BUFFER_LENGTH2(buffer, length1, length2, message) \
  if (node::Buffer::Length(buffer) != length1 && \
      node::Buffer::Length(buffer) != length2) { \
    return Nan::ThrowRangeError(message); \
  }

#define CHECK_BUFFER_LENGTH_GT_ZERO(buffer, message) \
  if (node::Buffer::Length(buffer) == 0) { \
    return Nan::ThrowRangeError(message); \
  }

#define CHECK_LENGTH_GT_ZERO(value, message) \
  if (value->Length() == 0) { \
    return Nan::ThrowRangeError(message); \
  }

#define CHECK_NUMBER_IN_INTERVAL(number, x, y, message) \
  if (number->IntegerValue() < x || number->IntegerValue() > y) { \
    return Nan::ThrowRangeError(message); \
  }

// arguments
#define HANDLE_ARG_BUFFER(index, name, msg) \
  v8::Local<v8::Object> name##_buffer = info[index].As<v8::Object>(); \
  CHECK_TYPE_BUFFER(name##_buffer, msg); \
  const unsigned char* name = (const unsigned char*) node::Buffer::Data(name##_buffer);

#define HANDLE_ARG_PRIVATE_KEY(index) \
  HANDLE_ARG_BUFFER(index, private_key, EC_PRIVATE_KEY_TYPE_INVALID) \
  CHECK_BUFFER_LENGTH(private_key_buffer, 32, EC_PRIVATE_KEY_LENGTH_INVALID)

#define HANDLE_ARG_PUBLIC_KEY(index) \
  HANDLE_ARG_BUFFER(index, public_key_raw, EC_PUBLIC_KEY_TYPE_INVALID) \
  CHECK_BUFFER_LENGTH2(public_key_raw_buffer, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID) \
  size_t public_key_raw_length = node::Buffer::Length(public_key_raw_buffer); \
  secp256k1_pubkey public_key; \
  if (secp256k1_ec_pubkey_parse(secp256k1ctx, &public_key, public_key_raw, public_key_raw_length) == 0) { \
    return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL); \
  }

#define HANDLE_ARG_COMPRESSED(index) \
  unsigned int compressed = SECP256K1_EC_COMPRESSED; \
  if (!info[index]->IsUndefined()) { \
    CHECK_TYPE_BOOLEAN(info[index], COMPRESSED_TYPE_INVALID); \
    if (!info[index]->BooleanValue()) compressed = SECP256K1_EC_UNCOMPRESSED; \
  }

#define HANDLE_ARG_TWEAK(index) \
  HANDLE_ARG_BUFFER(index, tweak, TWEAK_TYPE_INVALID) \
  CHECK_BUFFER_LENGTH(tweak_buffer, 32, TWEAK_LENGTH_INVALID)

#define HANDLE_ARG_MESSAGE(index) \
  HANDLE_ARG_BUFFER(index, message, MESSAGE_TYPE_INVALID) \
  CHECK_BUFFER_LENGTH(message_buffer, 32, MESSAGE_LENGTH_INVALID)

#define HANDLE_ARG_ECDSA_SIGNATURE(index) \
  HANDLE_ARG_ECDSA_SIGNATURE_RAW(index) \
  secp256k1_ecdsa_signature signature; \
  if (secp256k1_ecdsa_signature_parse_compact(secp256k1ctx, &signature, signature_raw) == 0) { \
    return Nan::ThrowError(ECDSA_SIGNATURE_PARSE_FAIL); \
  }

#define HANDLE_ARG_ECDSA_SIGNATURE_RAW(index) \
  HANDLE_ARG_BUFFER(index, signature_raw, ECDSA_SIGNATURE_TYPE_INVALID) \
  CHECK_BUFFER_LENGTH(signature_raw_buffer, 64, ECDSA_SIGNATURE_LENGTH_INVALID)

#define HANDLE_ARG_ECDSA_SIGNATURE_DER(index) \
  HANDLE_ARG_BUFFER(index, signature_der, ECDSA_SIGNATURE_TYPE_INVALID) \
  CHECK_BUFFER_LENGTH_GT_ZERO(signature_der_buffer, ECDSA_SIGNATURE_LENGTH_INVALID) \
  size_t signature_der_length = node::Buffer::Length(signature_der_buffer);

#define HANDLE_ARG_SCHNORR_SIGNATURE(index) \
  HANDLE_ARG_BUFFER(index, signature, SCHNORR_SIGNATURE_TYPE_INVALID) \
  CHECK_BUFFER_LENGTH(signature_buffer, 64, SCHNORR_SIGNATURE_LENGTH_INVALID)

#define HANDLE_ARG_NONCE_FUNCTION(index) \
  secp256k1_nonce_function noncefn = secp256k1_nonce_function_rfc6979; \
  noncefn_callback = info[index].As<v8::Function>(); \
  if (!noncefn_callback->IsUndefined()) { \
    CHECK_TYPE_FUNCTION(noncefn_callback, NONCE_FUNCTION_TYPE_INVALID); \
    noncefn = nonce_function_custom; \
  }

#define HANDLE_ARG_NONCE_DATA(index) \
  const unsigned char *noncedata = NULL; \
  v8::Local<v8::Object> noncedata_buffer = info[index].As<v8::Object>(); \
  if (!noncedata_buffer->IsUndefined()) { \
    CHECK_TYPE_BUFFER(noncedata_buffer, NONCE_DATA_TYPE_INVALID) \
    CHECK_BUFFER_LENGTH(noncedata_buffer, 32, NONCE_DATA_LENGTH_INVALID) \
    noncedata = (const unsigned char*) node::Buffer::Data(noncedata_buffer); \
  }

// return's
#define RETURN_BOOLEAN(value) info.GetReturnValue().Set(Nan::New<v8::Boolean>(value));

#define RETURN_BUFFER(data, data_length) info.GetReturnValue().Set(COPY_BUFFER(data, data_length));

#define RETURN_PUBLIC_KEY(public_key) \
  unsigned char public_key##_output[65]; \
  size_t public_key##_output_length = 65; \
  secp256k1_ec_pubkey_serialize(secp256k1ctx, &public_key##_output[0], &public_key##_output_length, &public_key, compressed); \
  RETURN_BUFFER(public_key##_output, public_key##_output_length)

// shortcuts
#define NEW_STRING(x) Nan::New<v8::String>(x).ToLocalChecked()

#define COPY_BUFFER(data, data_length) Nan::CopyBuffer((const char*) data, (uint32_t) data_length).ToLocalChecked()

#endif
