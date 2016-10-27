#include <memory>
#include <node.h>
#include <nan.h>
#include <secp256k1.h>

#include "messages.h"
#include "util.h"

extern secp256k1_context* secp256k1ctx;

NAN_METHOD(public_key_create) {
  Nan::HandleScope scope;

  HANDLE_ARG_PRIVATE_KEY(0)
  HANDLE_ARG_COMPRESSED(1)

  secp256k1_pubkey public_key;
  if (secp256k1_ec_pubkey_create(secp256k1ctx, &public_key, private_key) == 0) {
    return Nan::ThrowError(EC_PUBLIC_KEY_CREATE_FAIL);
  }

  RETURN_PUBLIC_KEY(public_key)
}

NAN_METHOD(public_key_convert) {
  Nan::HandleScope scope;

  HANDLE_ARG_PUBLIC_KEY(0)
  HANDLE_ARG_COMPRESSED(1)

  RETURN_PUBLIC_KEY(public_key)
}

NAN_METHOD(public_key_verify) {
  Nan::HandleScope scope;

  HANDLE_ARG_BUFFER(0, public_key_raw, EC_PUBLIC_KEY_TYPE_INVALID)
  size_t public_key_raw_length = node::Buffer::Length(public_key_raw_buffer);

  secp256k1_pubkey public_key;
  int result = secp256k1_ec_pubkey_parse(secp256k1ctx, &public_key, public_key_raw, public_key_raw_length);

  RETURN_BOOLEAN(result)
}

NAN_METHOD(public_key_tweak_add) {
  Nan::HandleScope scope;

  HANDLE_ARG_PUBLIC_KEY(0)
  HANDLE_ARG_TWEAK(1)
  HANDLE_ARG_COMPRESSED(2)

  if (secp256k1_ec_pubkey_tweak_add(secp256k1ctx, &public_key, tweak) == 0) {
    return Nan::ThrowError(EC_PUBLIC_KEY_TWEAK_ADD_FAIL);
  }

  RETURN_PUBLIC_KEY(public_key)
}

NAN_METHOD(public_key_tweak_mul) {
  Nan::HandleScope scope;

  HANDLE_ARG_PUBLIC_KEY(0)
  HANDLE_ARG_TWEAK(1)
  HANDLE_ARG_COMPRESSED(2)

  if (secp256k1_ec_pubkey_tweak_mul(secp256k1ctx, &public_key, tweak) == 0) {
    return Nan::ThrowError(EC_PUBLIC_KEY_TWEAK_MUL_FAIL);
  }

  RETURN_PUBLIC_KEY(public_key)
}

NAN_METHOD(public_key_combine) {
  Nan::HandleScope scope;

  v8::Local<v8::Array> public_keys_raw_buffers = info[0].As<v8::Array>();
  CHECK_TYPE_ARRAY(public_keys_raw_buffers, EC_PUBLIC_KEYS_TYPE_INVALID);
  CHECK_LENGTH_GT_ZERO(public_keys_raw_buffers, EC_PUBLIC_KEYS_LENGTH_INVALID);
  unsigned int public_keys_count = public_keys_raw_buffers->Length();

  HANDLE_ARG_COMPRESSED(1)

  std::unique_ptr<secp256k1_pubkey[]> public_keys(new secp256k1_pubkey[public_keys_count]);
  std::unique_ptr<secp256k1_pubkey*[]> public_keys_ptrs(new secp256k1_pubkey*[public_keys_count]);
  for (unsigned int i = 0; i < public_keys_count; ++i) {
    v8::Local<v8::Object> public_key_raw_buffer = v8::Local<v8::Object>::Cast(public_keys_raw_buffers->Get(i));
    CHECK_TYPE_BUFFER(public_key_raw_buffer, EC_PUBLIC_KEY_TYPE_INVALID);
    CHECK_BUFFER_LENGTH2(public_key_raw_buffer, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID);
    const unsigned char* public_key_raw = (unsigned char*) node::Buffer::Data(public_key_raw_buffer);
    size_t public_key_raw_length = node::Buffer::Length(public_key_raw_buffer);

    if (secp256k1_ec_pubkey_parse(secp256k1ctx, &public_keys[i], public_key_raw, public_key_raw_length) == 0) {
      return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);
    }

    public_keys_ptrs[i] = &public_keys[i];
  }

  secp256k1_pubkey public_key;
  if (secp256k1_ec_pubkey_combine(secp256k1ctx, &public_key, public_keys_ptrs.get(), public_keys_count) == 0) {
    return Nan::ThrowError(EC_PUBLIC_KEY_COMBINE_FAIL);
  }

  RETURN_PUBLIC_KEY(public_key)
}
