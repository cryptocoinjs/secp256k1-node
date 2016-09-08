#include <memory>
#include <node.h>
#include <nan.h>
#include <secp256k1.h>
#include <secp256k1_schnorr.h>

#include "messages.h"
#include "util.h"

extern secp256k1_context* secp256k1ctx;

static v8::Local<v8::Function> noncefn_callback;
static int nonce_function_custom(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
  v8::Local<v8::Value> argv[] = {
    COPY_BUFFER(msg32, 32),
    COPY_BUFFER(key32, 32),
    algo16 == NULL ? v8::Local<v8::Value>(Nan::Null()) : v8::Local<v8::Value>(COPY_BUFFER(algo16, 16)),
    data == NULL ? v8::Local<v8::Value>(Nan::Null()) : v8::Local<v8::Value>(COPY_BUFFER(data, 32)),
    Nan::New(counter)
  };

#if (NODE_MODULE_VERSION > NODE_0_10_MODULE_VERSION)
  v8::Isolate *isolate = v8::Isolate::GetCurrent();
  v8::Local<v8::Value> result = noncefn_callback->Call(isolate->GetCurrentContext()->Global(), 5, argv);
#else
  v8::Local<v8::Value> result = noncefn_callback->Call(v8::Context::GetCurrent()->Global(), 5, argv);
#endif

  if (!node::Buffer::HasInstance(result) || node::Buffer::Length(result) != 32) {
    return 0;
  }

  memcpy(nonce32, node::Buffer::Data(result), 32);
  return 1;
}

NAN_METHOD(schnorrSign) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> msg32_buffer = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(msg32_buffer, MSG32_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(msg32_buffer, 32, MSG32_LENGTH_INVALID);
  const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(msg32_buffer);

  v8::Local<v8::Object> private_buffer = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(private_buffer, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(private_buffer, 32, EC_PRIVATE_KEY_LENGTH_INVALID);
  const unsigned char* private_key = (const unsigned char*) node::Buffer::Data(private_buffer);

  secp256k1_nonce_function noncefn = secp256k1_nonce_function_rfc6979;
  void* data = NULL;
  v8::Local<v8::Object> options = info[2].As<v8::Object>();
  if (!options->IsUndefined()) {
    CHECK_TYPE_OBJECT(options, OPTIONS_TYPE_INVALID);

    v8::Local<v8::Value> data_value = options->Get(Nan::New<v8::String>("data").ToLocalChecked());
    if (!data_value->IsUndefined()) {
      CHECK_TYPE_BUFFER(data_value, OPTIONS_DATA_TYPE_INVALID);
      CHECK_BUFFER_LENGTH(data_value, 32, OPTIONS_DATA_LENGTH_INVALID);
      data = (void*) node::Buffer::Data(data_value);
    }

    noncefn_callback = v8::Local<v8::Function>::Cast(options->Get(Nan::New<v8::String>("noncefn").ToLocalChecked()));
    if (!noncefn_callback->IsUndefined()) {
      CHECK_TYPE_FUNCTION(noncefn_callback, OPTIONS_NONCEFN_TYPE_INVALID);
      noncefn = nonce_function_custom;
    }
  }

  unsigned char sig[64];
  if (secp256k1_schnorr_sign(secp256k1ctx, &sig[0], msg32, private_key, noncefn, data) == 0) {
    return Nan::ThrowError(SCHNORR_SIGN_FAIL);
  }

  info.GetReturnValue().Set(COPY_BUFFER(&sig[0], 64));
}

NAN_METHOD(schnorrVerify) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> msg32_buffer = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(msg32_buffer, MSG32_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(msg32_buffer, 32, MSG32_LENGTH_INVALID);
  const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(msg32_buffer);

  v8::Local<v8::Object> sig_input_buffer = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(sig_input_buffer, SCHNORR_SIGNATURE_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(sig_input_buffer, 64, SCHNORR_SIGNATURE_LENGTH_INVALID);
  const unsigned char* sig_input = (unsigned char*) node::Buffer::Data(sig_input_buffer);

  v8::Local<v8::Object> public_key_buffer = info[2].As<v8::Object>();
  CHECK_TYPE_BUFFER(public_key_buffer, EC_PUBLIC_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH2(public_key_buffer, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID);
  const unsigned char* public_key_input = (unsigned char*) node::Buffer::Data(public_key_buffer);
  size_t public_key_input_length = node::Buffer::Length(public_key_buffer);

  secp256k1_pubkey public_key;
  if (secp256k1_ec_pubkey_parse(secp256k1ctx, &public_key, public_key_input, public_key_input_length) == 0) {
    return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);
  }

  int result = secp256k1_schnorr_verify(secp256k1ctx, sig_input, msg32, &public_key);
  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(schnorrRecover) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> msg32_buffer = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(msg32_buffer, MSG32_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(msg32_buffer, 32, MSG32_LENGTH_INVALID);
  const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(msg32_buffer);

  v8::Local<v8::Object> sig_input_buffer = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(sig_input_buffer, SCHNORR_SIGNATURE_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(sig_input_buffer, 64, SCHNORR_SIGNATURE_LENGTH_INVALID);
  const unsigned char* sig_input = (unsigned char*) node::Buffer::Data(sig_input_buffer);

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  UPDATE_COMPRESSED_VALUE(flags, info[2], SECP256K1_EC_COMPRESSED, SECP256K1_EC_UNCOMPRESSED);

  secp256k1_pubkey public_key;
  if (secp256k1_schnorr_recover(secp256k1ctx, &public_key, sig_input, msg32) == 0) {
    return Nan::ThrowError(SCHNORR_RECOVER_FAIL);
  }

  unsigned char output[65];
  size_t output_length = 65;
  secp256k1_ec_pubkey_serialize(secp256k1ctx, &output[0], &output_length, &public_key, flags);
  info.GetReturnValue().Set(COPY_BUFFER(&output[0], output_length));
}

NAN_METHOD(schnorrGenerateNoncePair) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> msg32_buffer = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(msg32_buffer, MSG32_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(msg32_buffer, 32, MSG32_LENGTH_INVALID);
  const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(msg32_buffer);

  v8::Local<v8::Object> private_buffer = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(private_buffer, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(private_buffer, 32, EC_PRIVATE_KEY_LENGTH_INVALID);
  const unsigned char* private_key = (const unsigned char*) node::Buffer::Data(private_buffer);

  secp256k1_nonce_function noncefn = secp256k1_nonce_function_rfc6979;
  void* data = NULL;
  v8::Local<v8::Object> options = info[2].As<v8::Object>();
  unsigned int flags = SECP256K1_EC_COMPRESSED;
  if (!options->IsUndefined()) {
    CHECK_TYPE_OBJECT(options, OPTIONS_TYPE_INVALID);

    v8::Local<v8::Value> data_value = options->Get(Nan::New<v8::String>("data").ToLocalChecked());
    if (!data_value->IsUndefined()) {
      CHECK_TYPE_BUFFER(data_value, OPTIONS_DATA_TYPE_INVALID);
      CHECK_BUFFER_LENGTH(data_value, 32, OPTIONS_DATA_LENGTH_INVALID);
      data = (void*) node::Buffer::Data(data_value);
    }

    noncefn_callback = v8::Local<v8::Function>::Cast(options->Get(Nan::New<v8::String>("noncefn").ToLocalChecked()));
    if (!noncefn_callback->IsUndefined()) {
      CHECK_TYPE_FUNCTION(noncefn_callback, OPTIONS_NONCEFN_TYPE_INVALID);
      noncefn = nonce_function_custom;
    }

    v8::Local<v8::Value> compressed_value = options->Get(Nan::New<v8::String>("compressed").ToLocalChecked());
    UPDATE_COMPRESSED_VALUE(flags, compressed_value, SECP256K1_EC_COMPRESSED, SECP256K1_EC_UNCOMPRESSED);
  }

  secp256k1_pubkey pubnonce;
  unsigned char privnonce[32];
  if (secp256k1_schnorr_generate_nonce_pair(secp256k1ctx, &pubnonce, &privnonce[0], msg32, private_key, noncefn, data) == 0) {
    return Nan::ThrowError(SCHNORR_SIGN_FAIL);
  }

  unsigned char pubnonce_output[65];
  size_t pubnonce_output_length = 65;
  secp256k1_ec_pubkey_serialize(secp256k1ctx, &pubnonce_output[0], &pubnonce_output_length, &pubnonce, flags);
  info.GetReturnValue().Set(COPY_BUFFER(&pubnonce_output[0], pubnonce_output_length));

  v8::Local<v8::Object> obj = Nan::New<v8::Object>();
  obj->Set(Nan::New<v8::String>("pubNonce").ToLocalChecked(), COPY_BUFFER(&pubnonce_output[0], pubnonce_output_length));
  obj->Set(Nan::New<v8::String>("privNonce").ToLocalChecked(), COPY_BUFFER(&privnonce[0], 32));
  info.GetReturnValue().Set(obj);
}

NAN_METHOD(schnorrPartialSign) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> msg32_buffer = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(msg32_buffer, MSG32_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(msg32_buffer, 32, MSG32_LENGTH_INVALID);
  const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(msg32_buffer);

  v8::Local<v8::Object> private_buffer = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(private_buffer, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(private_buffer, 32, EC_PRIVATE_KEY_LENGTH_INVALID);
  const unsigned char* private_key = (const unsigned char*) node::Buffer::Data(private_buffer);

  v8::Local<v8::Object> input_buffer = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(input_buffer, EC_PUBLIC_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH2(input_buffer, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID);
  const unsigned char* input = (unsigned char*) node::Buffer::Data(input_buffer);
  size_t input_length = node::Buffer::Length(input_buffer);

  v8::Local<v8::Object> privnonce_buffer = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(privnonce_buffer, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(privnonce_buffer, 32, EC_PRIVATE_KEY_LENGTH_INVALID);
  const unsigned char* privnonce = (const unsigned char*) node::Buffer::Data(privnonce_buffer);

  secp256k1_pubkey pubnonce;
  if (secp256k1_ec_pubkey_parse(secp256k1ctx, &pubnonce, input, input_length) == 0) {
    return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);
  }

  unsigned char sig[64];
  if (secp256k1_schnorr_partial_sign(secp256k1ctx, &sig[0], msg32, private_key, &pubnonce, privnonce) < 1) {
    return Nan::ThrowError(SCHNORR_PARTIAL_SIGN_FAIL);
  }

  info.GetReturnValue().Set(COPY_BUFFER(&sig[0], 64));
}

NAN_METHOD(schnorrPartialCombine) {
  Nan::HandleScope scope;

  v8::Local<v8::Array> input_buffers = info[0].As<v8::Array>();
  CHECK_TYPE_ARRAY(input_buffers, SCHNORR_SIGNATURES_TYPE_INVALID);
  CHECK_LENGTH_GT_ZERO(input_buffers, SCHNORR_SIGNATURES_LENGTH_INVALID);

  std::unique_ptr<unsigned char*[]> pointers(new unsigned char*[input_buffers->Length()]);
  for (unsigned int i = 0; i < input_buffers->Length(); ++i) {
    v8::Local<v8::Object> input_buffer = v8::Local<v8::Object>::Cast(input_buffers->Get(i));
    CHECK_TYPE_BUFFER(input_buffer, SCHNORR_SIGNATURE_TYPE_INVALID);
    CHECK_BUFFER_LENGTH(input_buffer, 64, SCHNORR_SIGNATURE_LENGTH_INVALID);

    pointers[i] = (unsigned char*) node::Buffer::Data(input_buffer);
  }

  unsigned char sig[64];
  if (secp256k1_schnorr_partial_combine(secp256k1ctx, &sig[0], pointers.get(), input_buffers->Length()) == 0) {
    return Nan::ThrowError(SCHNORR_PARTIAL_COMBINE_FAIL);
  }

  info.GetReturnValue().Set(COPY_BUFFER(&sig[0], 64));
}
