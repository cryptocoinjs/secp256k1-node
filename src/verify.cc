#include <node.h>
#include <nan.h>
#include <secp256k1.h>

#include "messages.h"
#include "util.h"


extern secp256k1_context* secp256k1ctx;

class VerifyWorker : public Nan::AsyncWorker {
  public:
    VerifyWorker(v8::Local<v8::Object> msg32_buffer, v8::Local<v8::Object> sig_buffer, v8::Local<v8::Object> pubkey_buffer, Nan::Callback* callback)
      : Nan::AsyncWorker(callback), msg32_buffer(msg32_buffer), sig_buffer(sig_buffer), pubkey_buffer(pubkey_buffer) {}

    void Execute () {
      CHECK_ASYNC(msg32_buffer->IsUint8Array(), MSG32_TYPE_INVALID);
      CHECK_ASYNC(node::Buffer::Length(msg32_buffer) == 32, MSG32_LENGTH_INVALID);

      CHECK_ASYNC(sig_buffer->IsUint8Array(), ECDSA_SIGNATURE_TYPE_INVALID);
      CHECK_ASYNC(node::Buffer::Length(sig_buffer) == 64, ECDSA_SIGNATURE_LENGTH_INVALID);

      secp256k1_ecdsa_signature sig;
      const unsigned char* sig_input = (unsigned char*) node::Buffer::Data(sig_buffer);
      if (secp256k1_ecdsa_signature_parse_compact(secp256k1ctx, &sig, sig_input) == 0) {
        return SetErrorMessage(ECDSA_SIGNATURE_PARSE_FAIL);
      }

      CHECK_ASYNC(pubkey_buffer->IsUint8Array(), EC_PUBKEY_TYPE_INVALID);
      CHECK_ASYNC(node::Buffer::Length(pubkey_buffer) == 33 || node::Buffer::Length(pubkey_buffer) == 65, EC_PUBKEY_LENGTH_INVALID);

      secp256k1_pubkey pubkey;
      const unsigned char* pubkey_input = (unsigned char*) node::Buffer::Data(pubkey_buffer);
      size_t pubkey_inputlen = node::Buffer::Length(pubkey_buffer);
      if (secp256k1_ec_pubkey_parse(secp256k1ctx, &pubkey, pubkey_input, pubkey_inputlen) == 0) {
        return SetErrorMessage(EC_PUBKEY_PARSE_FAIL);
      }

      const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(msg32_buffer);
      result = secp256k1_ecdsa_verify(secp256k1ctx, &sig, msg32, &pubkey);
    }

    void HandleOKCallback () {
      Nan::HandleScope scope;

      v8::Local<v8::Value> argv[] = {
        Nan::Null(),
        Nan::New<v8::Boolean>(result)
      };

      callback->Call(2, argv);
    }

  protected:
    v8::Local<v8::Object> msg32_buffer;
    v8::Local<v8::Object> sig_buffer;
    v8::Local<v8::Object> pubkey_buffer;
    int result;
};


NAN_METHOD(verify) {
  Nan::HandleScope scope;

  v8::Local<v8::Function> callback = info[2].As<v8::Function>();
  CHECK(callback->IsFunction(), CALLBACK_TYPE_INVALID);

  VerifyWorker* worker = new VerifyWorker(
    info[0].As<v8::Object>(),
    info[1].As<v8::Object>(),
    info[2].As<v8::Object>(),
    new Nan::Callback(callback));

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(verifySync) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> msg32_buffer = info[0].As<v8::Object>();
  CHECK(msg32_buffer->IsUint8Array(), MSG32_TYPE_INVALID);
  CHECK(node::Buffer::Length(msg32_buffer) == 32, MSG32_LENGTH_INVALID);

  v8::Local<v8::Object> sig_buffer = info[1].As<v8::Object>();
  CHECK(sig_buffer->IsUint8Array(), ECDSA_SIGNATURE_TYPE_INVALID);
  CHECK(node::Buffer::Length(sig_buffer) == 64, ECDSA_SIGNATURE_LENGTH_INVALID);

  secp256k1_ecdsa_signature sig;
  const unsigned char* sig_input = (unsigned char*) node::Buffer::Data(sig_buffer);
  if (secp256k1_ecdsa_signature_parse_compact(secp256k1ctx, &sig, sig_input) == 0) {
    return Nan::ThrowError(ECDSA_SIGNATURE_PARSE_FAIL);
  }

  v8::Local<v8::Object> pubkey_buffer = info[2].As<v8::Object>();
  CHECK(pubkey_buffer->IsUint8Array(), EC_PUBKEY_TYPE_INVALID);
  CHECK(node::Buffer::Length(pubkey_buffer) == 33 || node::Buffer::Length(pubkey_buffer) == 65, EC_PUBKEY_LENGTH_INVALID);

  secp256k1_pubkey pubkey;
  const unsigned char* pubkey_input = (unsigned char*) node::Buffer::Data(pubkey_buffer);
  size_t pubkey_inputlen = node::Buffer::Length(pubkey_buffer);
  if (secp256k1_ec_pubkey_parse(secp256k1ctx, &pubkey, pubkey_input, pubkey_inputlen) == 0) {
    return Nan::ThrowError(EC_PUBKEY_PARSE_FAIL);
  }

  const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(msg32_buffer);
  int result = secp256k1_ecdsa_verify(secp256k1ctx, &sig, msg32, &pubkey);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
