#include <node.h>
#include <nan.h>
#include <secp256k1.h>

#include "messages.h"
#include "util.h"


extern secp256k1_context* secp256k1ctx;

class VerifyWorker : public Nan::AsyncWorker {
  public:
    VerifyWorker(v8::Local<v8::Object> sig_buffer, v8::Local<v8::Object> msg32_buffer, v8::Local<v8::Object> pubkey_buffer, Nan::Callback* callback)
      : Nan::AsyncWorker(callback), sig_buffer(sig_buffer), msg32_buffer(msg32_buffer), pubkey_buffer(pubkey_buffer) {}

    void Execute () {
      secp256k1_ecdsa_signature sig;
      if (signature_buffer_parse(sig_buffer, &sig) == 0) {
        return SetErrorMessage(ECDSA_SIGNATURE_PARSE_FAIL);
      }

      if (node::Buffer::Length(msg32_buffer) != 32) {
        return SetErrorMessage(MSG32_LENGTH_INVALID);
      }

      secp256k1_pubkey pubkey;
      if (pubkey_buffer_parse(pubkey_buffer, &pubkey) == 0) {
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
    v8::Local<v8::Object> sig_buffer;
    v8::Local<v8::Object> msg32_buffer;
    v8::Local<v8::Object> pubkey_buffer;
    int result;
};


NAN_METHOD(verify) {
  Nan::HandleScope scope;

  VerifyWorker* worker = new VerifyWorker(
    info[0].As<v8::Object>(),
    info[1].As<v8::Object>(),
    info[2].As<v8::Object>(),
    new Nan::Callback(info[3].As<v8::Function>()));

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(verifySync) {
  Nan::HandleScope scope;

  secp256k1_ecdsa_signature sig;
  if (signature_buffer_parse(info[1].As<v8::Object>(), &sig) == 0) {
    return Nan::ThrowError(ECDSA_SIGNATURE_PARSE_FAIL);
  }

  v8::Local<v8::Object> msg32_buffer = info[0].As<v8::Object>();
  if (node::Buffer::Length(msg32_buffer) != 32) {
    return Nan::ThrowError(MSG32_LENGTH_INVALID);
  }

  secp256k1_pubkey pubkey;
  if (pubkey_buffer_parse(info[2].As<v8::Object>(), &pubkey) == 0) {
    return Nan::ThrowError(EC_PUBKEY_PARSE_FAIL);
  }

  const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(msg32_buffer);
  int result = secp256k1_ecdsa_verify(secp256k1ctx, &sig, msg32, &pubkey);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
