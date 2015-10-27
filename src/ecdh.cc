#include <node.h>
#include <nan.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#include "messages.h"
#include "util.h"


extern secp256k1_context* secp256k1ctx;

class ECDHWorker : public Nan::AsyncWorker {
  public:
    ECDHWorker(v8::Local<v8::Object> pubkey_buffer, v8::Local<v8::Object> seckey_buffer, Nan::Callback* callback)
      : Nan::AsyncWorker(callback), pubkey_buffer(pubkey_buffer), seckey_buffer(seckey_buffer) {}

    void Execute () {
      secp256k1_pubkey pubkey;
      if (pubkey_buffer_parse(pubkey_buffer, &pubkey) == 0) {
        return SetErrorMessage(EC_PUBKEY_PARSE_FAIL);
      }

      if (node::Buffer::Length(seckey_buffer) != 32) {
        return SetErrorMessage(PRIVKEY_LENGTH_INVALID);
      }

      const unsigned char* seckey = (const unsigned char*) node::Buffer::Data(seckey_buffer);
      if (secp256k1_ecdh(secp256k1ctx, &output[0], &pubkey, seckey) == 0) {
        return SetErrorMessage(ECDH_FAIL);
      }
    }

    void HandleOKCallback () {
      Nan::HandleScope scope;

      v8::Local<v8::Value> argv[] = {
        Nan::Null(),
        copyBuffer((const char*) &output[0], 32)
      };

      callback->Call(2, argv);
    }

  protected:
    v8::Local<v8::Object> pubkey_buffer;
    v8::Local<v8::Object> seckey_buffer;
    unsigned char output[32];
};

NAN_METHOD(ecdh) {
  Nan::HandleScope scope;

  ECDHWorker* worker = new ECDHWorker(
    info[0].As<v8::Object>(),
    info[1].As<v8::Object>(),
    new Nan::Callback(info[2].As<v8::Function>()));

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(ecdhSync) {
  Nan::HandleScope scope;

  secp256k1_pubkey pubkey;
  if (pubkey_buffer_parse(info[0].As<v8::Object>(), &pubkey) == 0) {
    return Nan::ThrowError(EC_PUBKEY_PARSE_FAIL);
  }

  v8::Local<v8::Object> seckey_buffer = info[1].As<v8::Object>();
  if (node::Buffer::Length(seckey_buffer) != 32) {
    return Nan::ThrowError(PRIVKEY_LENGTH_INVALID);
  }

  unsigned char output[32];
  const unsigned char* seckey = (const unsigned char*) node::Buffer::Data(seckey_buffer);
  if (secp256k1_ecdh(secp256k1ctx, &output[0], &pubkey, seckey) == 0) {
    return Nan::ThrowError(ECDH_FAIL);
  }

  info.GetReturnValue().Set(copyBuffer((const char*) &output[0], 32));
}
