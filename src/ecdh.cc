#include <node.h>
#include <nan.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#include "messages.h"
#include "util.h"


extern secp256k1_context* secp256k1ctx;

class ECDHWorker : public Nan::AsyncWorker {
  public:
    ECDHWorker(v8::Local<v8::Object> pubkey_buffer, const unsigned char* seckey, Nan::Callback* callback)
      : Nan::AsyncWorker(callback), pubkey_buffer(pubkey_buffer), seckey(seckey) {}

    void Execute () {
      secp256k1_pubkey pubkey;
      if (pubkey_buffer_parse(pubkey_buffer, &pubkey) == 0) {
        return SetErrorMessage(EC_PUBKEY_PARSE_FAIL);
      }

      if (secp256k1_ecdh(secp256k1ctx, &output[0], &pubkey, &seckey[0]) == 0) {
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
    const unsigned char* seckey;
    unsigned char output[32];
};

NAN_METHOD(ecdh) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> pubkey_buffer = info[0].As<v8::Object>();
  const unsigned char* seckey = (const unsigned char*) node::Buffer::Data(info[1]);
  Nan::Callback* callback = new Nan::Callback(info[2].As<v8::Function>());

  ECDHWorker* worker = new ECDHWorker(pubkey_buffer, seckey, callback);
  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(ecdhSync) {
  Nan::HandleScope scope;

  secp256k1_pubkey pubkey;
  if (pubkey_buffer_parse(info[0].As<v8::Object>(), &pubkey) == 0) {
    return Nan::ThrowError(EC_PUBKEY_PARSE_FAIL);
  }

  unsigned char output[32];
  const unsigned char* seckey = (const unsigned char*) node::Buffer::Data(info[1]);
  if (secp256k1_ecdh(secp256k1ctx, &output[0], &pubkey, &seckey[0]) == 0) {
    return Nan::ThrowError(ECDH_FAIL);
  }

  info.GetReturnValue().Set(copyBuffer((const char*) &output[0], 32));
}
