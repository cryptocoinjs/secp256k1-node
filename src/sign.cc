#include <node.h>
#include <nan.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "messages.h"
#include "util.h"


extern secp256k1_context* secp256k1ctx;

class SignWorker : public Nan::AsyncWorker {
  public:
    SignWorker(v8::Local<v8::Object> msg32_buffer, v8::Local<v8::Object> seckey_buffer, Nan::Callback* callback)
      : Nan::AsyncWorker(callback), msg32_buffer(msg32_buffer), seckey_buffer(seckey_buffer) {}

    void Execute () {
      if (node::Buffer::Length(msg32_buffer) != 32) {
        return SetErrorMessage(MSG32_LENGTH_INVALID);
      }

      if (node::Buffer::Length(seckey_buffer) != 32) {
        return SetErrorMessage(PRIVKEY_LENGTH_INVALID);
      }

      secp256k1_ecdsa_recoverable_signature sig;
      const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(msg32_buffer);
      const unsigned char* seckey = (const unsigned char*) node::Buffer::Data(seckey_buffer);
      int result = secp256k1_ecdsa_sign_recoverable(secp256k1ctx, &sig, msg32, seckey, NULL, NULL);
      if (result == 0) {
        return SetErrorMessage(ECDSA_SIGN_FAIL);
      }

      secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1ctx, &output[0], &recid, &sig);
    }

    void HandleOKCallback () {
      Nan::HandleScope scope;

      v8::Local<v8::Object> obj = Nan::New<v8::Object>();
      obj->Set(Nan::New<v8::String>("signature").ToLocalChecked(), copyBuffer((const char* ) &output[0], 64));
      obj->Set(Nan::New<v8::String>("recovery").ToLocalChecked(), Nan::New<v8::Number>(recid));

      v8::Local<v8::Value> argv[] = {Nan::Null(), obj};

      callback->Call(2, argv);
    }

  protected:
    v8::Local<v8::Object> msg32_buffer;
    v8::Local<v8::Object> seckey_buffer;
    unsigned char output[64];
    int recid;
};

NAN_METHOD(sign) {
  Nan::HandleScope scope;

  SignWorker* worker = new SignWorker(
    info[0].As<v8::Object>(),
    info[1].As<v8::Object>(),
    new Nan::Callback(info[2].As<v8::Function>()));

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(signSync) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> msg32_buffer = info[0].As<v8::Object>();
  if (node::Buffer::Length(msg32_buffer) != 32) {
    return Nan::ThrowError(MSG32_LENGTH_INVALID);
  }

  v8::Local<v8::Object> seckey_buffer = info[1].As<v8::Object>();
  if (node::Buffer::Length(seckey_buffer) != 32) {
    return Nan::ThrowError(PRIVKEY_LENGTH_INVALID);
  }

  secp256k1_ecdsa_recoverable_signature sig;
  const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(msg32_buffer);
  const unsigned char* seckey = (const unsigned char*) node::Buffer::Data(seckey_buffer);
  int result = secp256k1_ecdsa_sign_recoverable(secp256k1ctx, &sig, msg32, seckey, NULL, NULL);
  if (result == 0) {
    return Nan::ThrowError(ECDSA_SIGN_FAIL);
  }

  unsigned char output[64];
  int recid;
  secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1ctx, &output[0], &recid, &sig);

  v8::Local<v8::Object> obj = Nan::New<v8::Object>();
  obj->Set(Nan::New<v8::String>("signature").ToLocalChecked(), copyBuffer((const char* ) &output[0], 64));
  obj->Set(Nan::New<v8::String>("recovery").ToLocalChecked(), Nan::New<v8::Number>(recid));
  info.GetReturnValue().Set(obj);
}