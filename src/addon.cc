#include <node.h>
#include <nan.h>
#include <secp256k1.h>

#include "privatekey.h"
#include "publickey.h"
#include "signature.h"
#include "ecdsa.h"
#include "ecdh.h"

secp256k1_context* secp256k1ctx;

#include "messages.h"
#include "util.h"

class KeyObject : public Nan::ObjectWrap {
  public:
    static NAN_MODULE_INIT(Init) {
      v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
      tpl->SetClassName(Nan::New("KeyObject").ToLocalChecked());
      tpl->InstanceTemplate()->SetInternalFieldCount(1);

      Nan::SetPrototypeMethod(tpl, "serialize", serialize);

      constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
    }

    int create (const unsigned char* seckey) {
      return secp256k1_ec_pubkey_create(secp256k1ctx, &pubkey_, seckey);
    }

    static v8::Local<v8::Object> NewInstance() {
      v8::Local<v8::Function> cons = Nan::New(constructor());
      v8::Local<v8::Value> argv[0];
      return Nan::NewInstance(cons, 0, argv).ToLocalChecked();
    }

  private:
    static inline Nan::Persistent<v8::Function> & constructor() {
      static Nan::Persistent<v8::Function> my_constructor;
      return my_constructor;
    }

    static NAN_METHOD(New) {
      if (info.IsConstructCall()) {
        KeyObject *obj = new KeyObject();
        obj->Wrap(info.This());
        info.GetReturnValue().Set(info.This());
      } else {
        v8::Local<v8::Function> cons = Nan::New(constructor());
        v8::Local<v8::Value> argv[0] = {};
        info.GetReturnValue().Set(Nan::NewInstance(cons, 0, argv).ToLocalChecked());
      }
    }

    static NAN_METHOD(serialize) {
      Nan::HandleScope scope;

      KeyObject* obj = Nan::ObjectWrap::Unwrap<KeyObject>(info.This());

      unsigned int flags = SECP256K1_EC_COMPRESSED;
      v8::Local<v8::Value> compressed = info[0].As<v8::Value>();
      if (!compressed->IsUndefined()) {
        CHECK_TYPE_BOOLEAN(compressed, COMPRESSED_TYPE_INVALID);
        if (!compressed->BooleanValue()) {
          flags = SECP256K1_EC_UNCOMPRESSED;
        }
      }

      unsigned char output[65];
      size_t outputlen = 65;
      secp256k1_ec_pubkey_serialize(secp256k1ctx, &output[0], &outputlen, &(obj->pubkey_), flags);

      info.GetReturnValue().Set(COPY_BUFFER(&output[0], outputlen));
    }

    secp256k1_pubkey pubkey_;
};

NAN_METHOD(publicKeyCreateNew) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> seckey_buffer = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(seckey_buffer, EC_PRIVKEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(seckey_buffer, 32, EC_PRIVKEY_LENGTH_INVALID);
  const unsigned char* seckey = (const unsigned char*) node::Buffer::Data(seckey_buffer);

  v8::Local<v8::Object> obj = KeyObject::NewInstance();
  if (Nan::ObjectWrap::Unwrap<KeyObject>(obj)->create(seckey) == 0) {
    return Nan::ThrowError(EC_PUBKEY_CREATE_FAIL);
  }

  info.GetReturnValue().Set(obj);
}

NAN_MODULE_INIT(Init) {
  secp256k1ctx = secp256k1_context_create(
    SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

  KeyObject::Init(target);

  // secret key
  Nan::Export(target, "privateKeyVerify", privateKeyVerify);
  Nan::Export(target, "privateKeyExport", privateKeyExport);
  Nan::Export(target, "privateKeyImport", privateKeyImport);
  Nan::Export(target, "privateKeyNegate", privateKeyNegate);
  Nan::Export(target, "privateKeyModInverse", privateKeyModInverse);
  Nan::Export(target, "privateKeyTweakAdd", privateKeyTweakAdd);
  Nan::Export(target, "privateKeyTweakMul", privateKeyTweakMul);

  // public key
  Nan::Export(target, "publicKeyCreate", publicKeyCreate);
  Nan::Export(target, "publicKeyCreateNew", publicKeyCreateNew);
  Nan::Export(target, "publicKeyConvert", publicKeyConvert);
  Nan::Export(target, "publicKeyVerify", publicKeyVerify);
  Nan::Export(target, "publicKeyTweakAdd", publicKeyTweakAdd);
  Nan::Export(target, "publicKeyTweakMul", publicKeyTweakMul);
  Nan::Export(target, "publicKeyCombine", publicKeyCombine);

  // signature
  Nan::Export(target, "signatureNormalize", signatureNormalize);
  Nan::Export(target, "signatureExport", signatureExport);
  Nan::Export(target, "signatureImport", signatureImport);
  Nan::Export(target, "signatureImportLax", signatureImportLax);

  // ecdsa
  Nan::Export(target, "sign", sign);
  Nan::Export(target, "verify", verify);
  Nan::Export(target, "recover", recover);

  // ecdh
  Nan::Export(target, "ecdh", ecdh);
  Nan::Export(target, "ecdhUnsafe", ecdhUnsafe);
}

NODE_MODULE(secp256k1, Init)
