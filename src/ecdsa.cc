#include <node.h>
#include <nan.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "nonce_function.h"
#include "messages.h"
#include "util.h"

extern secp256k1_context* secp256k1ctx;
extern v8::Local<v8::Function> noncefn_callback;

NAN_METHOD(ecdsa_sign) {
  Nan::HandleScope scope;

  HANDLE_ARG_MESSAGE(0)
  HANDLE_ARG_PRIVATE_KEY(1)
  HANDLE_ARG_NONCE_FUNCTION(2)
  HANDLE_ARG_NONCE_DATA(3)

  secp256k1_ecdsa_recoverable_signature sig;
  if (secp256k1_ecdsa_sign_recoverable(secp256k1ctx, &sig, message, private_key, noncefn, noncedata) == 0) {
    return Nan::ThrowError(ECDSA_SIGN_FAIL);
  }

  unsigned char output[64];
  int recid;
  secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1ctx, &output[0], &recid, &sig);

  v8::Local<v8::Object> obj = Nan::New<v8::Object>();
  obj->Set(NEW_STRING("signature"), COPY_BUFFER(&output[0], 64));
  obj->Set(NEW_STRING("recovery"), Nan::New<v8::Number>(recid));
  info.GetReturnValue().Set(obj);
}

NAN_METHOD(ecdsa_verify) {
  Nan::HandleScope scope;

  HANDLE_ARG_ECDSA_SIGNATURE(0)
  HANDLE_ARG_MESSAGE(1)
  HANDLE_ARG_PUBLIC_KEY(2)

  int result = secp256k1_ecdsa_verify(secp256k1ctx, &signature, message, &public_key);
  RETURN_BOOLEAN(result)
}

NAN_METHOD(ecdsa_recover) {
  Nan::HandleScope scope;

  HANDLE_ARG_ECDSA_SIGNATURE_RAW(0)
  HANDLE_ARG_MESSAGE(2)
  HANDLE_ARG_COMPRESSED(3)

  v8::Local<v8::Object> recid_object = info[1].As<v8::Object>();
  CHECK_TYPE_NUMBER(recid_object, ECDSA_RECOVERY_ID_TYPE_INVALID);
  CHECK_NUMBER_IN_INTERVAL(recid_object, 0, 3, ECDSA_RECOVERY_ID_VALUE_INVALID);
  int recid = (int) recid_object->IntegerValue();

  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1ctx, &signature, signature_raw, recid) == 0) {
    return Nan::ThrowError(ECDSA_SIGNATURE_PARSE_FAIL);
  }

  secp256k1_pubkey public_key;
  if (secp256k1_ecdsa_recover(secp256k1ctx, &public_key, &signature, message) == 0) {
    return Nan::ThrowError(ECDSA_RECOVER_FAIL);
  }

  RETURN_PUBLIC_KEY(public_key)
}
