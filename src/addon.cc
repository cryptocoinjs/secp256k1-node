#include <node.h>
#include <nan.h>
#include <secp256k1.h>

#include "privatekey.h"
#include "publickey.h"
#include "ecdsa.h"
#include "ecdsa_signature.h"
#include "schnorr.h"
#include "ecdh.h"
#include "util.h"

secp256k1_context* secp256k1ctx;

NAN_MODULE_INIT(Init) {
  secp256k1ctx = secp256k1_context_create(
    SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

  v8::Local<v8::Object> private_key = Nan::New<v8::Object>();
  Nan::SetMethod(private_key, "verify", private_key_verify);
  Nan::SetMethod(private_key, "export", private_key_export);
  Nan::SetMethod(private_key, "import", private_key_import);
  Nan::SetMethod(private_key, "tweakAdd", private_key_tweak_add);
  Nan::SetMethod(private_key, "tweakMul", private_key_tweak_mul);

  v8::Local<v8::Object> public_key = Nan::New<v8::Object>();
  Nan::SetMethod(public_key, "create", public_key_create);
  Nan::SetMethod(public_key, "convert", public_key_convert);
  Nan::SetMethod(public_key, "verify", public_key_verify);
  Nan::SetMethod(public_key, "tweakAdd", public_key_tweak_add);
  Nan::SetMethod(public_key, "tweakMul", public_key_tweak_mul);
  Nan::SetMethod(public_key, "combine", public_key_combine);

  v8::Local<v8::Object> ecdsa_signature = Nan::New<v8::Object>();
  Nan::SetMethod(ecdsa_signature, "normalize", ecdsa_signature_normalize);
  Nan::SetMethod(ecdsa_signature, "export", ecdsa_signature_export);
  Nan::SetMethod(ecdsa_signature, "import", ecdsa_signature_import);
  Nan::SetMethod(ecdsa_signature, "importLax", ecdsa_signature_import_lax);

  v8::Local<v8::Object> ecdsa = Nan::New<v8::Object>();
  ecdsa->Set(NEW_STRING("signature"), ecdsa_signature);
  Nan::SetMethod(ecdsa, "sign", ecdsa_sign);
  Nan::SetMethod(ecdsa, "verify", ecdsa_verify);
  Nan::SetMethod(ecdsa, "recover", ecdsa_recover);

  v8::Local<v8::Object> schnorr = Nan::New<v8::Object>();
  Nan::SetMethod(schnorr, "sign", schnorr_sign);
  Nan::SetMethod(schnorr, "verify", schnorr_verify);
  Nan::SetMethod(schnorr, "recover", schnorr_recover);
  Nan::SetMethod(schnorr, "generateNoncePair", schnorr_generate_nonce_pair);
  Nan::SetMethod(schnorr, "partialSign", schnorr_partial_sign);
  Nan::SetMethod(schnorr, "partialCombine", schnorr_partial_combine);

  v8::Local<v8::Object> ecdh = Nan::New<v8::Object>();
  Nan::SetMethod(ecdh, "sha256", ecdh_sha256);
  Nan::SetMethod(ecdh, "unsafe", ecdh_unsafe);

  target->Set(NEW_STRING("privateKey"), private_key);
  target->Set(NEW_STRING("publicKey"), public_key);
  target->Set(NEW_STRING("ecdsa"), ecdsa);
  target->Set(NEW_STRING("schnorr"), schnorr);
  target->Set(NEW_STRING("ecdh"), ecdh);
}

NODE_MODULE(secp256k1, Init)
