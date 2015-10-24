#include <nan.h>
#include <node.h>

#include "./util.h"
#include "./functions.h"
using namespace v8;


NAN_MODULE_INIT(Init){ 
  secp256k1ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

  Nan::Set(target, Nan::New<String>("sign").ToLocalChecked(), Nan::New<FunctionTemplate>(Sign)->GetFunction());
  Nan::Set(target, Nan::New<String>("recover").ToLocalChecked(), Nan::New<FunctionTemplate>(Recover)->GetFunction());
  Nan::Set(target, Nan::New<String>("verify").ToLocalChecked(), Nan::New<FunctionTemplate>(Verify)->GetFunction());
  Nan::Set(target, Nan::New<String>("secKeyVerify").ToLocalChecked(), Nan::New<FunctionTemplate>(Seckey_Verify)->GetFunction());
  Nan::Set(target, Nan::New<String>("pubKeyCreate").ToLocalChecked(), Nan::New<FunctionTemplate>(Pubkey_Create)->GetFunction());
  Nan::Set(target, Nan::New<String>("privKeyExport").ToLocalChecked(), Nan::New<FunctionTemplate>(Privkey_Export)->GetFunction());
  Nan::Set(target, Nan::New<String>("privKeyImport").ToLocalChecked(), Nan::New<FunctionTemplate>(Privkey_Import)->GetFunction());
  Nan::Set(target, Nan::New<String>("privKeyTweakAdd").ToLocalChecked(), Nan::New<FunctionTemplate>(Privkey_Tweak_Add)->GetFunction());
  Nan::Set(target, Nan::New<String>("privKeyTweakMul").ToLocalChecked(), Nan::New<FunctionTemplate>(Privkey_Tweak_Mul)->GetFunction());
  Nan::Set(target, Nan::New<String>("pubKeyTweakAdd").ToLocalChecked(), Nan::New<FunctionTemplate>(Pubkey_Tweak_Add)->GetFunction());
  Nan::Set(target, Nan::New<String>("pubKeyTweakMul").ToLocalChecked(), Nan::New<FunctionTemplate>(Pubkey_Tweak_Mul)->GetFunction());
}
NODE_MODULE(secp256k1, Init)
