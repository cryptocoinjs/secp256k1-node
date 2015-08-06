#ifndef SYNC_H
#define SYNC_H

#include <nan.h>
#include <node.h>
using namespace v8;

NAN_METHOD(Verify);
NAN_METHOD(Sign);
NAN_METHOD(Recover);
NAN_METHOD(Seckey_Verify);
NAN_METHOD(Pubkey_Create);
NAN_METHOD(Privkey_Import);
NAN_METHOD(Privkey_Export);
NAN_METHOD(Privkey_Tweak_Add);
NAN_METHOD(Privkey_Tweak_Mul);
NAN_METHOD(Pubkey_Tweak_Add);
NAN_METHOD(Pubkey_Tweak_Mul);

#endif
