#include <node.h>
#include <nan.h>
#include <secp256k1.h>
#include <util.h>
#include <field_impl.h>
#include <scalar_impl.h>
#include <group_impl.h>
#include <ecmult_const_impl.h>
#include <ecmult_gen_impl.h>

#include "messages.h"
#include "util.h"

NAN_METHOD(sha256) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(buf, "Buffer expected.");
  const unsigned char* data = (unsigned char*) node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  secp256k1_sha256_t sha;
  unsigned char output[32];

  secp256k1_sha256_initialize(&sha);
  secp256k1_sha256_write(&sha, data, len);
  secp256k1_sha256_finalize(&sha, &output[0]);

  info.GetReturnValue().Set(COPY_BUFFER(&output[0], 32));
}

NAN_METHOD(dsha256) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(buf, "Buffer expected.");
  const unsigned char* data = (unsigned char*) node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  secp256k1_sha256_t sha;
  unsigned char output[32];

  secp256k1_sha256_initialize(&sha);
  secp256k1_sha256_write(&sha, data, len);
  secp256k1_sha256_finalize(&sha, &output[0]);

  secp256k1_sha256_initialize(&sha);
  secp256k1_sha256_write(&sha, output, 32);
  secp256k1_sha256_finalize(&sha, &output[0]);

  info.GetReturnValue().Set(COPY_BUFFER(&output[0], 32));
}
