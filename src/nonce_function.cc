#include <node.h>
#include <nan.h>

#include "util.h"

v8::Local<v8::Function> noncefn_callback;
int nonce_function_custom(unsigned char* nonce32, const unsigned char* msg32, const unsigned char* key32, const unsigned char* algo16, void* data, unsigned int attempt) {
  v8::Local<v8::Value> argv[] = {
    COPY_BUFFER(msg32, 32),
    COPY_BUFFER(key32, 32),
    algo16 == NULL ? v8::Local<v8::Value>(Nan::Null()) : v8::Local<v8::Value>(COPY_BUFFER(algo16, 16)),
    data == NULL ? v8::Local<v8::Value>(Nan::Null()) : v8::Local<v8::Value>(COPY_BUFFER(data, 32)),
    Nan::New(attempt)
  };

  v8::Isolate *isolate = v8::Isolate::GetCurrent();
  v8::Local<v8::Value> result = noncefn_callback->Call(isolate->GetCurrentContext()->Global(), 5, argv);

  if (!node::Buffer::HasInstance(result) || node::Buffer::Length(result) != 32) {
    return 0;
  }

  memcpy(nonce32, node::Buffer::Data(result), 32);
  return 1;
}
