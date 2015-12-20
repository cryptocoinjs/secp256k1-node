#ifndef _SECP256K1_NODE_UTIL_
# define _SECP256K1_NODE_UTIL_

#include <node.h>
#include <nan.h>

#include "messages.h"


#define COPY_BUFFER(data, datalen) Nan::CopyBuffer((const char*) data, datalen).ToLocalChecked()

#define UPDATE_COMPRESSED_VALUE(compressed, obj, v_true, v_false) {            \
  if (!obj->IsUndefined()) {                                                   \
    CHECK_TYPE_BOOLEAN(obj, COMPRESSED_TYPE_INVALID);                          \
    compressed = obj->BooleanValue() ? v_true : v_false;                       \
  }                                                                            \
}

// Type checks (TypeError)
#define CHECK_TYPE_BUFFER(buffer, msg) {                                       \
  if (!node::Buffer::HasInstance(buffer)) {                                    \
    return Nan::ThrowTypeError(msg);                                           \
  }                                                                            \
}

#define CHECK_TYPE_BOOLEAN(obj, msg) {                                         \
  if (!obj->IsBoolean() && !obj->IsBooleanObject()) {                          \
    return Nan::ThrowTypeError(msg);                                           \
  }                                                                            \
}

#define CHECK_TYPE_FUNCTION(obj, msg) {                                        \
  if (!obj->IsFunction()) {                                                    \
    return Nan::ThrowTypeError(msg);                                           \
  }                                                                            \
}

#define CHECK_TYPE_NUMBER(obj, msg) {                                          \
  if (!obj->IsNumber() && !obj->IsNumberObject()) {                            \
    return Nan::ThrowTypeError(msg);                                           \
  }                                                                            \
}

#define CHECK_TYPE_ARRAY(obj, msg) {                                           \
  if (!obj->IsArray()) {                                                       \
    return Nan::ThrowTypeError(msg);                                           \
  }                                                                            \
}

#define CHECK_TYPE_OBJECT(obj, msg) {                                          \
  if (!obj->IsObject()) {                                                      \
    return Nan::ThrowTypeError(msg);                                           \
  }                                                                            \
}

// Length checks (RangeError)
#define CHECK_BUFFER_LENGTH_GT_ZERO(buffer, msg) {                             \
  if (node::Buffer::Length(buffer) == 0) {                                     \
    return Nan::ThrowRangeError(msg);                                          \
  }                                                                            \
}

#define CHECK_BUFFER_LENGTH(buffer, length, msg) {                             \
  if (node::Buffer::Length(buffer) != length) {                                \
    return Nan::ThrowRangeError(msg);                                          \
  }                                                                            \
}

#define CHECK_BUFFER_LENGTH2(buffer, length1, length2, msg) {                  \
  if (node::Buffer::Length(buffer) != length1 &&                               \
      node::Buffer::Length(buffer) != length2) {                               \
    return Nan::ThrowRangeError(msg);                                          \
  }                                                                            \
}

#define CHECK_LENGTH_GT_ZERO(obj, msg) {                                       \
  if (obj->Length() == 0) {                                                    \
    return Nan::ThrowRangeError(msg);                                          \
  }                                                                            \
}

#define CHECK_NUMBER_IN_INTERVAL(number, x, y, msg) {                          \
  if (number->IntegerValue() <= x || number->IntegerValue() >= y) {            \
    return Nan::ThrowRangeError(msg);                                          \
  }                                                                            \
}

#endif
