#include <secp256k1.h>
#include <secp256k1/include/secp256k1_ecdh.h>
#include <secp256k1/include/secp256k1_preallocated.h>
#include <secp256k1/include/secp256k1_recovery.h>

#include <vector>

// Local helpers
#define RETURN(result) return Napi::Number::New(info.Env(), result)

#define RETURN_INVERTED(result) RETURN(result == 1 ? 0 : 1)

#define RETURN_IF_ZERO(result, retcode)                                        \
  do {                                                                         \
    if (result == 0) {                                                         \
      RETURN(retcode);                                                         \
    }                                                                          \
  } while (0)

#define REQUIRE_UINT8_ARRAY(target, value, message)                            \
  do {                                                                         \
    const Napi::Value target##_value = (value);                                \
    if (!target##_value.IsTypedArray()) {                                      \
      Napi::TypeError::New(info.Env(), message).ThrowAsJavaScriptException();  \
      return info.Env().Undefined();                                           \
    }                                                                          \
                                                                               \
    (target) = target##_value.As<Napi::Uint8Array>();                          \
    if ((target).TypedArrayType() != napi_uint8_array) {                       \
      Napi::TypeError::New(info.Env(), message).ThrowAsJavaScriptException();  \
      return info.Env().Undefined();                                           \
    }                                                                          \
  } while (0)

#define REQUIRE_UINT8_ARRAY_EXACT(target, value, length, message)              \
  do {                                                                         \
    REQUIRE_UINT8_ARRAY(target, value, message);                               \
    if ((target).ByteLength() != static_cast<size_t>(length)) {                \
      Napi::RangeError::New(info.Env(), message).ThrowAsJavaScriptException(); \
      return info.Env().Undefined();                                           \
    }                                                                          \
  } while (0)

#define PUBKEY_SERIALIZE(retcode)                                              \
  do {                                                                         \
    size_t outputlen = output.Length();                                        \
    int flags =                                                                \
        outputlen == 33 ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED; \
    RETURN_IF_ZERO(secp256k1_ec_pubkey_serialize(                              \
                       this->ctx_, output.Data(), &outputlen, &pubkey, flags), \
                   retcode);                                                   \
  } while (0)

// Secp256k1
Napi::FunctionReference Secp256k1Addon::constructor;
unsigned int Secp256k1Addon::secp256k1_context_flags =
    SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY;

Napi::Value Secp256k1Addon::Init(Napi::Env env) {
  Napi::Function func = DefineClass(
      env,
      "Secp256k1Addon",
      {
          InstanceMethod("contextRandomize", &Secp256k1Addon::ContextRandomize),

          InstanceMethod("privateKeyVerify", &Secp256k1Addon::PrivateKeyVerify),
          InstanceMethod("privateKeyNegate", &Secp256k1Addon::PrivateKeyNegate),
          InstanceMethod("privateKeyTweakAdd",
                         &Secp256k1Addon::PrivateKeyTweakAdd),
          InstanceMethod("privateKeyTweakMul",
                         &Secp256k1Addon::PrivateKeyTweakMul),

          InstanceMethod("publicKeyVerify", &Secp256k1Addon::PublicKeyVerify),
          InstanceMethod("publicKeyCreate", &Secp256k1Addon::PublicKeyCreate),
          InstanceMethod("publicKeyConvert", &Secp256k1Addon::PublicKeyConvert),
          InstanceMethod("publicKeyNegate", &Secp256k1Addon::PublicKeyNegate),
          InstanceMethod("publicKeyCombine", &Secp256k1Addon::PublicKeyCombine),
          InstanceMethod("publicKeyTweakAdd",
                         &Secp256k1Addon::PublicKeyTweakAdd),
          InstanceMethod("publicKeyTweakMul",
                         &Secp256k1Addon::PublicKeyTweakMul),

          InstanceMethod("signatureNormalize",
                         &Secp256k1Addon::SignatureNormalize),
          InstanceMethod("signatureExport", &Secp256k1Addon::SignatureExport),
          InstanceMethod("signatureImport", &Secp256k1Addon::SignatureImport),

          InstanceMethod("ecdsaSign", &Secp256k1Addon::ECDSASign),
          InstanceMethod("ecdsaVerify", &Secp256k1Addon::ECDSAVerify),
          InstanceMethod("ecdsaRecover", &Secp256k1Addon::ECDSARecover),

          InstanceMethod("ecdh", &Secp256k1Addon::ECDH),
      });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}

Secp256k1Addon::Secp256k1Addon(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<Secp256k1Addon>(info) {
  ctx_ = secp256k1_context_create(secp256k1_context_flags);

  size_t size = secp256k1_context_preallocated_size(secp256k1_context_flags);
  Napi::MemoryManagement::AdjustExternalMemory(info.Env(), size);
}

void Secp256k1Addon::Finalize(Napi::Env env) {
  secp256k1_context_destroy(const_cast<secp256k1_context*>(ctx_));

  size_t size = secp256k1_context_preallocated_size(secp256k1_context_flags);
  Napi::MemoryManagement::AdjustExternalMemory(env, -size);
}

Napi::Value Secp256k1Addon::ContextRandomize(const Napi::CallbackInfo& info) {
  Napi::Uint8Array seed;
  const unsigned char* seed32 = NULL;
  if (!info[0].IsNull()) {
    REQUIRE_UINT8_ARRAY_EXACT(
        seed, info[0], 32, "seed must be a 32-byte Uint8Array");
    seed32 = seed.Data();
  }

  RETURN_INVERTED(secp256k1_context_randomize(
      const_cast<secp256k1_context*>(this->ctx_), seed32));
}

// PrivateKey
Napi::Value Secp256k1Addon::PrivateKeyVerify(const Napi::CallbackInfo& info) {
  Napi::Uint8Array seckey;
  REQUIRE_UINT8_ARRAY_EXACT(
      seckey, info[0], 32, "private key must be a 32-byte Uint8Array");

  RETURN_INVERTED(secp256k1_ec_seckey_verify(this->ctx_, seckey.Data()));
}

Napi::Value Secp256k1Addon::PrivateKeyNegate(const Napi::CallbackInfo& info) {
  Napi::Uint8Array seckey;
  REQUIRE_UINT8_ARRAY_EXACT(
      seckey, info[0], 32, "private key must be a 32-byte Uint8Array");

  RETURN_IF_ZERO(secp256k1_ec_privkey_negate(this->ctx_, seckey.Data()), 1);
  RETURN(0);
}

Napi::Value Secp256k1Addon::PrivateKeyTweakAdd(const Napi::CallbackInfo& info) {
  Napi::Uint8Array seckey;
  Napi::Uint8Array tweak;
  REQUIRE_UINT8_ARRAY_EXACT(
      seckey, info[0], 32, "private key must be a 32-byte Uint8Array");
  REQUIRE_UINT8_ARRAY_EXACT(
      tweak, info[1], 32, "tweak must be a 32-byte Uint8Array");

  RETURN_INVERTED(
      secp256k1_ec_privkey_tweak_add(this->ctx_, seckey.Data(), tweak.Data()));
}

Napi::Value Secp256k1Addon::PrivateKeyTweakMul(const Napi::CallbackInfo& info) {
  Napi::Uint8Array seckey;
  Napi::Uint8Array tweak;
  REQUIRE_UINT8_ARRAY_EXACT(
      seckey, info[0], 32, "private key must be a 32-byte Uint8Array");
  REQUIRE_UINT8_ARRAY_EXACT(
      tweak, info[1], 32, "tweak must be a 32-byte Uint8Array");

  RETURN_INVERTED(
      secp256k1_ec_privkey_tweak_mul(this->ctx_, seckey.Data(), tweak.Data()));
}

// PublicKey
Napi::Value Secp256k1Addon::PublicKeyVerify(const Napi::CallbackInfo& info) {
  auto input = info[0].As<Napi::Buffer<const unsigned char>>();

  secp256k1_pubkey pubkey;
  RETURN_IF_ZERO(secp256k1_ec_pubkey_parse(
                     this->ctx_, &pubkey, input.Data(), input.Length()),
                 1);
  RETURN(0);
}

Napi::Value Secp256k1Addon::PublicKeyCreate(const Napi::CallbackInfo& info) {
  auto output = info[0].As<Napi::Buffer<unsigned char>>();
  Napi::Uint8Array seckey;
  REQUIRE_UINT8_ARRAY_EXACT(
      seckey, info[1], 32, "private key must be a 32-byte Uint8Array");

  secp256k1_pubkey pubkey;
  RETURN_IF_ZERO(secp256k1_ec_pubkey_create(this->ctx_, &pubkey, seckey.Data()),
                 1);
  PUBKEY_SERIALIZE(2);
  RETURN(0);
}

Napi::Value Secp256k1Addon::PublicKeyConvert(const Napi::CallbackInfo& info) {
  auto output = info[0].As<Napi::Buffer<unsigned char>>();
  auto input = info[1].As<Napi::Buffer<const unsigned char>>();

  secp256k1_pubkey pubkey;
  RETURN_IF_ZERO(secp256k1_ec_pubkey_parse(
                     this->ctx_, &pubkey, input.Data(), input.Length()),
                 1);
  PUBKEY_SERIALIZE(2);
  RETURN(0);
}

Napi::Value Secp256k1Addon::PublicKeyNegate(const Napi::CallbackInfo& info) {
  auto output = info[0].As<Napi::Buffer<unsigned char>>();
  auto input = info[1].As<Napi::Buffer<const unsigned char>>();

  secp256k1_pubkey pubkey;
  RETURN_IF_ZERO(secp256k1_ec_pubkey_parse(
                     this->ctx_, &pubkey, input.Data(), input.Length()),
                 1);
  RETURN_IF_ZERO(secp256k1_ec_pubkey_negate(this->ctx_, &pubkey), 2);
  PUBKEY_SERIALIZE(3);
  RETURN(0);
}

Napi::Value Secp256k1Addon::PublicKeyCombine(const Napi::CallbackInfo& info) {
  auto output = info[0].As<Napi::Buffer<unsigned char>>();
  auto inputs = info[1].As<Napi::Array>();

  std::unique_ptr<secp256k1_pubkey[]> pubkeys(
      new secp256k1_pubkey[inputs.Length()]);
  std::unique_ptr<secp256k1_pubkey*[]> ptrs(
      new secp256k1_pubkey*[inputs.Length()]);
  for (unsigned int i = 0; i < inputs.Length(); ++i) {
    auto input = inputs.Get(i).As<Napi::Buffer<const unsigned char>>();
    RETURN_IF_ZERO(secp256k1_ec_pubkey_parse(
                       this->ctx_, &pubkeys[i], input.Data(), input.Length()),
                   1);
    ptrs[i] = &pubkeys[i];
  }

  secp256k1_pubkey pubkey;
  RETURN_IF_ZERO(secp256k1_ec_pubkey_combine(
                     this->ctx_, &pubkey, ptrs.get(), inputs.Length()),
                 2);
  PUBKEY_SERIALIZE(3);
  RETURN(0);
}

Napi::Value Secp256k1Addon::PublicKeyTweakAdd(const Napi::CallbackInfo& info) {
  auto output = info[0].As<Napi::Buffer<unsigned char>>();
  auto input = info[1].As<Napi::Buffer<const unsigned char>>();
  Napi::Uint8Array tweak;
  REQUIRE_UINT8_ARRAY_EXACT(
      tweak, info[2], 32, "tweak must be a 32-byte Uint8Array");

  secp256k1_pubkey pubkey;
  RETURN_IF_ZERO(secp256k1_ec_pubkey_parse(
                     this->ctx_, &pubkey, input.Data(), input.Length()),
                 1);
  RETURN_IF_ZERO(
      secp256k1_ec_pubkey_tweak_add(this->ctx_, &pubkey, tweak.Data()), 2);
  PUBKEY_SERIALIZE(3);
  RETURN(0);
}

Napi::Value Secp256k1Addon::PublicKeyTweakMul(const Napi::CallbackInfo& info) {
  auto output = info[0].As<Napi::Buffer<unsigned char>>();
  auto input = info[1].As<Napi::Buffer<const unsigned char>>();
  Napi::Uint8Array tweak;
  REQUIRE_UINT8_ARRAY_EXACT(
      tweak, info[2], 32, "tweak must be a 32-byte Uint8Array");

  secp256k1_pubkey pubkey;
  RETURN_IF_ZERO(secp256k1_ec_pubkey_parse(
                     this->ctx_, &pubkey, input.Data(), input.Length()),
                 1);
  RETURN_IF_ZERO(
      secp256k1_ec_pubkey_tweak_mul(this->ctx_, &pubkey, tweak.Data()), 2);
  PUBKEY_SERIALIZE(3);
  RETURN(0);
}

// Signature
Napi::Value Secp256k1Addon::SignatureNormalize(const Napi::CallbackInfo& info) {
  Napi::Uint8Array sig;
  REQUIRE_UINT8_ARRAY_EXACT(
      sig, info[0], 64, "signature must be a 64-byte Uint8Array");

  secp256k1_ecdsa_signature sigin, sigout;
  RETURN_IF_ZERO(
      secp256k1_ecdsa_signature_parse_compact(this->ctx_, &sigin, sig.Data()),
      1);
  secp256k1_ecdsa_signature_normalize(this->ctx_, &sigout, &sigin);
  secp256k1_ecdsa_signature_serialize_compact(this->ctx_, sig.Data(), &sigout);
  RETURN(0);
}

Napi::Value Secp256k1Addon::SignatureExport(const Napi::CallbackInfo& info) {
  auto obj = info[0].As<Napi::Object>();
  Napi::Uint8Array output;
  Napi::Uint8Array input;
  REQUIRE_UINT8_ARRAY_EXACT(output,
                            obj.Get("output"),
                            72,
                            "signature output must be a 72-byte Uint8Array");
  REQUIRE_UINT8_ARRAY_EXACT(
      input, info[1], 64, "signature must be a 64-byte Uint8Array");

  size_t outputlen = 72;

  secp256k1_ecdsa_signature sig;
  RETURN_IF_ZERO(
      secp256k1_ecdsa_signature_parse_compact(this->ctx_, &sig, input.Data()),
      1);
  RETURN_IF_ZERO(secp256k1_ecdsa_signature_serialize_der(
                     this->ctx_, output.Data(), &outputlen, &sig),
                 2);

  obj.Set("outputlen", outputlen);
  RETURN(0);
}

Napi::Value Secp256k1Addon::SignatureImport(const Napi::CallbackInfo& info) {
  Napi::Uint8Array output;
  REQUIRE_UINT8_ARRAY_EXACT(
      output, info[0], 64, "signature output must be a 64-byte Uint8Array");

  auto input = info[1].As<Napi::Buffer<const unsigned char>>();

  secp256k1_ecdsa_signature sig;
  RETURN_IF_ZERO(secp256k1_ecdsa_signature_parse_der(
                     this->ctx_, &sig, input.Data(), input.Length()),
                 1);
  RETURN_IF_ZERO(secp256k1_ecdsa_signature_serialize_compact(
                     this->ctx_, output.Data(), &sig),
                 2);
  RETURN(0);
}

// ECDSA
int ecdsa_sign_nonce_function(unsigned char* nonce32,
                              const unsigned char* msg32,
                              const unsigned char* key32,
                              const unsigned char* algo16,
                              void* data,
                              unsigned int counter) {
  auto obj = static_cast<Secp256k1Addon::ECDSASignData*>(data);
  auto env = Napi::Env(obj->env);

  auto result = obj->fn.Call({obj->msg32,
                              obj->key32,
                              env.Null(),
                              obj->data,
                              Napi::Number::New(env, counter)});
  if (!result.IsTypedArray()) return 0;
  auto nonce = result.As<Napi::Uint8Array>();
  if (nonce.TypedArrayType() != napi_uint8_array) return 0;
  if (nonce.ByteLength() != 32) return 0;

  memcpy(nonce32, nonce.Data(), 32);
  return 1;
}

Napi::Value Secp256k1Addon::ECDSASign(const Napi::CallbackInfo& info) {
  auto obj = info[0].As<Napi::Object>();
  const Napi::Value signature_output = obj.Get("signature");
  Napi::Uint8Array output;
  Napi::Uint8Array msg32;
  Napi::Uint8Array seckey;
  REQUIRE_UINT8_ARRAY_EXACT(output,
                            signature_output,
                            64,
                            "signature output must be a 64-byte Uint8Array");
  REQUIRE_UINT8_ARRAY_EXACT(
      msg32, info[1], 32, "message must be a 32-byte Uint8Array");
  REQUIRE_UINT8_ARRAY_EXACT(
      seckey, info[2], 32, "private key must be a 32-byte Uint8Array");

  int recid;

  void* data = NULL;
  // JavaScript nonce functions may reenter this addon, so callback state must
  // belong to this invocation rather than the Secp256k1Addon instance.
  ECDSASignData ecdsa_sign_data{};
  secp256k1_nonce_function noncefn = secp256k1_nonce_function_rfc6979;
  if (!info[4].IsUndefined()) {
    ecdsa_sign_data.env = info.Env();
    ecdsa_sign_data.fn = info[4].As<Napi::Function>();
    ecdsa_sign_data.msg32 = info[1];
    ecdsa_sign_data.key32 = info[2];
    ecdsa_sign_data.data = info[3].IsUndefined() ? info.Env().Null() : info[3];

    noncefn = ecdsa_sign_nonce_function;
    data = static_cast<void*>(&ecdsa_sign_data);
  } else if (!info[3].IsUndefined()) {
    Napi::Uint8Array nonce_data;
    REQUIRE_UINT8_ARRAY_EXACT(
        nonce_data, info[3], 32, "options.data must be a 32-byte Uint8Array");
    data = nonce_data.Data();
  }

  secp256k1_ecdsa_recoverable_signature sig;
  RETURN_IF_ZERO(
      secp256k1_ecdsa_sign_recoverable(
          this->ctx_, &sig, msg32.Data(), seckey.Data(), noncefn, data),
      1);

  // Keep writes in native storage until the nonce callback has returned and
  // the original JavaScript destination has been revalidated.
  unsigned char serialized[64];
  RETURN_IF_ZERO(secp256k1_ecdsa_recoverable_signature_serialize_compact(
                     this->ctx_, serialized, &recid, &sig),
                 2);

  Napi::Uint8Array current_output;
  REQUIRE_UINT8_ARRAY_EXACT(
      current_output,
      signature_output,
      64,
      "signature output must remain a 64-byte Uint8Array");
  memcpy(current_output.Data(), serialized, 64);

  obj.Set("recid", recid);
  RETURN(0);
}

Napi::Value Secp256k1Addon::ECDSAVerify(const Napi::CallbackInfo& info) {
  Napi::Uint8Array sigraw;
  Napi::Uint8Array msg32;
  REQUIRE_UINT8_ARRAY_EXACT(
      sigraw, info[0], 64, "signature must be a 64-byte Uint8Array");
  REQUIRE_UINT8_ARRAY_EXACT(
      msg32, info[1], 32, "message must be a 32-byte Uint8Array");

  auto input = info[2].As<Napi::Buffer<const unsigned char>>();

  secp256k1_ecdsa_signature sig;
  RETURN_IF_ZERO(
      secp256k1_ecdsa_signature_parse_compact(this->ctx_, &sig, sigraw.Data()),
      1);

  secp256k1_pubkey pubkey;
  RETURN_IF_ZERO(secp256k1_ec_pubkey_parse(
                     this->ctx_, &pubkey, input.Data(), input.Length()),
                 2);

  RETURN_IF_ZERO(
      secp256k1_ecdsa_verify(this->ctx_, &sig, msg32.Data(), &pubkey), 3);
  RETURN(0);
}

Napi::Value Secp256k1Addon::ECDSARecover(const Napi::CallbackInfo& info) {
  auto output = info[0].As<Napi::Buffer<unsigned char>>();
  Napi::Uint8Array sigraw;
  Napi::Uint8Array msg32;
  REQUIRE_UINT8_ARRAY_EXACT(
      sigraw, info[1], 64, "signature must be a 64-byte Uint8Array");
  REQUIRE_UINT8_ARRAY_EXACT(
      msg32, info[3], 32, "message must be a 32-byte Uint8Array");

  auto recid = info[2].As<Napi::Number>().Int32Value();

  secp256k1_ecdsa_recoverable_signature sig;
  RETURN_IF_ZERO(secp256k1_ecdsa_recoverable_signature_parse_compact(
                     this->ctx_, &sig, sigraw.Data(), recid),
                 1);

  secp256k1_pubkey pubkey;
  RETURN_IF_ZERO(
      secp256k1_ecdsa_recover(this->ctx_, &pubkey, &sig, msg32.Data()), 2);

  PUBKEY_SERIALIZE(3);
  RETURN(0);
}

// ECDH
int ecdh_hash_function(unsigned char* output,
                       const unsigned char* x,
                       const unsigned char* y,
                       void* data) {
  auto obj = static_cast<Secp256k1Addon::ECDHData*>(data);
  const size_t outputlen = obj->outputlen;

  memcpy(obj->xbuf.As<Napi::Uint8Array>().Data(), x, 32);
  memcpy(obj->ybuf.As<Napi::Uint8Array>().Data(), y, 32);

  auto result = obj->fn.Call({obj->xbuf, obj->ybuf, obj->data});
  if (!result.IsTypedArray()) return 0;
  auto hash = result.As<Napi::Uint8Array>();
  if (hash.TypedArrayType() != napi_uint8_array) return 0;
  if (hash.ByteLength() != outputlen) return 0;

  if (outputlen > 0) memcpy(output, hash.Data(), outputlen);
  return 1;
}

Napi::Value Secp256k1Addon::ECDH(const Napi::CallbackInfo& info) {
  const bool has_hashfn = !info[4].IsUndefined();
  const Napi::Value output_handle = info[0];
  Napi::Uint8Array output;
  if (has_hashfn) {
    REQUIRE_UINT8_ARRAY(output, output_handle, "output must be a Uint8Array");
  } else {
    REQUIRE_UINT8_ARRAY_EXACT(
        output, output_handle, 32, "output must be a 32-byte Uint8Array");
  }
  const size_t outputlen = output.ByteLength();

  auto input = info[1].As<Napi::Buffer<const unsigned char>>();
  Napi::Uint8Array seckey;
  REQUIRE_UINT8_ARRAY_EXACT(
      seckey, info[2], 32, "private key must be a 32-byte Uint8Array");

  void* data = NULL;
  // A custom hash function can synchronously reenter ECDH on this instance.
  ECDHData ecdh_data{};
  if (!has_hashfn && !info[3].IsUndefined()) {
    data = info[3].As<Napi::Buffer<unsigned char>>().Data();
  }

  secp256k1_ecdh_hash_function hashfn = secp256k1_ecdh_hash_function_sha256;
  if (has_hashfn) {
    auto env = info.Env();
    Napi::Uint8Array xbuf;
    Napi::Uint8Array ybuf;

    if (info[5].IsUndefined()) {
      xbuf = Napi::Uint8Array::New(env, 32);
    } else {
      REQUIRE_UINT8_ARRAY_EXACT(
          xbuf, info[5], 32, "options.xbuf must be a 32-byte Uint8Array");
    }

    if (info[6].IsUndefined()) {
      ybuf = Napi::Uint8Array::New(env, 32);
    } else {
      REQUIRE_UINT8_ARRAY_EXACT(
          ybuf, info[6], 32, "options.ybuf must be a 32-byte Uint8Array");
    }

    ecdh_data.fn = info[4].As<Napi::Function>();
    ecdh_data.xbuf = xbuf;
    ecdh_data.ybuf = ybuf;
    ecdh_data.data = info[3].IsUndefined() ? env.Null() : info[3];
    ecdh_data.outputlen = outputlen;

    hashfn = ecdh_hash_function;
    data = static_cast<void*>(&ecdh_data);
  }

  secp256k1_pubkey pubkey;
  RETURN_IF_ZERO(secp256k1_ec_pubkey_parse(
                     this->ctx_, &pubkey, input.Data(), input.Length()),
                 1);

  if (!has_hashfn) {
    RETURN_IF_ZERO(
        secp256k1_ecdh(
            this->ctx_, output.Data(), &pubkey, seckey.Data(), hashfn, data),
        2);
    RETURN(0);
  }

  // Keep callback output in native storage until the original JavaScript
  // destination has been revalidated. libsecp256k1 requires a non-null output
  // pointer even when a custom hash function intentionally produces no bytes.
  std::vector<unsigned char> result(outputlen == 0 ? 1 : outputlen);
  RETURN_IF_ZERO(
      secp256k1_ecdh(
          this->ctx_, result.data(), &pubkey, seckey.Data(), hashfn, data),
      2);

  Napi::Uint8Array current_output;
  REQUIRE_UINT8_ARRAY_EXACT(current_output,
                            output_handle,
                            outputlen,
                            "output must remain the same length during ecdh");
  if (outputlen > 0) memcpy(current_output.Data(), result.data(), outputlen);

  RETURN(0);
}
