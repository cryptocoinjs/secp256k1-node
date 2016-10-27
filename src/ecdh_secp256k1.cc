#include <string.h>

#include <secp256k1.h>
#include <util.h>
#include <field_impl.h>
#include <scalar_impl.h>
#include <group_impl.h>
#include <ecmult_impl.h>
#include <ecmult_gen_impl.h>
#include <ecmult_const_impl.h>

#define ARG_CHECK(cond) do { \
  if (EXPECT(!(cond), 0)) { \
    secp256k1_callback_call(&ctx->illegal_callback, #cond); \
    return 0; \
  } \
} while(0)

struct secp256k1_context_struct {
  secp256k1_ecmult_context ecmult_ctx;
  secp256k1_ecmult_gen_context ecmult_gen_ctx;
  secp256k1_callback illegal_callback;
  secp256k1_callback error_callback;
};

static int secp256k1_pubkey_load(const secp256k1_context* ctx, secp256k1_ge* ge, const secp256k1_pubkey* pubkey) {
  if (sizeof(secp256k1_ge_storage) == 64) {
    /* When the secp256k1_ge_storage type is exactly 64 byte, use its
     * representation inside secp256k1_pubkey, as conversion is very fast.
     * Note that secp256k1_pubkey_save must use the same representation. */
    secp256k1_ge_storage s;
    memcpy(&s, &pubkey->data[0], 64);
    secp256k1_ge_from_storage(ge, &s);
  } else {
    /* Otherwise, fall back to 32-byte big endian for X and Y. */
    secp256k1_fe x, y;
    secp256k1_fe_set_b32(&x, pubkey->data);
    secp256k1_fe_set_b32(&y, pubkey->data + 32);
    secp256k1_ge_set_xy(ge, &x, &y);
  }
  ARG_CHECK(!secp256k1_fe_is_zero(&ge->x));
  return 1;
}

static void secp256k1_pubkey_save(secp256k1_pubkey* pubkey, secp256k1_ge* ge) {
  if (sizeof(secp256k1_ge_storage) == 64) {
    secp256k1_ge_storage s;
    secp256k1_ge_to_storage(&s, ge);
    memcpy(&pubkey->data[0], &s, 64);
  } else {
    VERIFY_CHECK(!secp256k1_ge_is_infinity(ge));
    secp256k1_fe_normalize_var(&ge->x);
    secp256k1_fe_normalize_var(&ge->y);
    secp256k1_fe_get_b32(pubkey->data, &ge->x);
    secp256k1_fe_get_b32(pubkey->data + 32, &ge->y);
  }
}

int secp256k1_ecdh_sha256(const secp256k1_context* ctx, unsigned char* result, const secp256k1_pubkey* point, const unsigned char* scalar) {
  int ret = 0;
  int overflow = 0;
  secp256k1_gej res;
  secp256k1_ge pt;
  secp256k1_scalar s;
  ARG_CHECK(result != NULL);
  ARG_CHECK(point != NULL);
  ARG_CHECK(scalar != NULL);
  (void)ctx;

  secp256k1_pubkey_load(ctx, &pt, point);
  secp256k1_scalar_set_b32(&s, scalar, &overflow);
  if (overflow || secp256k1_scalar_is_zero(&s)) {
    ret = 0;
  } else {
    unsigned char x[32];
    unsigned char y[1];
    secp256k1_sha256_t sha;

    secp256k1_ecmult_const(&res, &pt, &s);
    secp256k1_ge_set_gej(&pt, &res);
    /* Compute a hash of the point in compressed form
     * Note we cannot use secp256k1_eckey_pubkey_serialize here since it does not
     * expect its output to be secret and has a timing sidechannel. */
    secp256k1_fe_normalize(&pt.x);
    secp256k1_fe_normalize(&pt.y);
    secp256k1_fe_get_b32(x, &pt.x);
    y[0] = 0x02 | secp256k1_fe_is_odd(&pt.y);

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, y, sizeof(y));
    secp256k1_sha256_write(&sha, x, sizeof(x));
    secp256k1_sha256_finalize(&sha, result);
    ret = 1;
  }

  secp256k1_scalar_clear(&s);
  return ret;
}

int secp256k1_ecdh_unsafe(const secp256k1_context* ctx, secp256k1_pubkey* pubkey, const secp256k1_pubkey* point, const unsigned char* scalar) {
  int ret = 0;
  int overflow = 0;
  secp256k1_gej res;
  secp256k1_ge pt;
  secp256k1_scalar s;
  ARG_CHECK(pubkey != NULL);
  ARG_CHECK(point != NULL);
  ARG_CHECK(scalar != NULL);
  (void)ctx;

  secp256k1_pubkey_load(ctx, &pt, point);
  secp256k1_scalar_set_b32(&s, scalar, &overflow);
  if (overflow || secp256k1_scalar_is_zero(&s)) {
    ret = 0;
  } else {
    secp256k1_ecmult_const(&res, &pt, &s);
    secp256k1_ge_set_gej(&pt, &res);
    secp256k1_pubkey_save(pubkey, &pt);
    ret = 1;
  }

  secp256k1_scalar_clear(&s);
  return ret;
}
