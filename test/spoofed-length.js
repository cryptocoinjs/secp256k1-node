// GHSA-mwf5-hpj8-xjjc: the interface must derive lengths from the intrinsic
// byteLength getter, never from an overrideable `length` property. Runs against
// both the native and elliptic backends.
module.exports = (t, secp256k1) => {
  t.test('spoofed .length is rejected', (t) => {
    // 1-byte buffer masquerading as `fakeLength` via an own `length` property.
    const spoof = (realLength, fakeLength) => {
      const value = new Uint8Array(realLength)
      Object.defineProperty(value, 'length', { value: fakeLength, configurable: true })
      return value
    }

    t.throws(
      () => secp256k1.privateKeyVerify(spoof(1, 32)),
      /^Error: Expected private key to be an Uint8Array with length 32$/,
      'defineProperty length spoof is rejected'
    )
    t.throws(
      () => secp256k1.privateKeyNegate(spoof(1, 32)),
      /^Error: Expected private key to be an Uint8Array with length 32$/,
      'the in-place write path is never reached with a spoofed length'
    )

    // Subclass exposing a fake `length` getter.
    class Spoofed extends Uint8Array {
      get length () { return 32 }
    }
    t.throws(
      () => secp256k1.privateKeyVerify(new Spoofed(1)),
      /^Error: Expected private key to be an Uint8Array with length 32$/,
      'subclass length getter is rejected'
    )

    // A spoofed length must not satisfy a multi-length (public key) check.
    t.throws(
      () => secp256k1.publicKeyVerify(spoof(1, 33)),
      /^Error: Expected public key to be an Uint8Array with length \[33, 65\]$/,
      'spoofed length does not satisfy a multi-length check'
    )

    // A separately supplied output buffer is measured the same way: a 1-byte
    // buffer claiming to be 33 must be rejected before anything is written into
    // it — the out-of-bounds write this advisory is about. `fakeLength` matches
    // the required length so a check that trusted `.length` would wrongly pass.
    const validSeckey = new Uint8Array(32)
    validSeckey[31] = 1
    t.throws(
      () => secp256k1.publicKeyCreate(validSeckey, true, spoof(1, 33)),
      /^Error: Expected output to be an Uint8Array with length 33$/,
      'a spoofed-length output buffer is rejected'
    )

    // Prototype-level override: replacing the shared `length` accessor makes even
    // a pristine buffer report a forged length through the prototype chain. The
    // interface reads the intrinsic byteLength getter captured at load, so this is
    // ignored just like the own-property and subclass spoofs above.
    const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype)
    const lengthDescriptor = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'length')
    Object.defineProperty(typedArrayPrototype, 'length', { configurable: true, get: () => 32 })
    try {
      t.throws(
        () => secp256k1.privateKeyVerify(new Uint8Array(1)),
        /^Error: Expected private key to be an Uint8Array with length 32$/,
        'prototype-level length override is ignored'
      )
    } finally {
      Object.defineProperty(typedArrayPrototype, 'length', lengthDescriptor)
    }

    t.end()
  })

  t.test('a spoofed .length does not alter a correctly-sized input', (t) => {
    // A genuine 32-byte buffer whose `.length` lies about being much larger.
    // The intrinsic byte length is still 32, so it passes validation and reaches
    // the backend, where a dependency (bn.js) that trusts `.length` would both
    // allocate against the lie and parse a different number. Canonicalizing the
    // input before handing it to the dependency must neutralize this. The native
    // backend derives every length from the buffer's internal slot and is immune
    // for the same reason; asserting on both keeps the two in lock-step.
    const fakeLength = (bytes, fake) => {
      const value = new Uint8Array(bytes)
      Object.defineProperty(value, 'length', { value: fake, configurable: true })
      return value
    }

    // Private key with scalar value 1: valid, and cheap to reason about.
    const seckey = new Uint8Array(32)
    seckey[31] = 1

    t.equal(
      secp256k1.privateKeyVerify(fakeLength(seckey, 1e6)),
      secp256k1.privateKeyVerify(seckey),
      'privateKeyVerify ignores the spoofed length'
    )
    t.ok(
      secp256k1.privateKeyVerify(fakeLength(seckey, 1e6)),
      'the correctly-sized key is still seen as valid'
    )

    t.same(
      secp256k1.publicKeyCreate(fakeLength(seckey, 1e6)),
      secp256k1.publicKeyCreate(seckey),
      'publicKeyCreate derives the same key regardless of the spoofed length'
    )

    // Tweak path: the tweak is parsed by bn.js and the private key is written
    // back in place. A spoofed length on either must not change the outcome.
    const tweak = new Uint8Array(32)
    tweak[31] = 2
    t.same(
      secp256k1.privateKeyTweakAdd(new Uint8Array(seckey), fakeLength(tweak, 1e6)),
      secp256k1.privateKeyTweakAdd(new Uint8Array(seckey), tweak),
      'privateKeyTweakAdd ignores a spoofed length on the tweak'
    )
    t.same(
      secp256k1.privateKeyTweakAdd(fakeLength(new Uint8Array(seckey), 1e6), tweak),
      secp256k1.privateKeyTweakAdd(new Uint8Array(seckey), tweak),
      'privateKeyTweakAdd ignores a spoofed length on the private key'
    )

    // Signing and verification consume the message, private key and signature
    // through the same dependencies.
    const message = new Uint8Array(32)
    message[31] = 3
    const sig = secp256k1.ecdsaSign(message, seckey).signature
    const honest = secp256k1.ecdsaSign(fakeLength(message, 1e6), seckey).signature
    t.same(honest, sig, 'ecdsaSign ignores a spoofed length on the message')
    t.equal(
      secp256k1.ecdsaVerify(sig, fakeLength(message, 1e6), secp256k1.publicKeyCreate(seckey)),
      true,
      'ecdsaVerify ignores a spoofed length on the message'
    )

    t.end()
  })

  t.test('a prototype-level length override does not change a parsed scalar', (t) => {
    // Overriding `length` on the shared TypedArray prototype makes every buffer —
    // including the copies the backend makes internally — report a forged length,
    // with no per-instance tampering. The backend pins each copy's own `length`
    // to the real byte count before parsing it, and the native path reads the
    // internal slot in C++, so a valid, correctly sized key is still parsed at 32
    // bytes on both. privateKeyVerify is the witness: it is a pure read, so the
    // scalar reaches bn.js and back without touching any output allocation.
    const seckey = new Uint8Array(32)
    seckey[31] = 1

    const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype)
    const lengthDescriptor = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'length')
    // Report 1, the length at which a check that trusted `.length` would parse a
    // different (zero) scalar and call the key invalid.
    Object.defineProperty(typedArrayPrototype, 'length', { configurable: true, get: () => 1 })
    try {
      t.equal(
        secp256k1.privateKeyVerify(seckey),
        true,
        'the scalar is parsed at its real length, not the overridden one'
      )
    } finally {
      Object.defineProperty(typedArrayPrototype, 'length', lengthDescriptor)
    }

    t.end()
  })
}
