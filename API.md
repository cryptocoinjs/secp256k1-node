# API Reference (v3.x)

- [`.privateKeyVerify(Buffer privateKey)`](#privatekeyverifybuffer-privatekey---boolean)
- [`.privateKeyExport(Buffer privateKey [, Boolean compressed = true])`](#privatekeyexportbuffer-privatekey--boolean-compressed--true---buffer)
- [`.privateKeyImport(Buffer privateKey)`](#privatekeyimportbuffer-privatekey---buffer)
- [`.privateKeyTweakAdd(Buffer privateKey, Buffer tweak)`](#privatekeytweakaddbuffer-privatekey-buffer-tweak---buffer)
- [`.privateKeyTweakMul(Buffer privateKey, Buffer tweak)`](#privatekeytweakmulbuffer-privatekey-buffer-tweak---buffer)
- [`.publicKeyCreate(Buffer privateKey [, Boolean compressed = true])`](#publickeycreatebuffer-privatekey--boolean-compressed--true---buffer)
- [`.publicKeyConvert(Buffer publicKey [, Boolean compressed = true])`](#publickeyconvertbuffer-publickey--boolean-compressed--true---buffer)
- [`.publicKeyVerify(Buffer publicKey)`](#publickeyverifybuffer-publickey---boolean)
- [`.publicKeyTweakAdd(Buffer publicKey, Buffer tweak [, Boolean compressed = true])`](#publickeytweakaddbuffer-publickey-buffer-tweak--boolean-compressed--true---buffer)
- [`.publicKeyTweakMul(Buffer publicKey, Buffer tweak [, Boolean compressed = true])`](#publickeytweakmulbuffer-publickey-buffer-tweak--boolean-compressed--true---buffer)
- [`.publicKeyCombine(Array<Buffer> publicKeys [, Boolean compressed = true])`](#publickeycombinearraybuffer-publickeys--boolean-compressed--true---buffer)
- [`.signatureNormalize(Buffer signature)`](#signaturenormalizebuffer-signature---buffer)
- [`.signatureExport(Buffer signature)`](#signatureexportbuffer-signature---buffer)
- [`.signatureImport(Buffer signature)`](#signatureimportbuffer-signature---buffer)
- [`.signatureImportLax(Buffer signature)`](#signatureimportlaxbuffer-signature---buffer)
- [`.sign(Buffer message, Buffer privateKey [, Object options])`](#signbuffer-message-buffer-privatekey--object-options---signature-buffer-recovery-number)
  - [Option: `Function noncefn`](#option-function-noncefn)
  - [Option: `Buffer data`](#option-buffer-data)
- [`.verify(Buffer message, Buffer signature, Buffer publicKey)`](#verifybuffer-message-buffer-signature-buffer-publickey---boolean)
- [`.recover(Buffer message, Buffer signature, Number recovery [, Boolean compressed = true])`](#recoverbuffer-message-buffer-signature-number-recovery--boolean-compressed--true---buffer)
- [`.ecdh(Buffer publicKey, Buffer privateKey)`](#ecdhbuffer-publickey-buffer-privatekey---buffer)
- [`.ecdhUnsafe(Buffer publicKey, Buffer privateKey [, Boolean compressed = true])`](#ecdhunsafebuffer-publickey-buffer-privatekey--boolean-compressed--true---buffer)
- [`.schnorrSign(Buffer message, Buffer privateKey [, Object options])`](#schnorrsignbuffer-message-buffer-privatekey--object-options---buffer)
  - [Option: `Function noncefn`](#option-function-noncefn)
  - [Option: `Buffer data`](#option-buffer-data)
- [`.schnorrVerify(Buffer message, Buffer signature, Buffer publicKey)`](#schnorrverifybuffer-message-buffer-signature-buffer-publickey---boolean)
- [`.schnorrRecover(Buffer message, Buffer signature [, Boolean compressed = true])`](#schnorrrecoverbuffer-message-buffer-signature--boolean-compressed--true---buffer)
- [`.schnorrGenerateNoncePair(Buffer message, Buffer privateKey [, Object options])`](#schnorrgeneratenoncepairbuffer-message-buffer-privatekey--object-options----pubnonce-buffer-privnonce-buffer-)
  - [Option: `Function noncefn`](#option-function-noncefn)
  - [Option: `Buffer data`](#option-buffer-data)
  - [Option: `Boolean compressed`](#option-boolean-compressed)
- [`.schnorrPartialSign(Buffer message, Buffer privateKey, Buffer pubNonceOther, Buffer privNonce)`](#schnorrpartialsignbuffer-message-buffer-privatekey-buffer-pubnonceother-buffer-privnonce---buffer)
- [`.schnorrPartialCombine(Array<Buffer> signatures)`](#schnorrpartialcombinearraybuffer-signatures---buffer)

#####`.privateKeyVerify(Buffer privateKey)` -> `Boolean`

Verify an ECDSA *privateKey*.

<hr>

#####`.privateKeyExport(Buffer privateKey [, Boolean compressed = true])` -> `Buffer`

Export a *privateKey* in DER format.

<hr>

#####`.privateKeyImport(Buffer privateKey)` -> `Buffer`

Import a *privateKey* in DER format.

<hr>

#####`.privateKeyTweakAdd(Buffer privateKey, Buffer tweak)` -> `Buffer`

Tweak a *privateKey* by adding *tweak* to it.

<hr>

#####`.privateKeyTweakMul(Buffer privateKey, Buffer tweak)` -> `Buffer`

Tweak a *privateKey* by multiplying it by a *tweak*.

<hr>

#####`.publicKeyCreate(Buffer privateKey [, Boolean compressed = true])` -> `Buffer`

Compute the public key for a *privateKey*.

<hr>

#####`.publicKeyConvert(Buffer publicKey [, Boolean compressed = true])` -> `Buffer`

Convert a *publicKey* to *compressed* or *uncompressed* form.

<hr>

#####`.publicKeyVerify(Buffer publicKey)` -> `Boolean`

Verify an ECDSA *publicKey*.

<hr>

#####`.publicKeyTweakAdd(Buffer publicKey, Buffer tweak [, Boolean compressed = true])` -> `Buffer`

Tweak a *publicKey* by adding *tweak* times the generator to it.

<hr>

#####`.publicKeyTweakMul(Buffer publicKey, Buffer tweak [, Boolean compressed = true])` -> `Buffer`

Tweak a *publicKey* by multiplying it by a *tweak* value.

<hr>

#####`.publicKeyCombine(Array<Buffer> publicKeys [, Boolean compressed = true])` -> `Buffer`

Add a given *publicKeys* together.

<hr>

#####`.signatureNormalize(Buffer signature)` -> `Buffer`

Convert a *signature* to a normalized lower-S form.

<hr>

#####`.signatureExport(Buffer signature)` -> `Buffer`

Serialize an ECDSA *signature* in DER format.

<hr>

#####`.signatureImport(Buffer signature)` -> `Buffer`

Parse a DER ECDSA *signature* (follow by [BIP66](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki)).

<hr>

#####`.signatureImportLax(Buffer signature)` -> `Buffer`

Same as [signatureImport](#signatureimportbuffer-signature---buffer) but not follow by [BIP66](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki).

<hr>

#####`.sign(Buffer message, Buffer privateKey [, Object options])` -> `{signature: Buffer, recovery: number}`

Create an ECDSA signature. Always return low-S signature.

Inputs: 32-byte message m, 32-byte scalar key d, 32-byte scalar nonce k.

* Compute point R = k * G. Reject nonce if R's x coordinate is zero.
* Compute 32-byte scalar r, the serialization of R's x coordinate.
* Compose 32-byte scalar s = k^-1 \* (r \* d + m). Reject nonce if s is zero.
* The signature is (r, s).

######Option: `Function noncefn`

Nonce generator. By default it is [rfc6979](https://tools.ietf.org/html/rfc6979).

Function signature: `noncefn(Buffer message, Buffer privateKey, ?Buffer algo, ?Buffer data, Number attempt)` -> `Buffer`

######Option: `Buffer data`

Additional data for [noncefn](#option-function-noncefn) (RFC 6979 3.6) (32 bytes). By default is `null`.

<hr>

#####`.verify(Buffer message, Buffer signature, Buffer publicKey)` -> `Boolean`

Verify an ECDSA signature.

Note: **return false for high signatures!**

Inputs: 32-byte message m, public key point Q, signature: (32-byte r, scalar s).

* Signature is invalid if r is zero.
* Signature is invalid if s is zero.
* Compute point R = (s^-1 \* m \* G + s^-1 \* r \* Q). Reject if R is infinity.
* Signature is valid if R's x coordinate equals to r.

<hr>

#####`.recover(Buffer message, Buffer signature, Number recovery [, Boolean compressed = true])` -> `Buffer`

Recover an ECDSA public key from a signature.

<hr>

#####`.ecdh(Buffer publicKey, Buffer privateKey)` -> `Buffer`

Compute an EC Diffie-Hellman secret and applied sha256 to compressed public key.

<hr>

#####`.ecdhUnsafe(Buffer publicKey, Buffer privateKey [, Boolean compressed = true])` -> `Buffer`

Compute an EC Diffie-Hellman secret and return public key as result.

<hr>

#####`.schnorrSign(Buffer message, Buffer privateKey [, Object options])` -> `Buffer`

Create a signature using a custom EC-Schnorr-SHA256 construction. It produces non-malleable 64-byte signatures which support public key recovery batch validation, and multiparty signing.

Inputs: 32-byte message m, 32-byte scalar key d, 32-byte scalar nonce k.

* Compute point R = k \* G. Reject nonce if R's y coordinate is odd (or negate nonce).
* Compute 32-byte r, the serialization of R's x coordinate.
* Compute scalar h = Hash(r || m). Reject nonce if h == 0 or h >= order.
* Compute scalar s = k - h \* x.
* The signature is (r, s).

######Option: `Function noncefn`

See [options.noncefn in ECDSA .sign](#option-function-noncefn)

######Option: `Buffer data`

See [options.data in ECDSA .sign](#option-buffer-data)

<hr>

#####`.schnorrVerify(Buffer message, Buffer signature, Buffer publicKey)` -> `Boolean`

Verify a Schnorr signature.

Inputs: 32-byte message m, public key point Q, signature: (32-byte r, scalar s).

* Signature is invalid if s >= order.
* Signature is invalid if r >= p.
* Compute scalar h = Hash(r || m). Signature is invalid if h == 0 or h >= order.
* Compute point R = h \* Q + s \* G. Signature is invalid if R is infinity or R's y coordinate is odd.
* Signature is valid if the serialization of R's x coordinate equals r.

<hr>

#####`.schnorrRecover(Buffer message, Buffer signature [, Boolean compressed = true])` -> `Buffer`

Recover an EC public key from a Schnorr signature.

<hr>

#####`.schnorrGenerateNoncePair(Buffer message, Buffer privateKey [, Object options])` -> `{ pubNonce: Buffer, privNonce: Buffer }`

Generate a nonce pair deterministically for use with [.schnorrPartialSign](#schnorrpartialsignbuffer-message-buffer-privatekey-buffer-pubnonceother-buffer-privnonce---buffer).

######Option: `Function noncefn`

See [options.noncefn in ECDSA .sign](#option-function-noncefn)

######Option: `Buffer data`

See [options.data in ECDSA .sign](#option-buffer-data)

######Option: `Boolean compressed`

`pubNonce` serialization flag, by default -- `true`

<hr>

#####`.schnorrPartialSign(Buffer message, Buffer privateKey, Buffer pubNonceOther, Buffer privNonce)` -> `Buffer`

Produce a partial Schnorr signature, which can be combined using [.schnorrPartialCombine](#schnorrpartialcombinearraybuffer-signatures---buffer), to end up with a full signature that is verifiable using [.schnorrVerify](#schnorrverifybuffer-message-buffer-signature-buffer-publickey---boolean).

<hr>

#####`.schnorrPartialCombine(Array<Buffer> signatures)` -> `Buffer`

Combine multiple Schnorr partial signatures.
