# API Reference (v4.x)

- [`privateKey`](#privatekey)
  - [`verify(Buffer privateKey)`](#privatekeyverifybuffer-privatekey---boolean)
  - [`export(Buffer privateKey [, Boolean compressed = true])`](#privatekeyexportbuffer-privatekey--boolean-compressed--true---buffer)
  - [`import(Buffer privateKey)`](#privatekeyimportbuffer-privatekey---buffer)
  - [`tweakAdd(Buffer privateKey, Buffer tweak)`](#privatekeytweakaddbuffer-privatekey-buffer-tweak---buffer)
  - [`tweakMul(Buffer privateKey, Buffer tweak)`](#privatekeytweakmulbuffer-privatekey-buffer-tweak---buffer)
- [`publicKey`](#publickey)
  - [`create(Buffer privateKey [, Boolean compressed = true])`](#publickeycreatebuffer-privatekey--boolean-compressed--true---buffer)
  - [`convert(Buffer publicKey [, Boolean compressed = true])`](#publickeyconvertbuffer-publickey--boolean-compressed--true---buffer)
  - [`verify(Buffer publicKey)`](#publickeyverifybuffer-publickey---boolean)
  - [`tweakAdd(Buffer publicKey, Buffer tweak [, Boolean compressed = true])`](#publickeytweakaddbuffer-publickey-buffer-tweak--boolean-compressed--true---buffer)
  - [`tweakMul(Buffer publicKey, Buffer tweak [, Boolean compressed = true])`](#publickeytweakmulbuffer-publickey-buffer-tweak--boolean-compressed--true---buffer)
  - [`combine(Array<Buffer> publicKeys [, Boolean compressed = true])`](#publickeycombinearraybuffer-publickeys--boolean-compressed--true---buffer)
- [`ecdsa`](#ecdsa)
  - [`signature`](#ecdsasignature)
    - [`normalize(Buffer signature)`](#ecdsasignaturenormalizebuffer-signature---buffer)
    - [`export(Buffer signature)`](#ecdsasignatureexportbuffer-signature---buffer)
    - [`import(Buffer signature)`](#ecdsasignatureimportbuffer-signature---buffer)
    - [`importLax(Buffer signature)`](#ecdsasignatureimportlaxbuffer-signature---buffer)
  - [`sign(Buffer message, Buffer privateKey [, Function noncefn [, Buffer noncedata]])`](#ecdsasignbuffer-message-buffer-privatekey--function-noncefn--buffer-noncedata----signature-buffer-recovery-number-)
  - [`verify(Buffer signature, Buffer message, Buffer publicKey)`](#ecdsaverifybuffer-signature-buffer-message-buffer-publickey---boolean)
  - [`recover(Buffer signature, Number recovery, Buffer message [, Boolean compressed = true])`](#ecdsarecoverbuffer-signature-number-recovery-buffer-message--boolean-compressed--true---buffer)
- [`schnorr`](#schnorr)
  - [`sign(Buffer message, Buffer privateKey [, Function noncefn [, Buffer noncedata]])`](#signbuffer-message-buffer-privatekey--function-noncefn--buffer-noncedata---buffer)
  - [`verify(Buffer signature, Buffer message, Buffer publicKey)`](#verifybuffer-signature-buffer-message-buffer-publickey---boolean)
  - [`recover(Buffer signature, Buffer message [, Boolean compressed = true])`](#recoverbuffer-signature-buffer-message--boolean-compressed--true---buffer)
  - [`generateNoncePair(Buffer message, Buffer privateKey [, Function noncefn [, Buffer noncedata [, Boolean compressed]]])`](#generatenoncepairbuffer-message-buffer-privatekey--function-noncefn--buffer-noncedata--boolean-compressed----pubnonce-buffer-privnonce-buffer-)
  - [`partialSign(Buffer message, Buffer privateKey, Buffer pubnonceOthers, Buffer privnonce)`](#partialsignbuffer-message-buffer-privatekey-buffer-pubnonceothers-buffer-privnonce---buffer)
  - [`partialCombine(Array<Buffer> signatures)`](#partialcombinearraybuffer-signatures---buffer)
- [`ecdh`](#ecdh)
  - [`sha256(Buffer publicKey, Buffer privateKey)`](#sha256buffer-publickey-buffer-privatekey---buffer)
  - [`unsafe(Buffer publicKey, Buffer privateKey [, Boolean compressed = true])`](#unsafebuffer-publickey-buffer-privatekey--boolean-compressed--true---buffer)

<hr>

###`privateKey`

####`privateKey.verify(Buffer privateKey)` -> `Boolean`

Verify an EC *privateKey*.

####`privateKey.export(Buffer privateKey [, Boolean compressed = true])` -> `Buffer`

Export a *privateKey* in DER format.

####`privateKey.import(Buffer privateKey)` -> `Buffer`

Import a *privateKey* in DER format.

####`privateKey.tweakAdd(Buffer privateKey, Buffer tweak)` -> `Buffer`

Tweak a *privateKey* by adding *tweak* to it.

####`privateKey.tweakMul(Buffer privateKey, Buffer tweak)` -> `Buffer`

Tweak a *privateKey* by multiplying it by a *tweak*.

<hr>

###`publicKey`

####`publicKey.create(Buffer privateKey [, Boolean compressed = true])` -> `Buffer`

Compute the public key for a *privateKey*.

####`publicKey.convert(Buffer publicKey [, Boolean compressed = true])` -> `Buffer`

Convert a *publicKey* to *compressed* or *uncompressed* form.

####`publicKey.verify(Buffer publicKey)` -> `Boolean`

Verify an EC *publicKey*.

####`publicKey.tweakAdd(Buffer publicKey, Buffer tweak [, Boolean compressed = true])` -> `Buffer`

Tweak a *publicKey* by adding *tweak* times the generator to it.

####`publicKey.tweakMul(Buffer publicKey, Buffer tweak [, Boolean compressed = true])` -> `Buffer`

Tweak a *publicKey* by multiplying it by a *tweak* value.

####`publicKey.combine(Array<Buffer> publicKeys [, Boolean compressed = true])` -> `Buffer`

Add a given *publicKeys* together.

<hr>

###`ecdsa`

####`ecdsa.signature`

#####`ecdsa.signature.normalize(Buffer signature)` -> `Buffer`

Convert a *signature* to a normalized lower-S form.

#####`ecdsa.signature.export(Buffer signature)` -> `Buffer`

Serialize an ECDSA *signature* in DER format.

#####`ecdsa.signature.import(Buffer signature)` -> `Buffer`

Parse a DER ECDSA *signature* (follow by [BIP66](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki)).

#####`ecdsa.signature.importLax(Buffer signature)` -> `Buffer`

Same as [ecdsa.signature.import](#ecdsasignatureimportbuffer-signature---buffer) but not follow by [BIP66](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki).

####`ecdsa.sign(Buffer message, Buffer privateKey [, Function noncefn [, Buffer noncedata]])` -> `{ signature: Buffer, recovery: number }`

Create an ECDSA signature. Always return low-S signature.

Inputs: 32-byte message m, 32-byte scalar key d, 32-byte scalar nonce k.

* Compute point R = k * G. Reject nonce if R's x coordinate is zero.
* Compute 32-byte scalar r, the serialization of R's x coordinate.
* Compose 32-byte scalar s = k^-1 \* (r \* d + m). Reject nonce if s is zero.
* The signature is (r, s).

By default:

  - noncefn is [rfc6979](https://tools.ietf.org/html/rfc6979)
  - noncedata is empty `Buffer` (RFC 6979 3.6) (32 bytes)

####`ecdsa.verify(Buffer signature, Buffer message, Buffer publicKey)` -> `Boolean`

Verify an ECDSA signature.

Note: **return false for high signatures!**

Inputs: 32-byte message m, public key point Q, signature: (32-byte r, scalar s).

* Signature is invalid if r is zero.
* Signature is invalid if s is zero.
* Compute point R = (s^-1 \* m \* G + s^-1 \* r \* Q). Reject if R is infinity.
* Signature is valid if R's x coordinate equals to r.

####`ecdsa.recover(Buffer signature, Number recovery, Buffer message [, Boolean compressed = true])` -> `Buffer`

Recover an ECDSA public key from a signature.

<hr>

###`schnorr`

####`sign(Buffer message, Buffer privateKey [, Function noncefn [, Buffer noncedata]])` -> `Buffer`

Create a signature using a custom EC-Schnorr-SHA256 construction. It produces non-malleable 64-byte signatures which support public key recovery batch validation, and multiparty signing.

Inputs: 32-byte message m, 32-byte scalar key d, 32-byte scalar nonce k.

* Compute point R = k \* G. Reject nonce if R's y coordinate is odd (or negate nonce).
* Compute 32-byte r, the serialization of R's x coordinate.
* Compute scalar h = Hash(r || m). Reject nonce if h == 0 or h >= order.
* Compute scalar s = k - h \* x.
* The signature is (r, s).

####`verify(Buffer signature, Buffer message, Buffer publicKey)` -> `Boolean`

Verify a Schnorr signature.

Inputs: 32-byte message m, public key point Q, signature: (32-byte r, scalar s).

* Signature is invalid if s >= order.
* Signature is invalid if r >= p.
* Compute scalar h = Hash(r || m). Signature is invalid if h == 0 or h >= order.
* Compute point R = h \* Q + s \* G. Signature is invalid if R is infinity or R's y coordinate is odd.
* Signature is valid if the serialization of R's x coordinate equals r.

####`recover(Buffer signature, Buffer message [, Boolean compressed = true])` -> `Buffer`

Recover an EC public key from a Schnorr signature.

####`generateNoncePair(Buffer message, Buffer privateKey [, Function noncefn [, Buffer noncedata [, Boolean compressed]]])` -> `{ pubnonce: Buffer, privnonce: Buffer }`

Generate a nonce pair deterministically for use with [schnorr.partialSign](#partialsignbuffer-message-buffer-privatekey-buffer-pubnonceothers-buffer-privnonce---buffer).

####`partialSign(Buffer message, Buffer privateKey, Buffer pubnonceOthers, Buffer privnonce)` -> `Buffer`

Produce a partial Schnorr signature, which can be combined using [schnorr.partialCombine](#partialcombinearraybuffer-signatures---buffer), to end up with a full signature that is verifiable using [schnorr.verify](##verifybuffer-signature-buffer-message-buffer-publickey---boolean).

####`partialCombine(Array<Buffer> signatures)` -> `Buffer`

Combine multiple Schnorr partial signatures.

<hr>

###`ecdh`

####`sha256(Buffer publicKey, Buffer privateKey)` -> `Buffer`

Compute an EC Diffie-Hellman secret and applied sha256 to compressed public key.

####`unsafe(Buffer publicKey, Buffer privateKey [, Boolean compressed = true])` -> `Buffer`

Compute an EC Diffie-Hellman secret and return public key as result.
