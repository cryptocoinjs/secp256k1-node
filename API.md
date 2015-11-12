# API Reference (v3.x)

- [`.secretKeyVerify(Buffer secretKey)`](#secretkeyverifybuffer-secretkey---boolean)
- [`.secretKeyExport(Buffer secretKey [, Boolean compressed = true])`](#secretkeyexportbuffer-secretkey--boolean-compressed--true---buffer)
- [`.secretKeyImport(Buffer secretKey)`](#secretkeyimportbuffer-secretkey---buffer)
- [`.secretKeyTweakAdd(Buffer secretKey, Buffer tweak)`](#secretkeytweakaddbuffer-secretkey-buffer-tweak---buffer)
- [`.secretKeyTweakMul(Buffer secretKey, Buffer tweak)`](#secretkeytweakmulbuffer-secretkey-buffer-tweak---buffer)
- [`.publicKeyCreate(Buffer secretKey [, Boolean compressed = true])`](#publickeycreatebuffer-secretkey--boolean-compressed--true---buffer)
- [`.publicKeyConvert(Buffer publicKey [, Boolean compressed = true])`](#publickeyconvertbuffer-publickey--boolean-compressed--true---buffer)
- [`.publicKeyVerify(Buffer publicKey)`](#publickeyverifybuffer-publickey---boolean)
- [`.publicKeyTweakAdd(Buffer publicKey, Buffer tweak [, Boolean compressed = true])`](#publickeytweakaddbuffer-publickey-buffer-tweak--boolean-compressed--true---buffer)
- [`.publicKeyTweakMul(Buffer publicKey, Buffer tweak [, Boolean compressed = true])`](#publickeytweakmulbuffer-publickey-buffer-tweak--boolean-compressed--true---buffer)
- [`.publicKeyCombine(Array<Buffer> publicKeys [, Boolean compressed = true])`](#publickeycombinearraybuffer-publickeys--boolean-compressed--true---buffer)
- [`.signatureNormalize(Buffer signature)`](#signaturenormalizebuffer-signature---buffer)
- [`.signatureExport(Buffer signature)`](#signatureexportbuffer-signature---buffer)
- [`.signatureImport(Buffer signature)`](#signatureimportbuffer-signature---buffer)
- [`.sign(Buffer msg, Buffer secretKey [, Object options])`](#signbuffer-msg-buffer-secretkey--object-options---signature-buffer-recovery-number)
  - [Option: `Function noncefn`](#option-function-noncefn)
  - [Option: `Buffer data`](#option-buffer-data)
- [`.verify(Buffer msg, Buffer signature, Buffer publicKey)`](#verifybuffer-msg-buffer-signature-buffer-publickey---boolean)
- [`.recover(Buffer msg, Buffer signature, Number recovery [, Boolean compressed = true])`](#recoverbuffer-msg-buffer-signature-number-recovery--boolean-compressed--true---buffer)
- [`.ecdh(Buffer publicKey, Buffer secretKey [, Object options])`](#ecdhbuffer-publickey-buffer-secretkey--object-options---buffer)
  - [Option: `Function hashfn`](#option-function-hashfn)

#####`.secretKeyVerify(Buffer secretKey)` -> `Boolean`

Verify an ECDSA *secretKey*.

<hr>

#####`.secretKeyExport(Buffer secretKey [, Boolean compressed = true])` -> `Buffer`

Export a *secretKey* in DER format.

<hr>

#####`.secretKeyImport(Buffer secretKey)` -> `Buffer`

Import a *secretKey* in DER format.

<hr>

#####`.secretKeyTweakAdd(Buffer secretKey, Buffer tweak)` -> `Buffer`

Tweak a *secretKey* by adding *tweak* to it.

<hr>

#####`.secretKeyTweakMul(Buffer secretKey, Buffer tweak)` -> `Buffer`

Tweak a *secretKey* by multiplying it by a *tweak*.

<hr>

#####`.publicKeyCreate(Buffer secretKey [, Boolean compressed = true])` -> `Buffer`

Compute the public key for a *secretKey*.

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

Parse a DER ECDSA *signature*.

<hr>

#####`.sign(Buffer msg, Buffer secretKey [, Object options])` -> `{signature: Buffer, recovery: number}`

Create an ECDSA signature.

######Option: `Function noncefn`

Nonce generator. By default it is [rfc6979](https://tools.ietf.org/html/rfc6979).

Function signature: `noncefn(Buffer msg, Buffer secretKey, ?Buffer algo, ?Buffer data, Number attempt)` -> `Buffer`

######Option: `Buffer data`

Additional data for [noncefn](#option-function-noncefn) (RFC 6979 3.6) (32 bytes). By default is `null`.

<hr>

#####`.verify(Buffer msg, Buffer signature, Buffer publicKey)` -> `Boolean`

Verify an ECDSA signature.

<hr>

#####`.recover(Buffer msg, Buffer signature, Number recovery [, Boolean compressed = true]` -> `Buffer`

Recover an ECDSA public key from a signature.

<hr>

#####`.ecdh(Buffer publicKey, Buffer secretKey [, Object options])` -> `Buffer`

Compute an EC Diffie-Hellman secret.

######Option: `Function hashfn`

Hash function that is applied to a point that is result of ecdh. By default it is sha256 that applied to compressed public key.

Function signature: `hashfn(Buffer x, Buffer y)` -> `Buffer`
