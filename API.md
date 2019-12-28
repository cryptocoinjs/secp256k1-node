## API Reference (v4.x)

- Functions work with [Uint8Array](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array). While [Buffer](https://nodejs.org/api/buffer.html) is awesome, current version for browsers ([feross/buffer](https://github.com/feross/buffer/)) is out of date (compare to Node.js Buffer) and in future difference probably will be only bigger. But because Buffer extends Uint8Array, you can pass and receive Buffers easily. Also, work with native Uint8Array reduce final build size, if you do not use Buffer in your browser application.

- Custom type for data output. It's possible pass Buffer or Object which inherits Uint8Array to function for data output. Of course length should match, or you can pass function which accept number of bytes and return instance with specified length.

- In place operations. Some functions doing in place operations. This done for less allocations, if you need new instance this can be easily done with creating it before pass to functions. For example:

```js
const newPrivateKey = secp256k1.privateKeyNegate(Buffer.from(privateKey))
```

<hr>

- [`.contextRandomize(seed: Uint8Array): void`](#contextrandomizeseed-uint8array-void)
- [`.privateKeyVerify(privateKey: Uint8Array): boolean`](#privatekeyverifyprivatekey-uint8array-boolean)
- [`.privateKeyNegate(privateKey: Uint8Array): Uint8Array`](#privatekeynegateprivatekey-uint8array-uint8array)
- [`.privateKeyTweakAdd(privateKey: Uint8Array, tweak: Uint8Array): Uint8Array`](#privatekeytweakaddprivatekey-uint8array-tweak-uint8array-uint8array)
- [`.privateKeyTweakMul(privateKey: Uint8Array, tweak: Uint8Array): Uint8Array`](#privatekeytweakmulprivatekey-uint8array-tweak-uint8array-uint8array)
- [`.publicKeyCreate(privateKey: Uint8Array, compressed: boolean = true, output: Uint8Array | ((_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array`](#publickeycreateprivatekey-uint8array-compressed-boolean--true-output-uint8array--_-number--uint8array--len--new-uint8arraylen-uint8array)
- [`.publicKeyConvert(publicKey: Uint8Array, compressed: boolean = true, output: Uint8Array | ((_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array`](#publickeyconvertpublickey-uint8array-compressed-boolean--true-output-uint8array--_-number--uint8array--len--new-uint8arraylen-uint8array)
- [`.publicKeyNegate(publicKey: Uint8Array, compressed: boolean = true, output: Uint8Array | ((_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array`](#publickeynegatepublickey-uint8array-compressed-boolean--true-output-uint8array--_-number--uint8array--len--new-uint8arraylen-uint8array)
- [`.publicKeyCombine(publicKeys: Uint8Array[], compressed: boolean = true, output: Uint8Array | ((_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array`](#publickeycombinepublickeys-uint8array-compressed-boolean--true-output-uint8array--_-number--uint8array--len--new-uint8arraylen-uint8array)
- [`.publicKeyTweakAdd(publicKey: Uint8Array, tweak: Uint8Array, compressed: boolean = true, output: Uint8Array | ((_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array`](#publickeytweakaddpublickey-uint8array-tweak-uint8array-compressed-boolean--true-output-uint8array--_-number--uint8array--len--new-uint8arraylen-uint8array)
- [`.publicKeyTweakMul(publicKey: Uint8Array, tweak: Uint8Array, compressed: boolean = true, output: Uint8Array | ((_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array`](#publickeytweakmulpublickey-uint8array-tweak-uint8array-compressed-boolean--true-output-uint8array--_-number--uint8array--len--new-uint8arraylen-uint8array)
- [`.signatureNormalize(signature: Uint8Array): Uint8Array`](#signaturenormalizesignature-uint8array-uint8array)
- [`.signatureExport(signature, output: Uint8Array | ((_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array`](#signatureexportsignature-output-uint8array--_-number--uint8array--len--new-uint8arraylen-uint8array)
- [`.signatureImport(signature, output: Uint8Array | ((_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array`](#signatureimportsignature-output-uint8array--_-number--uint8array--len--new-uint8arraylen-uint8array)
- [`.ecdsaSign(message: Uint8Array, privateKey: Uint8Array, output: Uint8Array | ((_: number) => Uint8Array)): { signature: Uint8Array, recid: number  = (len) => new Uint8Array(len)}`](#ecdsasignmessage-uint8array-privatekey-uint8array-output-uint8array--_-number--uint8array--signature-uint8array-recid-number---len--new-uint8arraylen)
- [`.ecdsaVerify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean`](#ecdsaverifysignature-uint8array-message-uint8array-publickey-uint8array-boolean)
- [`.ecdsaRecover(signature: Uint8Array, recid: number, message: Uint8Array, compressed: boolean = true, output: Uint8Array | ((_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array`](#ecdsarecoversignature-uint8array-recid-number-message-uint8array-compressed-boolean--true-output-uint8array--_-number--uint8array--len--new-uint8arraylen-uint8array)
- [`.ecdh(publicKey: Uint8Array, privateKey: Uint8Array, output: Uint8Array | ((_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array`](#ecdhpublickey-uint8array-privatekey-uint8array-output-uint8array--_-number--uint8array--len--new-uint8arraylen-uint8array)

##### .contextRandomize(seed: Uint8Array): void

Updates the context randomization to protect against side-channel leakage, `seed` should be Uint8Array with length 32.

##### .privateKeyVerify(privateKey: Uint8Array): boolean

Verify a private key.

##### .privateKeyNegate(privateKey: Uint8Array): Uint8Array

Negate a private key in place and return result.

##### .privateKeyTweakAdd(privateKey: Uint8Array, tweak: Uint8Array): Uint8Array

Tweak a private key in place by adding tweak to it.

##### .privateKeyTweakMul(privateKey: Uint8Array, tweak: Uint8Array): Uint8Array

Tweak a private key in place by multiplying it by a tweak.

##### .publicKeyCreate(privateKey: Uint8Array, compressed: boolean = true, output: Uint8Array | ((\_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array

Compute the public key for a secret key.

##### .publicKeyConvert(publicKey: Uint8Array, compressed: boolean = true, output: Uint8Array | ((\_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array

Reserialize public key to another format.

##### .publicKeyNegate(publicKey: Uint8Array, compressed: boolean = true, output: Uint8Array | ((\_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array

Negates a public key in place.

##### .publicKeyCombine(publicKeys: Uint8Array[], compressed: boolean = true, output: Uint8Array | ((\_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array

Add a number of public keys together.

##### .publicKeyTweakAdd(publicKey: Uint8Array, tweak: Uint8Array, compressed: boolean = true, output: Uint8Array | ((\_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array

Tweak a public key by adding tweak times the generator to it.

##### .publicKeyTweakMul(publicKey: Uint8Array, tweak: Uint8Array, compressed: boolean = true, output: Uint8Array | ((\_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array

Tweak a public key by multiplying it by a tweak value.

##### .signatureNormalize(signature: Uint8Array): Uint8Array

Convert a signature to a normalized lower-S form in place.

##### .signatureExport(signature, output: Uint8Array | ((\_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array

Export an ECDSA signature to DER format.

##### .signatureImport(signature, output: Uint8Array | ((\_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array

Parse a DER ECDSA signature.

##### .ecdsaSign(message: Uint8Array, privateKey: Uint8Array, output: Uint8Array | ((\_: number) => Uint8Array)): { signature: Uint8Array, recid: number  = (len) => new Uint8Array(len)}

Create an ECDSA signature.

##### .ecdsaVerify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean

Verify an ECDSA signature.

##### .ecdsaRecover(signature: Uint8Array, recid: number, message: Uint8Array, compressed: boolean = true, output: Uint8Array | ((\_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array

Recover an ECDSA public key from a signature.

##### .ecdh(publicKey: Uint8Array, privateKey: Uint8Array, output: Uint8Array | ((\_: number) => Uint8Array) = (len) => new Uint8Array(len)): Uint8Array

Compute an EC Diffie-Hellman secret in constant time.
