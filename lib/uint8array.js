const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype)

const getTypedArrayType = Function.prototype.call.bind(
  Object.getOwnPropertyDescriptor(
    typedArrayPrototype,
    Symbol.toStringTag
  ).get
)

const getTypedArrayByteLength = Function.prototype.call.bind(
  Object.getOwnPropertyDescriptor(
    typedArrayPrototype,
    'byteLength'
  ).get
)

module.exports = function getUint8ArrayByteLength (value) {
  try {
    if (getTypedArrayType(value) !== 'Uint8Array') return undefined
    return getTypedArrayByteLength(value)
  } catch {
    return undefined
  }
}
