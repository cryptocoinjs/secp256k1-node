import BigNum from 'bignum'

export const BN_MAX256 = BigNum.pow(2, 256).sub(1)
export const N = BigNum.fromBuffer(Buffer.from('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 'hex'))
export const NH = N.shiftRight(1)
export const P = BigNum.fromBuffer(Buffer.from('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 'hex'))
export const K = BigNum(1).shiftLeft(256).sub(P)

const ZERO_BUFFER32 = Buffer.alloc(32, 0)
export function fillZeros (buffer) {
  return Buffer.concat([ZERO_BUFFER32, buffer]).slice(-32)
}

export function testBN (t, bn, bignum) {
  const isNeg = bignum.cmp(0) < 0
  if (isNeg) bignum = bignum.neg()

  try {
    t.same(bn.negative, isNeg ? 1 : 0)
    t.same(bn.length, Math.max(Math.ceil(bignum.bitLength() / 26), 1))
    for (let i = 0, bign = bignum; i < bn.length; ++i) {
      t.same(bn.words[i], bign.and(0x03ffffff).toNumber())
      bign = bign.shiftRight(26)
    }
  } catch (err) {
    console.log(bn)
    console.log(bn.toBuffer().toString('hex'))
    console.log(fillZeros(bignum.toBuffer()).toString('hex'), isNeg)
    throw err
  }
}
