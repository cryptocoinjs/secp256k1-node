function genCombMulTo (alen, blen) {
  var len = alen + blen - 1
  var src = [
    'const a = num1.words',
    'const b = num2.words',
    'const o = out.words',
    'let c = 0',
    'let lo',
    'let mid',
    'let hi'
  ]

  for (let i = 0; i < alen; i++) {
    src.push(`const a${i} = a[${i}] | 0`)
    src.push(`const al${i} = a${i} & 0x1fff`)
    src.push(`const ah${i} = a${i} >>> 13`)
  }
  for (let i = 0; i < blen; i++) {
    src.push(`const b${i} = b[${i}] | 0`)
    src.push(`const bl${i} = b${i} & 0x1fff`)
    src.push(`const bh${i} = b${i} >>> 13`)
  }
  src.push('')
  src.push(`out.length = ${len}`)

  for (let k = 0; k < len; k++) {
    const minJ = Math.max(0, k - alen + 1)
    const maxJ = Math.min(k, blen - 1)

    src.push(`/* k = ${k} */`)
    src.push(`lo = Math.imul(al${k - minJ}, bl${minJ})`)
    src.push(`mid = Math.imul(al${k - minJ}, bh${minJ})`)
    src.push(`mid += Math.imul(ah${k - minJ}, bl${minJ})`)
    src.push(`hi = Math.imul(ah${k - minJ}, bh${minJ})`)

    for (let j = minJ + 1; j <= maxJ; j++) {
      let i = k - j

      src.push(`lo += Math.imul(al${i}, bl${j})`)
      src.push(`mid += Math.imul(al${i}, bh${j})`)
      src.push(`mid += Math.imul(ah${i}, bl${j})`)
      src.push(`hi += Math.imul(ah${i}, bh${j})`)
    }

    src.push(`let w${k} = c + lo + ((mid & 0x1fff) << 13)`)
    src.push(`c = hi + (mid >>> 13) + (w${k} >>> 26)`)
    src.push(`w${k} &= 0x3ffffff`)
  }

  // Store in separate step for better memory access
  for (let k = 0; k < len; k++) src.push(`o[${k}] = w${k}`)
  src.push('if (c !== 0) {',
           `  o[${len}] = c`,
           '  out.length++',
           '}',
           'return out')

  return src.join('\n')
}

console.log(genCombMulTo(10, 10))
