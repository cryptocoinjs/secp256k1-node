import { readFileSync, writeFileSync } from 'fs'
import { join } from 'path'

const sourceFilename = join(__dirname, '../src/messages.h')
const outputFilename = join(__dirname, '../es/messages.json')

const content = readFileSync(sourceFilename, 'utf-8')
const messages = content.split('\n').reduce((result, line) => {
  const match = line.match(/#define ([A-Z_0-9]+) "(.*)"/)
  if (match !== null) result[match[1]] = match[2]
  return result
}, {})

writeFileSync(outputFilename, JSON.stringify(messages, null, 2) + '\n')
