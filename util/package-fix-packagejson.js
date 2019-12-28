#!/usr/bin/env node
const fs = require('fs')
const yargs = require('yargs')

const fields = [
  'name',
  'version',
  'description',
  'keywords',
  'bugs',
  'repository',
  'license',
  'author',
  'contributors',
  'main',
  'browser',
  'scripts',
  'dependencies',
  'engines',
  'gypfile'
]

function getArgs () {
  return yargs
    .usage('Usage: $0 <command> [options]')
    .wrap(yargs.terminalWidth())
    .options({
      file: {
        alias: 'f',
        description: 'Path to package.json',
        type: 'string'
      }
    })
    .help('help')
    .alias('help', 'h').argv
}

const args = getArgs()
const pkg = JSON.parse(fs.readFileSync(args.file, 'utf8'))

const fixedPkg = {}
for (const [key, value] of Object.entries(pkg)) {
  if (fields.includes(key)) fixedPkg[key] = value
}

const content = JSON.stringify(fixedPkg, null, 2)
fs.writeFileSync(args.file, content)
