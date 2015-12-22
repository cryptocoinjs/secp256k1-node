#!/usr/bin/env node
'use strict'

var fs = require('fs')
var path = require('path')

var sourceFilename = path.join(__dirname, '../src/messages.h')
var outputFilename = path.join(__dirname, '../lib/messages.json')

var result = {}
var messages = fs.readFileSync(sourceFilename, 'utf-8').split('\n')
for (var i = 0; i < messages.length; ++i) {
  var match = messages[i].match(/#define ([A-Z_0-9]+) "(.*)"/)
  if (match !== null) {
    result[match[1]] = match[2]
  }
}

fs.writeFileSync(outputFilename, JSON.stringify(result, null, 2) + '\n')
