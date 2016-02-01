module.exports = function (config) {
  config.set({
    browserNoActivityTimeout: 120000,
    frameworks: ['browserify', 'detectBrowsers', 'mocha'],
    files: [
      'test/index.js'
    ],
    preprocessors: {
      'test/index.js': ['browserify', 'env']
    },
    singleRun: true,
    plugins: [
      'karma-browserify',
      'karma-chrome-launcher',
      'karma-env-preprocessor',
      'karma-firefox-launcher',
      'karma-detect-browsers',
      'karma-mocha'
    ],
    browserify: {
      debug: true
    },
    envPreprocessor: [
      'RANDOM_TESTS_REPEAT',
      'TRAVIS'
    ],
    detectBrowsers: {
      enabled: true,
      usePhantomJS: false,
      postDetection: function (availableBrowser) {
        if (process.env.TRAVIS) {
          return ['Firefox']
        }

        var browsers = ['Chrome', 'Firefox']
        return browsers.filter(function (browser) {
          return availableBrowser.indexOf(browser) !== -1
        })
      }
    }
  })
}
