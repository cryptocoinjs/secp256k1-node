module.exports = function (config) {
  config.set({
    browserNoActivityTimeout: 120000,
    files: [
      'test/index.js'
    ],
    frameworks: [
      'browserify',
      'detectBrowsers',
      'tap'
    ],
    plugins: [
      'karma-browserify',
      'karma-chrome-launcher',
      'karma-env-preprocessor',
      'karma-firefox-launcher',
      'karma-detect-browsers',
      'karma-tap'
    ],
    preprocessors: {
      'test/index.js': ['browserify', 'env']
    },
    singleRun: true,
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
