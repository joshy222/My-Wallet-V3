module.exports = function(karma) {

  karma.set({
    basePath : './',

    frameworks: ['jasmine', 'browserify'],

    browsers : ['Chrome'], //'PhantomJS'],

    browserNoActivityTimeout: 60000,

    // reportSlowerThan: 50,

    client: {
      captureConsole: true
    },

    autoWatch: true,

    // logLevel: config.LOG_DEBUG,

    reporters: ['progress','coverage'],

    coverageReporter: {
      type : 'html',
      dir : 'coverage/',
      subdir: '.'
    },

    preprocessors: {
      'tests/**/*.coffee' : ['browserify']
    },

    browserify: {
      configure: function(bundle) {
        bundle.on('prebundle', function() {
          bundle.transform('coffeeify');
          bundle.transform('browserify-istanbul');
          bundle.plugin('proxyquireify/plugin');
        });
      },
      debug: true
    },

    coffeePreprocessor: {
      // options passed to the coffee compiler
      options: {
        bare: true,
        sourceMap: true
      },
      // transforming the filenames
      transformPath: function(path) {
        return path.replace(/\.coffee$/, '.js');
      }
    },
    
    files: [
      'build/bower_components.js',
      'bower_components/es5-shim/es5-shim.min.js',
      'bower_components/es6-shim/es6-shim.min.js',
      'node_modules/sjcl/sjcl.js',
      'node_modules/xregexp/xregexp-all.js',
      'src/crypto-util-legacy.js',
      'src/shared.js',
      'tests/**/*.coffee',
      {pattern: 'src/**/*.js', included: false},
      // Or specify individual test files:
      // 'tests/bip38_spec.js.coffee',
      // 'tests/blockchain_api_spec.js.coffee',
      // 'tests/claim_redeem_spec.js.coffee',
      // 'tests/hdwallet_spec.js.coffee',
      // 'tests/legacy_addresses_spec.js.coffee',
      // 'tests/my_wallet_spec.js.coffee',
      // 'tests/spend_spec.js.coffee'
      // 'tests/tags_spec.js.coffee',
      // 'tests/transaction_spec.js.coffee',
      // 'tests/transaction_spend_spec.js.coffee',
      // 'tests/wallet_spec.js.coffee'
    ]
  });
};
