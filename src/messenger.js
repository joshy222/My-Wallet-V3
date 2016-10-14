'use strict';

var WalletCrypto = require('./wallet-crypto');
var Bitcoin = require('bitcoinjs-lib');
var crypto = require('crypto');
var API = require('./api');
var MyWallet = require('./wallet');
var Contacts = require('./contacts');

module.exports = Messenger;

var myFakeFetchOK = function () {return Promise.resolve('token');}
var myFakeFetchNOK = function () {return Promise.reject('cagada');}

function Messenger (cipher, token) {
  var algo = 'algo';
  var myToken = token;
};

Messenger.new = function (cipher) {
  var createMessenger = function(token) {
    return new Messenger(cipher, token);
  };
  return myFakeFetchOK().then(createMessenger)
}

Messenger.prototype.getMessage = function (id) {
  console.log('messenger is well loaded (token): ' + this.token);
};

// Messenger.call = function (object, method) {
//   return object.method
// }
