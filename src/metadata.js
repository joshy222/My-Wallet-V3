'use strict';

var WalletCrypto = require('./wallet-crypto');
var Bitcoin = require('bitcoinjs-lib');
var API = require('./api');
var Helpers = require('./helpers');

var MyWallet = require('./wallet');

module.exports = Metadata;

function Metadata (payloadType, cipher) {
  this.VERSION = 1;
  this._payloadTypeId = payloadType;
  this._magicHash = null;
  this._value = null;
  this._sequence = Promise.resolve();

  // BIP 43 purpose needs to be 31 bit or less. For lack of a BIP number
  // we take the first 31 bits of the SHA256 hash of a reverse domain.
  var hash = WalletCrypto.sha256('info.blockchain.metadata');
  var purpose = hash.slice(0, 4).readUInt32BE(0) & 0x7FFFFFFF; // 510742

  var masterHDNode = MyWallet.wallet.hdwallet.getMasterHDNode(cipher);
  var metaDataHDNode = masterHDNode.deriveHardened(purpose);

  // Payload types:
  // 0: reserved (guid)
  // 1: reserved
  // 2: whats-new
  // 3: buy-sell
  // 4: contacts list (messaging)

  var payloadTypeNode = metaDataHDNode.deriveHardened(payloadType);

  // purpose' / type' / 0' : https://meta.blockchain.info/{address}
  //                       signature used to authenticate
  // purpose' / type' / 1' : sha256(private key) used as 256 bit AES key

  this._node = payloadTypeNode.deriveHardened(0);

  this._address = this._node.getAddress();
  this._signatureKeyPair = this._node.keyPair;

  var privateKeyBuffer = payloadTypeNode.deriveHardened(1).keyPair.d.toBuffer();
  this._encryptionKey = WalletCrypto.sha256(privateKeyBuffer);
}

Metadata.prototype.setMagicHash = function (encryptedPayload) {
  this._magicHash = Bitcoin.message.magicHash(encryptedPayload, Bitcoin.networks.bitcoin);
};

Object.defineProperties(Metadata.prototype, {
  'existsOnServer': {
    configurable: false,
    get: function () { return Boolean(this._magicHash); }
  }
});

/*
metadata = new Blockchain.Metadata(2);
metadata.create({
  lastViewed: Date.now()
});
*/
Metadata.prototype.create = function (data) {
  var self = this;
  return this.next(function () {
    var payload = JSON.stringify(data);

    var encryptedPayload = WalletCrypto.encryptDataWithKey(payload, self._encryptionKey);

    var encryptedPayloadSignature = Bitcoin.message.sign(
      self._signatureKeyPair,
      encryptedPayload
    );

    var serverPayload = {
      version: 1,
      payload_type_id: self._payloadTypeId,
      payload: encryptedPayload,
      signature: encryptedPayloadSignature.toString('base64')
    };

    return self.POST(self._address, serverPayload).then(function () {
      self._value = data;
      self.setMagicHash(encryptedPayload);
    });
  });
};

Metadata.prototype.fetch = function () {
  var self = this;
  return this.next(function () {
    return self.GET(self._address).then(function (serverPayload) {
      if (serverPayload === null) {
        return null;
      }

      var decryptedPayload = WalletCrypto.decryptDataWithKey(serverPayload.payload, self._encryptionKey);

      var verified = self._verify(
        Buffer(serverPayload.signature, 'base64'),
        serverPayload.payload
      );

      if (verified) {
        self._previousPayload = decryptedPayload;
        self._value = JSON.parse(decryptedPayload);
        self.setMagicHash(serverPayload.payload);
        return self._value;
      } else {
        throw new Error('METADATA_SIGNATURE_VERIFICATION_ERROR');
      }
    }).catch(function (e) {
      console.error(e);
      return Promise.reject('METADATA_FETCH_FAILED');
    });
  });
};

// Overridden in Objective-C
Metadata.prototype._verify = function (signature, message) {
  return Bitcoin.message.verify(this._address, signature, message);
};
/*
metadata.update({
  lastViewed: Date.now()
});
*/
Metadata.prototype.update = function (data) {
  var self = this;
  return this.next(function () {
    var payload = JSON.stringify(data);
    if (payload === self._previousPayload) {
      return Promise.resolve();
    }
    self._previousPayload = payload;
    var encryptedPayload = WalletCrypto.encryptDataWithKey(payload, self._encryptionKey);
    var encryptedPayloadSignature = Bitcoin.message.sign(
      self._signatureKeyPair,
      encryptedPayload
    );

    var serverPayload = {
      version: 1,
      payload_type_id: self._payloadTypeId,
      prev_magic_hash: self._magicHash.toString('hex'),
      payload: encryptedPayload,
      signature: encryptedPayloadSignature.toString('base64')
    };

    return self.PUT(self._address, serverPayload).then(function () {
      self._value = data;
      self.setMagicHash(encryptedPayload);
    });
  });
};

Metadata.prototype.GET = function (endpoint, data) {
  // if (this._payloadTypeId === 3) {
  //   return Promise.reject('DEBUG: simulate meta data service failure');
  // }
  return this.request('GET', endpoint, data);
};

Metadata.prototype.POST = function (endpoint, data) {
  return this.request('POST', endpoint, data);
};

Metadata.prototype.PUT = function (endpoint, data) {
  return this.request('PUT', endpoint, data);
};

Metadata.prototype.request = function (method, endpoint, data) {
  var url = API.API_ROOT_URL + 'metadata/' + endpoint;

  var options = {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'omit'
  };

  if (method !== 'GET') {
    options.body = JSON.stringify(data);
  }

  options.method = method;

  var handleNetworkError = function (e) {
    return Promise.reject({ error: 'METADATA_CONNECT_ERROR', message: e });
  };

  var checkStatus = function (response) {
    if (response.status >= 200 && response.status < 300) {
      return response.json();
    } else if (method === 'GET' && response.status === 404) {
      return null;
    } else {
      return response.text().then(Promise.reject.bind(Promise));
    }
  };

  return fetch(url, options)
    .catch(handleNetworkError)
    .then(checkStatus);
};

Metadata.prototype.next = function (f) {
  var nextInSeq = this._sequence.then(f);
  this._sequence = nextInSeq.then(Helpers.noop, Helpers.noop);
  return nextInSeq;
};
