import _ from 'lodash';

import _bcrypt from 'bcryptjs';

const webCrypto = window.crypto || window.msCrypto || window.webkitCrypto || window.mozCrypto;

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8");

function stringToBytes(ascii) {
  return enc.encode(ascii);
}

function bytesToBase64String(bytes) {
  return window.btoa(new Uint8Array(bytes).reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '')).trim();
}

function base64StringToBytes(hex) {
  return new Uint8Array(window.atob(hex).match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

function bytesToString(bytes) {
  return dec.decode(bytes);
}

class RSA {

  rsaName = "RSA-OAEP";

  encrypt(text, publicKey) {
    return this.importFromJwk(publicKey, true).then(key => {
      return webCrypto.subtle.encrypt(
        {
            name: this.rsaName,
        },
        key, //from generateKey or importKey above
        stringToBytes(text),
      )
      .then((encrypted) => {
        return bytesToBase64String(encrypted);
      })
      .catch((err) => {
        console.error(`[RSA] Error while decrypt ${err.message}`, err);
      });
    });
  }

  decrypt(encdata, privateKey) {
    return this.importFromJwk(privateKey, false).then(key => {
      return webCrypto.subtle.decrypt(
        {
          name: this.rsaName,
        },
        key, //from generateKey or importKey above
        base64StringToBytes(encdata) //ArrayBuffer of the data
      )
      .then((decrypted) => {
        return bytesToString(decrypted);
      })
      .catch((err) => {
        console.error(`[RSA] Error while decrypt ${err.message}`, err);
      });
    });
  }

  exportAsJwk(key) {
    return webCrypto.subtle.exportKey(
      "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
      key //can be a publicKey or privateKey, as long as extractable was true
    )
    .catch((err) => {
      console.error(`[RSA] Error while exporting key ${err.message}`, err);
    });
  }

  importFromJwk(key, pub) {
    return webCrypto.subtle.importKey(
      "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
      key,
      {   //these are the algorithm options
        name: this.rsaName,
        hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
      },
      true, //whether the key is extractable (i.e. can be used in exportKey)
      [pub ? "encrypt" : "decrypt"] 
    )
    .catch((err) => {
      console.error(`[RSA] Error while importing key ${err.message}`, err);
    });
  }

  genKeyPair() {
    return webCrypto.subtle.generateKey({
        name: this.rsaName,
        modulusLength: 2048, //can be 1024, 2048, or 4096
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
      },
      true, //whether the key is extractable (i.e. can be used in exportKey)
      ["encrypt", "decrypt"] //must be ["encrypt", "decrypt"] or ["wrapKey", "unwrapKey"]
    )
    .then((key) => {
      return this.exportAsJwk(key.publicKey).then(publicKey => {
        return this.exportAsJwk(key.privateKey).then(privateKey => {
          return {
            publicKey,
            privateKey
          }
        });
      });
    })
    .catch((err) => {
      console.error(`[RSA] Error while gen key pair ${err.message}`, err);
    });
  }
}

class AES {

  aesName = "AES-CTR"

  deriveKey(passphrase) {
    const pass = _.repeat(passphrase, 128).substring(0, 32);
    return this.importKey(pass);
  }

  importKey(raw) {
    return webCrypto.subtle.importKey(
      "raw", //can be "jwk" or "raw"
      stringToBytes(raw),
      {   //this is the algorithm options
          name: this.aesName,
      },
      true, //whether the key is extractable (i.e. can be used in exportKey)
      ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
    )
    .catch(function(err){
      console.error(`[AES] error while importing key ${err.message}`, err);
    });
  }

  encrypt(text, masterkey) {
    return this.deriveKey(masterkey).then(key => {
      return webCrypto.subtle.encrypt(
        {
          name: this.aesName,
          //Don't re-use counters!
          //Always use a new counter every time your encrypt!
          counter: new Uint8Array(16),
          length: 128, //can be 1-128
        },
        key, //from generateKey or importKey above
        stringToBytes(text) //ArrayBuffer of data you want to encrypt
      )
      .then((encrypted) => {
        return bytesToBase64String(encrypted);
      })
      .catch(function(err){
        console.error(`[AES] error while encrypt ${err.message}`, err);
      });
    });
  }

  decrypt(encdata, masterkey) {
    return this.deriveKey(masterkey).then(key => {
      return webCrypto.subtle.decrypt(
        {
            name: this.aesName,
            counter: new Uint8Array(16), //The same counter you used to encrypt
            length: 128, //The same length you used to encrypt
        },
        key, //from generateKey or importKey above
        base64StringToBytes(encdata) //ArrayBuffer of the data
      )
      .then((decrypted) => {
        return bytesToString(decrypted);
      })
      .catch((err) => {
        console.error(`[AES] error while decrypt ${err.message}`, err);
      });
    });
  }
}

export const aes = new AES();
export const rsa = new RSA();
export const bcrypt = _bcrypt;

export function generateRandomKey() {
  return window.btoa(String.fromCharCode.apply(null, getRandomValues(new Uint8Array(16)))).trim();
}

function getRandomValues(buf) {
  if (crypto && webCrypto.getRandomValues) {
      return webCrypto.getRandomValues(buf);
  }
  if (window.msCrypto && window.mswebCrypto.getRandomValues) {
      return window.mswebCrypto.getRandomValues(buf);
  }
  throw new Error('No cryptographic randomness!');
}

