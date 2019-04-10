/*
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8");

function asciiToUint8Array(ascii) {
  return enc.encode(ascii);
}

function bytesToHexString(bytes) {
  return new Uint8Array(bytes).reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}

function hexStringToUint8Array(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

function bytesToASCIIString(bytes) {
  return dec.decode(bytes);
}*/

export const _aes = {
  encrypt: (text, masterkey) => {
    return Promise.resolve(CryptoJS.AES.encrypt(text, masterkey).toString());
  },
  decrypt: (encdata, masterkey) => {
    return Promise.resolve(CryptoJS.AES.decrypt(encdata, masterkey).toString(CryptoJS.enc.Utf8));
  }
};

import CryptoJS from 'crypto-js';

// https://github.com/diafygi/webcrypto-examples
// https://gist.github.com/jo/8619441
// https://coolaj86.com/articles/webcrypto-encrypt-and-decrypt-with-aes/
// https://github.com/diafygi/webcrypto-examples/issues/8

class Test {
  login(email, password) {
    return this.server.login(email, password).then(res => {
      if (res) {
        this.email = email;
        this.password = password;
        this.name = res.name
        return aes.decrypt(res.salt, this.password).then(salt => {
          return this.decryptPrivateKey(res.privateKey, salt, this.password).then(decryptedPrivateKey => {
            this.salt = salt;
            this.privateKey = decryptedPrivateKey;
            this.publicKey = res.publicKey;
            console.log('Logged in as ' + this.email);
            return this.loadMessage();
          });
        });
      } else {
        console.log('Bad login ...');
        return null;
      }
    });
  }

  createAccount(name, email, password) {
    this.email = email;
    this.password = password;
    this.name = name
    return this.server.createUser(email, name, bcrypt.hashSync(password, this.generateSalt()).then(res => {
      console.log('Generating keys ...');
      return rsa.genKeyPair().then(pair => {
        this.privateKey = pair.privateKey;
        this.publicKey = pair.publicKey;
        this.salt = this.generateSalt();
        console.log('Sending keys to server');
        return aes.encrypt(this.salt, this.password).then(encryptedSalt => {
          return this.encryptPrivateKey(this.privateKey, this.salt, this.password).then(encryptedPrivateKey => {
            return this.server.storeKey(
              this.email,
              encryptedSalt,
              this.publicKey,
              encryptedPrivateKey
            ).then(() => {
              console.log('Logged in as ' + this.email);
              return this.loadMessage();
            });
          });
        });
      });
    });
  }
}


const webCrypto = window.crypto || window.msCrypto || window.webkitCrypto || window.mozCrypto;

export function generateRandomKey() {
  return window.btoa(String.fromCharCode.apply(null, getRandomValues(new Uint8Array(16)))).trim();
}

function getRandomValues(buf) {
  if (webCrypto && webCrypto.getRandomValues) {
      return webCrypto.getRandomValues(buf);
  }
  if (window.msCrypto && window.mswebCrypto.getRandomValues) {
      return window.mswebCrypto.getRandomValues(buf);
  }
  throw new Error('No cryptographic randomness!');
}
