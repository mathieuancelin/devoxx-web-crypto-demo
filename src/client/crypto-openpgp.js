import _bcrypt from 'bcryptjs';
import openpgp, { message, key , stream } from 'openpgp';

openpgp.message = message;
openpgp.key = key;
openpgp.stream = stream;
openpgp.initWorker({ path: 'openpgp/openpgp.worker.js' });

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

  encrypt(text, publicKey) {
    return openpgp.key.readArmored(publicKey).then(keys => {
      openpgp.encrypt({
        message: message.fromText(text),
        publicKeys: keys,
      }).then(encrypted => {
        return openpgp.stream.readToEnd(encrypted.data);
      })
    });
  }

  decrypt(encdata, privateKey) {
    return openpgp.key.readArmored(privateKey).then(keys => {
      openpgp.decrypt({
        message: message.fromText(encdata),
        privateKeys: keys,
      }).then(decrypted => {
        return openpgp.stream.readToEnd(decrypted.data);
      })
    });
  }

  exportAsJwk(key) {
    return Promise.resolve(key);
  }

  genKeyPair(name, email) {
    return openpgp.generateKey({ 
      numBits: 4096,
      userIds: [{ name, email }]
    }).then(key => {
      const privateKey = key.privateKeyArmored;
      const publicKey = key.publicKeyArmored;
      return {
        privateKey,
        publicKey
      };
    });
  }
}

class AES {

  encrypt(text, masterkey) {
    console.log('encrypt')
    return openpgp.encrypt({
      message: message.fromText(text),
      passwords: [masterkey],
      armor: false
    }).then(ciphertext => {
      const arr = message.fromText(ciphertext).packets.write();
      return bytesToBase64String(arr);
    });
  }

  decrypt(encdata, masterkey) {
    console.log('decrypt', encdata);
    const m = message.fromBinary(base64StringToBytes(encdata));
    return openpgp.decrypt({
      message: m,
      passwords: [masterkey],
      format: 'binary' // binary
    }).then(plaintext => {
      console.log('then', plaintext);
      return bytesToString(plaintext.data);
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
