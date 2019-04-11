import _bcrypt from 'bcryptjs';
import CryptoJS from 'crypto-js';
import JSEncrypt from 'jsencrypt';

const webCrypto = window.crypto || window.msCrypto || window.webkitCrypto || window.mozCrypto;

class RSA {

  encrypt(text, publicKey) {
    const crypt = new JSEncrypt({ default_key_size: 2048 })
    crypt.setKey(publicKey);
    return Promise.resolve(crypt.encrypt(text));
  }

  decrypt(encdata, privateKey) {
    const crypt = new JSEncrypt({ default_key_size: 2048 })
    crypt.setKey(privateKey);
    return Promise.resolve(crypt.decrypt(encdata));
  }

  exportAsJwk(key) {
    return Promise.resolve(key);
  }

  genKeyPair(size, name, email) {
    const crypt = new JSEncrypt({ default_key_size: size });
    const privateKey = crypt.getPrivateKey();
    const publicKey = crypt.getPublicKey();
    return Promise.resolve({
      privateKey,
      publicKey
    });
  }
}

class AES {

  encrypt(text, masterkey) {
    return Promise.resolve(CryptoJS.AES.encrypt(text, masterkey).toString());
  }

  decrypt(encdata, masterkey) {
    return Promise.resolve(CryptoJS.AES.decrypt(encdata, masterkey).toString(CryptoJS.enc.Utf8));
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
