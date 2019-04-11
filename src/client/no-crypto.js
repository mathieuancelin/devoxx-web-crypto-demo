import _bcrypt from 'bcryptjs';

const webCrypto = window.crypto || window.msCrypto || window.webkitCrypto || window.mozCrypto;

class RSA {

  encrypt(text, publicKey) {
    return Promise.resolve(text);
  }

  decrypt(encdata, privateKey) {
    return Promise.resolve(encdata);
  }

  exportAsJwk(key) {
    return Promise.resolve(key);
  }

  genKeyPair(size, name, email) {
    return Promise.resolve({
      privateKey: 'private',
      publicKey: 'public'
    });
  }
}

class AES {

  encrypt(text, masterkey) {
    return Promise.resolve(text);
  }

  decrypt(encdata, masterkey) {
    return Promise.resolve(encdata);
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
