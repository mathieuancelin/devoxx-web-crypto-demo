import _bcrypt from 'bcryptjs';
import openpgp, { message, key , stream } from 'openpgp';

openpgp.message = message;
openpgp.key = key;
openpgp.stream = stream;
openpgp.initWorker({ path: 'openpgp/openpgp.worker.js' });

const webCrypto = window.crypto || window.msCrypto || window.webkitCrypto || window.mozCrypto;

class RSA {

  encrypt(text, publicKey) {
    return openpgp.key.readArmored(publicKey).then(keys => {
      return openpgp.encrypt({
        message: openpgp.message.fromText(text),
        publicKeys: keys.keys,
      }).then(encrypted => {
        return openpgp.stream.readToEnd(encrypted.data);
      })
    });
  }

  decrypt(encdata, privateKey) {
    return openpgp.key.readArmored(privateKey).then(keys => {
      return openpgp.message.readArmored(encdata).then(m => {
        return openpgp.decrypt({
          message: m,
          privateKeys: keys.keys,
        }).then(decrypted => {
          return openpgp.stream.readToEnd(decrypted.data);
        })
      });
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
    return openpgp.encrypt({
      message: openpgp.message.fromText(text),
      passwords: [masterkey],
      armor: true
    }).then(encrypted => {
      return openpgp.stream.readToEnd(encrypted.data);
    });
  }

  decrypt(encdata, masterkey) {
    return openpgp.message.readArmored(encdata).then(m => {
      return openpgp.decrypt({
        message: m,
        passwords: [masterkey],
        format: 'string'
      }).then(decrypted => {
        return openpgp.stream.readToEnd(decrypted.data);
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