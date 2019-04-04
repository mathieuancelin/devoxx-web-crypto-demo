const crypto = require('crypto');
const bcrypt = require('bcrypt');

exports.bcrypt = bcrypt;

exports.rsa = {
  encrypt: (text, publicKey) => {
    const buffer = Buffer.from(text);
    const encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString("base64");
  },
  decrypt: (encdata, privateKey) => {
    const buffer = Buffer.from(encdata, "base64");
    const decrypted = crypto.privateDecrypt(privateKey, buffer);
    return decrypted.toString("utf8");
  },
  genKeyPair: () => {
    return crypto.generateKeyPairSync('rsa', {
      modulusLength: 4096,  // the length of your key in bits
      publicKeyEncoding: {
        type: 'spki',       // recommended to be 'spki' by the Node.js docs
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',      // recommended to be 'pkcs8' by the Node.js docs
        format: 'pem'
      }
    });
  }
};

exports.aes = {
  encrypt: (text, masterkey) => {
    const iv = crypto.randomBytes(16);
    const salt = crypto.randomBytes(64);
    const key = crypto.pbkdf2Sync(masterkey, salt, 2145, 32, 'sha512');
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
  },
  decrypt: (encdata, masterkey) => {
    const bData = Buffer.from(encdata, 'base64');
    const salt = bData.slice(0, 64);
    const iv = bData.slice(64, 80);
    const tag = bData.slice(80, 96);
    const text = bData.slice(96);
    const key = crypto.pbkdf2Sync(masterkey, salt , 2145, 32, 'sha512');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = decipher.update(text, 'binary', 'utf8') + decipher.final('utf8');
    return decrypted;
  }
};

