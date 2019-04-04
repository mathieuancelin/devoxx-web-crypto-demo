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