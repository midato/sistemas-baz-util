import {Injectable} from '@angular/core';

import * as crypto from 'crypto';

@Injectable({
  providedIn: 'root'
})
export class EncryptionUtilService {

  constructor() {
  }

  async encryptKey(valor, aes, hmac) {
    const aesK = aes;
    const hmack = hmac;
    var rest = valor;
    let encrypted = await this.encryptAes(rest, aesK, hmack);
    // console.log('encryptKey: encrypted key: ' + encrypted);
    return encrypted;
  };

  async decryptKey(path: string, aes: string, hmac: string) {
    const aesK = aes;
    const hmack = hmac;
    var rest = path;
    let decrypted = await this.decryptAes(rest, aesK, hmack);
    // console.log('decryptKey: decrypted key: ' + decrypted);
    return decrypted;
  }

  async encryptAes(plainText, aesK, hmack) {
    var datoAcifrar = plainText.replace(/['"]+/g, '');
    var aesKey = Buffer.from(aesK, 'utf8');
    aesKey = Buffer.from(aesK, 'base64');
    var aesHmac = Buffer.from(hmack, 'utf8');
    // @ts-ignore
    aesHmac = Buffer.from(aesHmac, 'base64');
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv(await this.getAlgorithm(aesKey), aesKey, iv);
    let cipherText = Buffer.concat([cipher.update(Buffer.from(datoAcifrar, 'utf8')), cipher.final()]);
    const iv_cipherText = Buffer.concat([iv, cipherText]);
    var hmac = crypto.createHmac('SHA256', Buffer.from(hmack, 'base64')).update(iv_cipherText).digest();
    const iv_cipherText_hmac = Buffer.concat([iv_cipherText, hmac]);
    const iv_cipherText_hmac_base64 = iv_cipherText_hmac.toString('base64');

    return iv_cipherText_hmac_base64;
  }

  async decryptAes(encryptedValue: string, aesK: string, hmacK: string) {
    const ivCipherTextHmac = Buffer.from(encryptedValue, 'base64');
    const aesKey = Buffer.from(aesK, 'base64');
    const hmacKey = Buffer.from(hmacK, 'utf8');
    const macLength = crypto.createHmac('sha256', hmacKey).digest().length;

    const cipherTextLength = ivCipherTextHmac.length - macLength;
    const iv = ivCipherTextHmac.slice(0, 16);
    const cipherText = ivCipherTextHmac.slice(16, cipherTextLength);
    const decipher = crypto.createDecipheriv(await this.getAlgorithm(aesKey), aesKey, iv);

    let decrypted = decipher.update(cipherText);
    // @ts-ignore
    decrypted += decipher.final();

    return decrypted.toString();
  }

  encryptRSA(valor, pubKey) {
    let encryptBuff = crypto.publicEncrypt(
      {
        key: pubKey,
        padding: crypto.constants.RSA_PKCS1_PADDING,
      },
      Buffer.from(valor)
    );
    return encryptBuff.toString('base64');
  };

  decryptRSA(valor, privKey) {
    const paddingValue = crypto.constants.RSA_PKCS1_PADDING;
    // @ts-ignore
    var msg = new Buffer.from(valor, 'base64');
    var descryptValue = crypto.privateDecrypt({key: privKey, padding: paddingValue}, msg);
    return descryptValue.toString();
  };

  async getAlgorithm(keyBase64: any) {
    const key = Buffer.from(keyBase64, 'base64');
    switch (key.length) {
      case 16:
        return 'aes-128-cbc';
      case 32:
        return 'aes-256-cbc';
    }
    throw new Error('getAlgorithm: Invalid key length: ' + key.length);
  }

}
