import {Injectable} from '@angular/core';

import * as crypto from 'crypto';

@Injectable({
  providedIn: 'root'
})
export class EncryptionUtilService {

  constructor() {
  }

  async encryptKey(value, aes, hmac) {
    try {
      const aesK = aes;
      const hmacK = hmac;
      const rest = value;
      return await this.encryptAes(rest, aesK, hmacK);
    } catch (e) {
      // console.log('encryptKey: error: ', e);
      return value;
    }
  };

  async decryptKey(value: string, aes: string, hmac: string) {
    try {
      const aesK = aes;
      const hmacK = hmac;
      const rest = value;
      return await this.decryptAes(rest, aesK, hmacK);
    } catch (e) {
      // console.log('decryptKey: error: ', e);
      return value;
    }
  }

  async encryptRSA(value, privateKey) {
    try {
      const key = '-----BEGIN PUBLIC KEY-----\n' + privateKey + '\n-----END PUBLIC KEY-----';
      let encryptBuff = crypto.publicEncrypt(
        {
          key,
          padding: crypto.constants.RSA_PKCS1_PADDING,
        },
        Buffer.from(value)
      );
      return encryptBuff.toString('base64');
    } catch (e) {
      // console.log('encryptRSA: error: ', e);
      return value;
    }
  };

  async decryptRSA(value, privateKey) {
    try {
      const key = '-----BEGIN PRIVATE KEY-----\n' + privateKey + '\n-----END PRIVATE KEY-----';
      const paddingValue = crypto.constants.RSA_PKCS1_PADDING;

      // @ts-ignore
      const msg = new Buffer.from(value, 'base64');
      return crypto.privateDecrypt({key, padding: paddingValue}, msg).toString();
    } catch (e) {
      // console.log('decryptRSA: error: ', e);
      return value;
    }
  };

  async encryptAes(plainText, aesK, hmack) {
    const valueToEncrypt = plainText.replace(/['"]+/g, '');

    let aesKey = Buffer.from(aesK, 'utf8');
    aesKey = Buffer.from(aesK, 'base64');

    // let aesHmac = Buffer.from(hmack, 'utf8');
    // // @ts-ignore
    // aesHmac = Buffer.from(aesHmac, 'base64');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(await this.getAlgorithm(aesKey), aesKey, iv);

    let cipherText = Buffer.concat([cipher.update(Buffer.from(valueToEncrypt, 'utf8')), cipher.final()]);
    const ivCipherText = Buffer.concat([iv, cipherText]);
    const hmac = crypto.createHmac('SHA256', Buffer.from(hmack, 'base64')).update(ivCipherText).digest();
    const ivCipherTextHmac = Buffer.concat([ivCipherText, hmac]);

    return ivCipherTextHmac.toString('base64');
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
