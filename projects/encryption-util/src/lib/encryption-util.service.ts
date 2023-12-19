import { Injectable } from '@angular/core';

import * as crypto from 'crypto';
import * as forge from 'node-forge';

@Injectable({
  providedIn: 'root',
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
      return value;
    }
  }

  async encryptKeyGCM(value, aes, hmac) {
    try {
      const aesK = aes;
      const hmacK = hmac;
      const rest = value;
      return await this.encryptAesGCM(rest, aesK, hmacK);
    } catch (e) {
      return value;
    }
  };

  async decryptKeyGCM(value: string, aes: string, hmac: string) {
    try {
      const aesK = aes;
      const hmacK = hmac;
      const rest = value;
      return await this.decryptAesGCM(rest, aesK, hmacK);
    } catch (e) {
      return value;
    }
  }

  async encryptRSA(value, publicKey) {
    try {
      // const key = '-----BEGIN PUBLIC KEY-----\n' + publicKey + '\n-----END PUBLIC KEY-----';
      const normalizedPublicKeyKey = this._toKeyWithPem(
        publicKey,
        'public',
      );
      let encryptBuff = crypto.publicEncrypt(
        {
          key: normalizedPublicKeyKey,
          padding: crypto.constants.RSA_PKCS1_PADDING,
        },
        Buffer.from(value),
      );
      return encryptBuff.toString('base64');
    } catch (e) {
      return value;
    }
  };

  async decryptRSA(value, privateKey) {
    try {
      // const key = '-----BEGIN PRIVATE KEY-----\n' + privateKey + '\n-----END PRIVATE KEY-----';
      const normalizedPrivateKey = this._toKeyWithPem(
        privateKey,
        'private',
      );
      const paddingValue = crypto.constants.RSA_PKCS1_PADDING;

      // @ts-ignore
      const msg = new Buffer.from(value, 'base64');
      return crypto.privateDecrypt({
          key: normalizedPrivateKey,
          padding: paddingValue,
        },
        msg,
      ).toString();
    } catch (e) {
      return value;
    }
  };

  async encryptAes(plainText, aesK, hmack) {
    try {
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
    } catch (e) {
      return plainText;
    }
  }

  async decryptAes(encryptedValue: string, aesK: string, hmacK: string) {
    try {
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
    } catch (e) {
      return encryptedValue;
    }
  }

  async encryptAesGCM(plainText, aesK, hmack) {
    try {
      const valueToEncrypt = plainText.replace(/['"]+/g, '');

      let aesKey = Buffer.from(aesK, 'utf8');
      aesKey = Buffer.from(aesK, 'base64');

      // let aesHmac = Buffer.from(hmack, 'utf8');
      // // @ts-ignore
      // aesHmac = Buffer.from(aesHmac, 'base64');
      const iv = crypto.randomBytes(12);
      // const cipher = crypto.createCipheriv(await this.getAlgorithmGCM(aesKey), aesKey, iv);
      const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);

      let cipherText = Buffer.concat([cipher.update(Buffer.from(valueToEncrypt, 'utf8')), cipher.final()]);
      const ivCipherText = Buffer.concat([iv, cipherText]);
      const hmac = crypto.createHmac('SHA256', Buffer.from(hmack, 'base64')).update(ivCipherText).digest();
      const ivCipherTextHmac = Buffer.concat([ivCipherText, hmac]);

      return ivCipherTextHmac.toString('base64');
    } catch (e) {
      return plainText;
    }
  }

  async decryptAesGCM(encryptedValue: string, aesK: string, hmacK: string) {
    try {
      const ivCipherTextHmac = Buffer.from(encryptedValue, 'base64');
      const aesKey = Buffer.from(aesK, 'base64');
      const hmacKey = Buffer.from(hmacK, 'utf8');
      const macLength = crypto.createHmac('sha256', hmacKey).digest().length;

      const cipherTextLength = ivCipherTextHmac.length - macLength;
      const iv = ivCipherTextHmac.slice(0, 12);
      const cipherText = ivCipherTextHmac.slice(12, cipherTextLength);
      // const cipherText = ivCipherTextHmac.slice(12);
      // const decipher = crypto.createDecipheriv(await this.getAlgorithmGCM(aesKey), aesKey, iv);
      const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);

      let decrypted = decipher.update(cipherText);
      // @ts-ignore
      decrypted += decipher.final();

      return decrypted.toString();
    } catch (e) {
      return encryptedValue;
    }
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

  async getAlgorithmGCM(keyBase64: any) {
    const key = Buffer.from(keyBase64, 'base64');
    switch (key.length) {
      case 16:
        return 'aes-128-gcm';
      case 32:
        return 'aes-256-gcm';
    }
    throw new Error('getAlgorithmGCM: Invalid key length: ' + key.length);
  }

  async encryptRSAOAEP(value, publicKey) {
    try {
      const normalizedPublicKey = this._toKeyWithPem(
        publicKey,
        'public',
      );
      console.log(normalizedPublicKey);

      const publicKeyFromPem = forge.pki.publicKeyFromPem(normalizedPublicKey);
      const encrypted = publicKeyFromPem.encrypt(value, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: {
          md: forge.md.sha1.create(),
        },
      });
      return forge.util.encode64(encrypted);
    } catch (e) {
      console.log('encryptRSAOAE: error: ', e);
      return new Promise<string>((resolve, reject) => {
        resolve(value);
      });
    }
  };

  async decryptRSAOAEP(value, privateKey) {
    try {
      const normalizedPrivateKey = this._toKeyWithPem(
        privateKey,
        'private',
      );
      const privateKeyFromPem = forge.pki.privateKeyFromPem(normalizedPrivateKey);
      var decrypted = privateKeyFromPem.decrypt(forge.util.decode64(value), 'RSA-OAEP', { // esto es el dato desencriptado
        md: forge.md.sha256.create(),
        mgf1: {
          md: forge.md.sha256.create(),
        },
      });
      return decrypted;
    } catch (error) {
      return new Promise<string>((resolve, reject) => {
        resolve(value);
      });
    }
  }

  _toKeyWithPem(key, type) {
    let localKey = key;

    if (!localKey) {
      return localKey;
    }

    if (type === 'public') {
      localKey =
        '-----BEGIN PUBLIC KEY-----\n' + key + '\n-----END PUBLIC KEY-----';
    }

    if (type === 'private') {
      localKey =
        '-----BEGIN PRIVATE KEY-----\n' + key + '\n-----END PRIVATE KEY-----';
    }
    return localKey;
  }

}
