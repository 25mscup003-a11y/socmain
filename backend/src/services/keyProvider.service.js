const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { encryptAes256Gcm, decryptAes256Gcm, canonicalize } = require('../security/cryptoPrimitives');

function decodeKey(value) {
  const text = String(value || '').trim();
  let key;
  if (/^[a-f\d]{64}$/i.test(text)) key = Buffer.from(text, 'hex');
  else key = Buffer.from(text, 'base64');
  if (key.length !== 32) {
    key.fill(0);
    throw new Error('KMS master key must decode to exactly 32 bytes');
  }
  return key;
}

function assertProtectedFile(filename) {
  const stat = fs.statSync(filename);
  if (!stat.isFile()) throw new Error('KMS master key path must be a regular file');
  if (process.platform !== 'win32' && process.env.NODE_ENV === 'production' && (stat.mode & 0o077)) {
    throw new Error('KMS master key file must not be accessible by group or other users');
  }
}

function readOrCreateDevelopmentKey(filename) {
  try {
    assertProtectedFile(filename);
    return decodeKey(fs.readFileSync(filename, 'utf8'));
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }

  fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  const generated = crypto.randomBytes(32);
  try {
    try {
      fs.writeFileSync(filename, generated.toString('base64'), {
        encoding: 'utf8',
        mode: 0o600,
        flag: 'wx',
      });
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
    }
  } finally {
    generated.fill(0);
  }
  assertProtectedFile(filename);
  return decodeKey(fs.readFileSync(filename, 'utf8'));
}

class LocalFileKeyProvider {
  constructor(options = {}) {
    this.keyFile = options.keyFile || process.env.KMS_MASTER_KEY_FILE || '';
    this.testingKey = options.testingKey || '';
    this.developmentKeyFile = options.developmentKeyFile
      || process.env.KMS_DEVELOPMENT_KEY_FILE
      || path.resolve(__dirname, '../../.runtime-secrets/ajnat-kms-master-key');
    this.keyReference = options.keyReference || `local-file:${path.basename(this.keyFile || 'injected')}`;
  }

  _readKey() {
    if (this.testingKey) return decodeKey(this.testingKey);
    if (this.keyFile) {
      try {
        assertProtectedFile(this.keyFile);
        return decodeKey(fs.readFileSync(this.keyFile, 'utf8'));
      } catch (error) {
        if (process.env.NODE_ENV === 'production' || error?.code !== 'ENOENT') throw error;
      }
    }
    if (process.env.NODE_ENV === 'production') {
      throw new Error('KMS_MASTER_KEY_FILE is required for the local KMS provider in production');
    }
    const developmentKey = process.env.KMS_MASTER_KEY_B64;
    if (developmentKey) return decodeKey(developmentKey);
    return readOrCreateDevelopmentKey(this.developmentKeyFile);
  }

  async wrapKey(dek, context) {
    const kek = this._readKey();
    try {
      const wrapped = encryptAes256Gcm(dek, kek, { operation: 'wrap-dek', ...context });
      return {
        provider: 'local-file',
        algorithm: 'AES-256-GCM',
        keyReference: this.keyReference,
        iv: wrapped.iv,
        authTag: wrapped.authTag,
        ciphertext: wrapped.ciphertext,
        encryptionContext: context,
      };
    } finally {
      kek.fill(0);
    }
  }

  async unwrapKey(wrapped, context) {
    if (wrapped.provider !== 'local-file' || wrapped.keyReference !== this.keyReference) {
      throw new Error('Wrapped key belongs to a different KMS provider or KEK');
    }
    if (canonicalize(wrapped.encryptionContext || {}) !== canonicalize(context)) {
      throw new Error('KMS encryption context mismatch');
    }
    const kek = this._readKey();
    try {
      return decryptAes256Gcm({
        algorithm: wrapped.algorithm,
        iv: wrapped.iv,
        authTag: wrapped.authTag,
        ciphertext: wrapped.ciphertext,
      }, kek, { operation: 'wrap-dek', ...context });
    } finally {
      kek.fill(0);
    }
  }

  health() {
    try {
      const key = this._readKey();
      key.fill(0);
      return { healthy: true, provider: 'local-file', keyReference: this.keyReference };
    } catch (error) {
      return { healthy: false, provider: 'local-file', error: error.message };
    }
  }
}

class AwsKmsKeyProvider {
  constructor(options = {}) {
    this.keyId = options.keyId || process.env.AWS_KMS_KEY_ID || '';
    if (!this.keyId) throw new Error('AWS_KMS_KEY_ID is required for the AWS KMS provider');
    let sdk;
    try {
      sdk = require('@aws-sdk/client-kms');
    } catch {
      throw new Error('@aws-sdk/client-kms is required when KMS_PROVIDER=aws-kms');
    }
    this.EncryptCommand = sdk.EncryptCommand;
    this.DecryptCommand = sdk.DecryptCommand;
    this.DescribeKeyCommand = sdk.DescribeKeyCommand;
    this.client = options.client || new sdk.KMSClient({ region: options.region || process.env.AWS_REGION });
    this.healthCache = null;
  }

  async wrapKey(dek, context) {
    const response = await this.client.send(new this.EncryptCommand({
      KeyId: this.keyId,
      Plaintext: dek,
      EncryptionContext: Object.fromEntries(Object.entries(context).map(([k, v]) => [k, String(v)])),
      EncryptionAlgorithm: 'SYMMETRIC_DEFAULT',
    }));
    return {
      provider: 'aws-kms', algorithm: 'AWS-KMS-SYMMETRIC-DEFAULT', keyReference: this.keyId,
      ciphertext: Buffer.from(response.CiphertextBlob).toString('base64'), encryptionContext: context,
    };
  }

  async unwrapKey(wrapped, context) {
    const response = await this.client.send(new this.DecryptCommand({
      KeyId: wrapped.keyReference,
      CiphertextBlob: Buffer.from(wrapped.ciphertext, 'base64'),
      EncryptionContext: Object.fromEntries(Object.entries(context).map(([k, v]) => [k, String(v)])),
      EncryptionAlgorithm: 'SYMMETRIC_DEFAULT',
    }));
    const key = Buffer.from(response.Plaintext);
    if (key.length !== 32) {
      key.fill(0);
      throw new Error('AWS KMS returned an invalid data-encryption key');
    }
    return key;
  }

  async health() {
    if (this.healthCache?.expiresAt > Date.now()) return this.healthCache.value;
    let value;
    try {
      const response = await this.client.send(new this.DescribeKeyCommand({ KeyId: this.keyId }));
      const metadata = response.KeyMetadata || {};
      const usable = metadata.Enabled === true
        && metadata.KeyState === 'Enabled'
        && metadata.KeyUsage === 'ENCRYPT_DECRYPT'
        && metadata.KeySpec === 'SYMMETRIC_DEFAULT';
      value = {
        healthy: usable,
        provider: 'aws-kms',
        keyReference: this.keyId,
        keyState: metadata.KeyState || 'Unknown',
        hsmCapable: true,
      };
    } catch (error) {
      value = { healthy: false, provider: 'aws-kms', keyReference: this.keyId, error: error.message, hsmCapable: true };
    }
    this.healthCache = { value, expiresAt: Date.now() + 60_000 };
    return value;
  }
}

let providerOverride = null;
let providerInstance = null;
let providerSignature = '';

function getKeyProvider() {
  if (providerOverride) return providerOverride;
  const provider = String(process.env.KMS_PROVIDER || 'local-file').toLowerCase();
  const signature = `${provider}:${process.env.AWS_KMS_KEY_ID || ''}:${process.env.KMS_MASTER_KEY_FILE || ''}:${process.env.KMS_DEVELOPMENT_KEY_FILE || ''}`;
  if (providerInstance && providerSignature === signature) return providerInstance;
  if (provider === 'aws' || provider === 'aws-kms') providerInstance = new AwsKmsKeyProvider();
  else if (provider === 'local-file') providerInstance = new LocalFileKeyProvider();
  else throw new Error(`Unsupported KMS_PROVIDER: ${provider}`);
  providerSignature = signature;
  return providerInstance;
}

function setKeyProviderForTests(provider) {
  if (process.env.NODE_ENV !== 'test') throw new Error('KMS provider override is test-only');
  providerOverride = provider;
}

module.exports = { LocalFileKeyProvider, AwsKmsKeyProvider, getKeyProvider, setKeyProviderForTests, decodeKey };
