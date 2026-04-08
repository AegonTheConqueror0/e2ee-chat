import sodium from 'libsodium-wrappers-sumo';
import { get, set, del } from 'idb-keyval';

// --- Types ---

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface EncryptedData {
  ciphertext: string; // Base64
  nonce: string; // Base64
}

export interface IdentityKeys {
  signing: KeyPair; // Ed25519
  exchange: KeyPair; // X25519
}

// --- Initialization ---

let isSodiumReady = false;
export async function initSodium() {
  if (isSodiumReady) return;
  await sodium.ready;
  isSodiumReady = true;
}

// --- Key Management ---

const KEYS_STORE_NAME = 'e2ee-keys';

export async function generateIdentityKeys(): Promise<IdentityKeys> {
  await initSodium();
  const signing = sodium.crypto_sign_keypair();
  const exchange = sodium.crypto_box_keypair();
  
  return {
    signing: {
      publicKey: signing.publicKey,
      privateKey: signing.privateKey,
    },
    exchange: {
      publicKey: exchange.publicKey,
      privateKey: exchange.privateKey,
    },
  };
}

export async function saveKeysLocally(keys: IdentityKeys) {
  // Store as Base64 strings in IndexedDB for persistence
  const serialized = {
    signing: {
      publicKey: sodium.to_base64(keys.signing.publicKey),
      privateKey: sodium.to_base64(keys.signing.privateKey),
    },
    exchange: {
      publicKey: sodium.to_base64(keys.exchange.publicKey),
      privateKey: sodium.to_base64(keys.exchange.privateKey),
    },
  };
  await set(KEYS_STORE_NAME, serialized);
}

export async function loadKeysLocally(): Promise<IdentityKeys | null> {
  await initSodium();
  const serialized = await get(KEYS_STORE_NAME);
  if (!serialized) return null;

  return {
    signing: {
      publicKey: sodium.from_base64(serialized.signing.publicKey),
      privateKey: sodium.from_base64(serialized.signing.privateKey),
    },
    exchange: {
      publicKey: sodium.from_base64(serialized.exchange.publicKey),
      privateKey: sodium.from_base64(serialized.exchange.privateKey),
    },
  };
}

export async function clearKeysLocally() {
  await del(KEYS_STORE_NAME);
}

// --- Base64 Helpers ---

export function toBase64(data: Uint8Array): string {
  return sodium.to_base64(data);
}

export function fromBase64(data: string): Uint8Array {
  return sodium.from_base64(data);
}

// --- Symmetric Encryption (XChaCha20-Poly1305) ---

export function encryptSymmetric(data: string | Uint8Array, key: Uint8Array): EncryptedData {
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const message = typeof data === 'string' ? sodium.from_string(data) : data;
  
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    message,
    null,
    null,
    nonce,
    key
  );

  return {
    ciphertext: sodium.to_base64(ciphertext),
    nonce: sodium.to_base64(nonce),
  };
}

export function decryptSymmetric(encrypted: EncryptedData, key: Uint8Array): string {
  const ciphertext = sodium.from_base64(encrypted.ciphertext);
  const nonce = sodium.from_base64(encrypted.nonce);
  
  const decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    null,
    nonce,
    key
  );

  return sodium.to_string(decrypted);
}

// --- Asymmetric Encryption (X25519 / crypto_box) ---

export function encryptAsymmetric(data: string, recipientPublicKey: Uint8Array, senderPrivateKey: Uint8Array): EncryptedData {
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
  const message = sodium.from_string(data);
  
  const ciphertext = sodium.crypto_box_easy(
    message,
    nonce,
    recipientPublicKey,
    senderPrivateKey
  );

  return {
    ciphertext: sodium.to_base64(ciphertext),
    nonce: sodium.to_base64(nonce),
  };
}

export function decryptAsymmetric(encrypted: EncryptedData, senderPublicKey: Uint8Array, recipientPrivateKey: Uint8Array): string {
  const ciphertext = sodium.from_base64(encrypted.ciphertext);
  const nonce = sodium.from_base64(encrypted.nonce);
  
  const decrypted = sodium.crypto_box_open_easy(
    ciphertext,
    nonce,
    senderPublicKey,
    recipientPrivateKey
  );

  return sodium.to_string(decrypted);
}

// --- Signing (Ed25519) ---

export function signData(data: string, privateKey: Uint8Array): string {
  const signature = sodium.crypto_sign_detached(sodium.from_string(data), privateKey);
  return sodium.to_base64(signature);
}

export function verifySignature(data: string, signature: string, publicKey: Uint8Array): boolean {
  try {
    return sodium.crypto_sign_verify_detached(
      sodium.from_base64(signature),
      sodium.from_string(data),
      publicKey
    );
  } catch {
    return false;
  }
}

// --- Key Derivation (Argon2 via libsodium) ---

export async function deriveKeyFromPassphrase(passphrase: string, salt: Uint8Array): Promise<Uint8Array> {
  await initSodium();
  return sodium.crypto_pwhash(
    32,
    passphrase,
    salt,
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  );
}

export async function backupKeys(keys: IdentityKeys, passphrase: string): Promise<EncryptedData & { salt: string }> {
  await initSodium();
  const salt = sodium.randombytes_buf(16);
  const backupKey = await deriveKeyFromPassphrase(passphrase, salt);
  
  const serializedKeys = JSON.stringify({
    signing: sodium.to_base64(keys.signing.privateKey),
    exchange: sodium.to_base64(keys.exchange.privateKey),
  });
  
  const encrypted = encryptSymmetric(serializedKeys, backupKey);
  
  return {
    ...encrypted,
    salt: sodium.to_base64(salt),
  };
}

export async function restoreKeys(backup: EncryptedData & { salt: string }, passphrase: string, publicKeys: { signing: Uint8Array, exchange: Uint8Array }): Promise<IdentityKeys> {
  await initSodium();
  const salt = sodium.from_base64(backup.salt);
  const backupKey = await deriveKeyFromPassphrase(passphrase, salt);
  
  const decrypted = decryptSymmetric(backup, backupKey);
  const parsed = JSON.parse(decrypted);
  
  return {
    signing: {
      publicKey: publicKeys.signing,
      privateKey: sodium.from_base64(parsed.signing),
    },
    exchange: {
      publicKey: publicKeys.exchange,
      privateKey: sodium.from_base64(parsed.exchange),
    },
  };
}

// --- Room Keys ---

export function generateRoomKey(): Uint8Array {
  return sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
}
