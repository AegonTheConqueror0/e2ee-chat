import sodium from 'libsodium-wrappers';
import { encryptSymmetric, decryptSymmetric, generateRoomKey, initSodium } from './crypto';

/**
 * Proves that the server cannot decrypt stored data.
 * This test simulates a server-side environment (without the room key).
 */
export async function runSecurityTest() {
  await initSodium();
  
  const roomKey = generateRoomKey();
  const plaintext = "This is a highly sensitive message.";
  
  // 1. Client encrypts the message
  const encrypted = encryptSymmetric(plaintext, roomKey);
  console.log("Encrypted Data (Stored on Server):", encrypted);
  
  // 2. Server attempts to decrypt without the key
  const fakeKey = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  
  try {
    decryptSymmetric(encrypted, fakeKey);
    console.error("❌ SECURITY FAILURE: Server decrypted the message with a fake key!");
  } catch (err) {
    console.log("✅ SECURITY SUCCESS: Server failed to decrypt without the correct key.");
  }
  
  // 3. Client decrypts with the correct key
  const decrypted = decryptSymmetric(encrypted, roomKey);
  if (decrypted === plaintext) {
    console.log("✅ INTEGRITY SUCCESS: Client correctly decrypted the message.");
  } else {
    console.error("❌ INTEGRITY FAILURE: Decrypted message does not match plaintext.");
  }
}
