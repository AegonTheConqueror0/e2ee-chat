# E2EE Chat - Secure Messaging Application

A highly secure, end-to-end encrypted chat application built with React, TypeScript, and Firebase. This application ensures that only the intended recipients can read messages, and the server never has access to plaintext data or private keys.

## 🛡️ Security Architecture

### 1. Cryptography
- **Asymmetric Encryption**: X25519 (ECDH) via `libsodium`'s `crypto_box` for secure key exchange.
- **Symmetric Encryption**: XChaCha20-Poly1305 for high-performance, authenticated encryption of messages and files.
- **Signing**: Ed25519 for message authenticity and non-repudiation.
- **Key Derivation**: Argon2id for deriving strong encryption keys from user passphrases for backups.

### 2. Key Management
- **Identity Keys**: Generated client-side and stored in IndexedDB. Private keys never leave the device in plaintext.
- **Room Keys**: A unique symmetric key is generated for each room. This key is encrypted for each member's public exchange key and stored in Firestore.
- **Multi-Device Sync**: Supported by encrypting the room key for each registered device public key of a user.
- **Key Backup**: Private keys are encrypted with a passphrase-derived key (Argon2) before being uploaded to the server as a backup.

### 3. Metadata Minimization
- **Encrypted Fields**: Room names, message content, and file attachments are all encrypted.
- **Plaintext Fields**: Only essential metadata for routing and access control (Room IDs, Member UIDs, Timestamps) are stored in plaintext.

## 🕵️ Threat Model

| Threat | Mitigation |
| --- | --- |
| **Server Compromise** | All sensitive data is encrypted client-side. The attacker only sees ciphertexts and metadata. |
| **Database Leak** | Same as above. Without private keys, the data is useless. |
| **Man-in-the-Middle** | Messages are signed with Ed25519, ensuring authenticity and integrity. |
| **Brute-Force Backup** | Argon2id with high memory/time costs makes brute-forcing passphrases computationally expensive. |
| **Device Theft** | Private keys are stored in IndexedDB. Users should use OS-level encryption and strong device passwords. |

## 🚀 Getting Started

1. **Sign In**: Use your Google account to authenticate.
2. **Setup Keys**: Generate your identity keys. You can choose to backup your keys with a strong passphrase.
3. **Create a Room**: Start a new secure room. A unique key will be generated for it.
4. **Add Members**: Share your UID with others. Add them to your room using their UID.
5. **Chat Securely**: All messages and files are encrypted before they leave your device.

## 🛠️ Tech Stack
- **Frontend**: React, Vite, Tailwind CSS, shadcn/ui, Framer Motion.
- **Backend**: Firebase Auth, Firestore, Firebase Storage.
- **Crypto**: libsodium-wrappers, argon2-browser.

## 🧪 Security Verification
To verify that the server cannot decrypt your data:
1. Open the Firestore console.
2. Navigate to a `messages` document.
3. Observe the `ciphertext` and `nonce` fields.
4. Attempt to decrypt them without the room key (impossible).
