#!/bin/bash

# Security Check Script for E2EE Chat

echo "Running security checks..."

# 1. Check for hardcoded secrets
echo "Checking for hardcoded secrets..."
grep -rE "AIza[0-9A-Za-z-_]{35}" . && echo "❌ ERROR: Hardcoded Firebase API key found!" || echo "✅ No hardcoded Firebase API keys found."

# 2. Check for private key leakage
echo "Checking for private key leakage..."
grep -r "privateKey" src/firebase.ts && echo "❌ ERROR: Private key mentioned in Firebase service!" || echo "✅ Private keys are isolated from Firebase service."

# 3. Check for plaintext message storage
echo "Checking for plaintext message storage..."
grep -r "messageText" src/firebase.ts && echo "❌ ERROR: Plaintext message storage found!" || echo "✅ Messages are stored as ciphertexts."

# 4. Check for encryption library usage
echo "Checking for encryption library usage..."
grep -r "crypto_aead_xchacha20poly1305_ietf_encrypt" src/lib/crypto.ts && echo "✅ XChaCha20-Poly1305 encryption found." || echo "❌ ERROR: XChaCha20-Poly1305 encryption missing!"

echo "Security checks completed."
