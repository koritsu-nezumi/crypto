import { Crypto } from "...";
import { Layer } from "effect";
import { concatBytes, copyBytes, equalBytes, randomBytes } from "@noble/ciphers/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { argon2id } from "@noble/hashes/argon2.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { base58, base64, hex, utf8 } from "@scure/base";

export const CryptoLayer = Layer.succeed(Crypto, {
  "~raquel/Crypto": "~raquel/Crypto",
  randomBytes: (bytesLength) => randomBytes(bytesLength),
  equalBytes: (a, b) => equalBytes(a, b),
  concatBytes: (arrays) => concatBytes(arrays),
  copyBytes: (bytes) => copyBytes(bytes),
  sha256: (msg) => sha256(msg),
  hkdf: (ikm, salt, info, length) => hkdf(sha256, ikm,  salt, info, length),
  hmac: (key, message) => hmac(sha256, key, message),
  argon2id: (ikm, salt, opts) => argon2id(ikm, salt, opts),
  xchacha20poly1305: (key, nonce, aad) => xchacha20poly1305(key, nonce, aad),
  x25519: {
    getPublicKey: (secretKey) => x25519.getPublicKey(secretKey),
    getSharedSecret: (secretKeyA, publicKeyB) => x25519.getSharedSecret(secretKeyA, publicKeyB),
  },
  ed25519: {
    getPublicKey: (secretKey) => ed25519.getPublicKey(secretKey),
    sign: (message, secretKey) => ed25519.sign(message, secretKey),
    verify: (signature, message, publicKey) => ed25519.verify(signature, message, publicKey),
  },
  utf8: {
    encode:(data) => utf8.encode(data),
    decode:(data) => utf8.decode(data),
  },
  hex: {
    encode:(data) => hex.encode(data),
    decode:(data) => hex.decode(data),
  },
  base64: {
    encode: (data) => base64.encode(data),
    decode: (data) => base64.decode(data),
  },
  base58: {
    encode: (data) => base58.encode(data),
    decode: (data) => base58.decode(data),
  }
});

