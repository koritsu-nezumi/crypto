import { Effect, Layer, Redacted } from "effect";
import { Crypto } from "./Crypto";
import {
  concatBytes,
  copyBytes,
  equalBytes,
  randomBytes,
} from "@noble/ciphers/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { argon2id } from "@noble/hashes/argon2.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { base58, base64, hex, utf8 } from "@scure/base";

export const CryptoLayer = Layer.succeed(Crypto, {
  "~raquel/Crypto": "~raquel/Crypto",
  randomBytes: (bytesLength) => Effect.sync(() => randomBytes(bytesLength)),
  equalBytes: (a, b) => Effect.sync(() => equalBytes(a, b)),
  concatBytes: (arrays) => Effect.sync(() => concatBytes(arrays)),
  copyBytes: (bytes) => Effect.sync(() => copyBytes(bytes)),
  sha256: (msg) => Effect.sync(() => sha256(msg)),
  hkdf: (ikm, salt, info, length) =>
    Effect.sync(() => hkdf(sha256, Redacted.value(ikm), salt, info, length)),
  hmac: (key, message) =>
    Effect.sync(() => hmac(sha256, Redacted.value(key), message)),
  argon2id: (ikm, salt, opts) =>
    Effect.sync(() => argon2id(Redacted.value(ikm), salt, opts)),
  xchacha20poly1305: (key, nonce, aad) => {
    const cipher = xchacha20poly1305(Redacted.value(key), nonce, aad);
    return {
      encrypt: (plaintext) =>
        Effect.sync(() => cipher.encrypt(Redacted.value(plaintext))),
      decrypt: (ciphertext) =>
        Effect.sync(() => Redacted.make(cipher.decrypt(ciphertext))),
    };
  },
  x25519: {
    getPublicKey: (secretKey) =>
      Effect.sync(() => x25519.getPublicKey(Redacted.value(secretKey))),
    getSharedSecret: (secretKeyA, publicKeyB) =>
      Effect.sync(() =>
        Redacted.make(
          x25519.getSharedSecret(Redacted.value(secretKeyA), publicKeyB),
        ),
      ),
  },
  ed25519: {
    getPublicKey: (secretKey) =>
      Effect.sync(() => ed25519.getPublicKey(Redacted.value(secretKey))),
    sign: (message, secretKey) =>
      Effect.sync(() => ed25519.sign(message, Redacted.value(secretKey))),
    verify: (signature, message, publicKey) =>
      Effect.sync(() => ed25519.verify(signature, message, publicKey)),
  },
  utf8: {
    encode: (data) => Effect.sync(() => utf8.encode(data)),
    decode: (data) => Effect.sync(() => utf8.decode(data)),
  },
  hex: {
    encode: (data) => Effect.sync(() => hex.encode(data)),
    decode: (data) => Effect.sync(() => hex.decode(data)),
  },
  base64: {
    encode: (data) => Effect.sync(() => base64.encode(data)),
    decode: (data) => Effect.sync(() => base64.decode(data)),
  },
  base58: {
    encode: (data) => Effect.sync(() => base58.encode(data)),
    decode: (data) => Effect.sync(() => base58.decode(data)),
  },
});
