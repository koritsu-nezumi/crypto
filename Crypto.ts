import { Context } from "effect";

/** @internal DO NOT EXPORT */
const TypeId = "~raquel/Crypto";

/**
 * Cryptographic primitives service.
 *
 * Groups byte utilities, hashing, key derivation, authenticated encryption,
 * message authentication, key exchange, digital signatures and text encodings
 * behind a single injectable service.
 *
 * @since 1.0.0
 * @category Services
 */
export class Crypto extends Context.Service<
  Crypto,
  {
    /** @internal */
    readonly [TypeId]: typeof TypeId;

    /**
     * Generates cryptographically secure random bytes.
     *
     * @param bytesLength - The number of random bytes to generate.
     * @returns A new `Uint8Array` of the requested length.
     *
     * @since 1.0.0
     * @category Bytes
     */
    readonly randomBytes: (bytesLength: number) => Uint8Array;

    /**
     * Compares two byte arrays for equality.
     *
     * @param a - The first byte array.
     * @param b - The second byte array.
     * @returns `true` if both arrays have the same length and contents.
     *
     * @since 1.0.0
     * @category Bytes
     */
    readonly equalBytes: (a: Uint8Array, b: Uint8Array) => boolean;

    /**
     * Concatenates multiple byte arrays into a single new array.
     *
     * @param arrays - The byte arrays to concatenate, in order.
     * @returns A new `Uint8Array` containing all the input bytes.
     *
     * @since 1.0.0
     * @category Bytes
     */
    readonly concatBytes: (...arrays: Uint8Array[]) => Uint8Array;
    
    /**
     * Creates an independent copy of a byte array.
     *
     * @param bytes - The byte array to copy.
     * @returns A new `Uint8Array` that does not share memory with the input.
     *
     * @since 1.0.0
     * @category Bytes
     */
    readonly copyBytes: (bytes: Uint8Array) => Uint8Array;
    
    /**
     * Computes the SHA-256 hash of a message.
     *
     * @param msg - The message to hash.
     * @returns The 32-byte digest.
     *
     * @since 1.0.0
     * @category Hashing
     */
    readonly sha256: (msg: Uint8Array) => Uint8Array;
    
    /**
     * Derives key material using HKDF (RFC 5869).
     *
     * @param ikm - The input keying material.
     * @param salt - An optional salt. When omitted, a default is used.
     * @param info - Optional context and application specific information.
     * @param length - The number of bytes to derive.
     * @returns The derived key material of the requested length.
     *
     * @since 1.0.0
     * @category Key derivation
     */
    readonly hkdf: (
      ikm: Uint8Array,
      salt: Uint8Array | undefined,
      info: Uint8Array | undefined,
      length: number,
    ) => Uint8Array;

    /**
     * Hashes a password using Argon2id.
     *
     * @param ikm - The password (input keying material) to hash.
     * @param salt - A unique salt for this password.
     * @param opts - Optional cost parameters.
     * @param opts.m - Memory cost, in KiB.
     * @param opts.t - Time cost, as a number of iterations.
     * @param opts.p - Parallelism degree.
     * @returns The derived hash.
     *
     * @since 1.0.0
     * @category Password hashing
     */
    readonly argon2id: (
      ikm: Uint8Array,
      salt: Uint8Array,
      opts?: { m: number; t: number; p: number },
    ) => Uint8Array;
    
    /**
     * Creates an XChaCha20-Poly1305 authenticated encryption (AEAD) cipher.
     *
     * @param key - The 32-byte secret key.
     * @param nonce - The 24-byte nonce. Must never be reused with the same key.
     * @param aad - Optional additional authenticated data. It is authenticated
     *   but not encrypted, and must be the same on encryption and decryption.
     * @returns An object with `encrypt` and `decrypt` operations bound to the
     *   given key, nonce and AAD.
     *
     * @since 1.0.0
     * @category Encryption
     */
    readonly xchacha20poly1305: (
      key: Uint8Array,
      nonce: Uint8Array,
      aad?: Uint8Array,
    ) => {
      /**
       * Encrypts and authenticates a plaintext.
       *
       * @param plaintext - The data to encrypt.
       * @returns The ciphertext followed by the authentication tag.
       */
      readonly encrypt: (plaintext: Uint8Array) => Uint8Array;

      /**
       * Verifies and decrypts a ciphertext.
       *
       * @param ciphertext - The ciphertext followed by its authentication tag.
       * @returns The original plaintext.
       * @throws If authentication fails (tampered data, wrong key, nonce or AAD).
       */
      readonly decrypt: (ciphertext: Uint8Array) => Uint8Array;
    };

    /**
     * Computes a message authentication code (HMAC).
     *
     * @param key - The secret key.
     * @param message - The message to authenticate.
     * @returns The authentication tag.
     *
     * @since 1.0.0
     * @category Message authentication
     */
    readonly hmac: (key: Uint8Array, message: Uint8Array) => Uint8Array;

    /**
     * X25519 Diffie-Hellman key exchange.
     *
     * @since 1.0.0
     * @category Key exchange
     */
    readonly x25519: {
      /**
       * Derives the public key that corresponds to a secret key.
       *
       * @param secretKey - The 32-byte secret key.
       * @returns The 32-byte public key.
       */
      readonly getPublicKey: (secretKey: Uint8Array) => Uint8Array;

      /**
       * Computes a shared secret between two parties.
       *
       * @param secretKeyA - Your own secret key.
       * @param publicKeyB - The other party's public key.
       * @returns The 32-byte shared secret.
       */
      readonly getSharedSecret: (
        secretKeyA: Uint8Array,
        publicKeyB: Uint8Array,
      ) => Uint8Array;
    };

    /**
     * Ed25519 digital signatures.
     *
     * @since 1.0.0
     * @category Signatures
     */
    readonly ed25519: {
      /**
       * Derives the public key that corresponds to a secret key.
       *
       * @param secretKey - The 32-byte secret key.
       * @returns The 32-byte public key.
       */
      readonly getPublicKey: (secretKey: Uint8Array) => Uint8Array;

      /**
       * Signs a message.
       *
       * @param message - The message to sign.
       * @param secretKey - The signer's secret key.
       * @returns The 64-byte signature.
       */
      readonly sign: (message: Uint8Array, secretKey: Uint8Array) => Uint8Array;

      /**
       * Verifies a signature.
       *
       * @param signature - The signature to verify.
       * @param message - The message that was signed.
       * @param publicKey - The signer's public key.
       * @returns `true` if the signature is valid for the message and key.
       */
      readonly verify: (
        signature: Uint8Array,
        message: Uint8Array,
        publicKey: Uint8Array,
      ) => boolean;
    };

    /**
     * UTF-8 conversion between bytes and text.
     *
     * @since 1.0.0
     * @category Encoding
     */
    readonly utf8: {
      /**
       * Converts UTF-8 bytes into a string.
       *
       * @param data - The UTF-8 encoded bytes.
       * @returns The decoded string.
       */
      readonly encode: (data: Uint8Array) => string,

      /**
       * Converts a string into UTF-8 bytes.
       *
       * @param data - The string to convert.
       * @returns The UTF-8 encoded bytes.
       */
      readonly decode: (data: string) => Uint8Array,
    };

    /**
     * Hexadecimal conversion between bytes and text.
     *
     * @since 1.0.0
     * @category Encoding
     */
    readonly hex: {
      /**
       * Converts bytes into a hexadecimal string.
       *
       * @param data - The bytes to encode.
       * @returns The hexadecimal representation.
       */
      readonly encode: (data: Uint8Array) => string,

      /**
       * Converts a hexadecimal string into bytes.
       *
       * @param data - The hexadecimal string to decode.
       * @returns The decoded bytes.
       */
      readonly decode: (data: string) => Uint8Array,
    };

    /**
     * Base64 conversion between bytes and text, intended for machine
     * consumption (compact, not meant to be read or typed by people).
     *
     * @since 1.0.0
     * @category Encoding
     */
    readonly base64: {
      /**
       * Converts bytes into a Base64 string.
       *
       * @param data - The bytes to encode.
       * @returns The Base64 representation.
       */
      readonly encode: (data: Uint8Array) => string,
      
      /**
       * Converts a Base64 string into bytes.
       *
       * @param data - The Base64 string to decode.
       * @returns The decoded bytes.
       */
      readonly decode: (data: string) => Uint8Array,
    };

    /**
     * Base58 conversion between bytes and text, intended for human
     * consumption (avoids visually ambiguous characters).
     *
     * @since 1.0.0
     * @category Encoding
     */
    readonly base58: {
      /**
       * Converts bytes into a Base58 string.
       *
       * @param data - The bytes to encode.
       * @returns The Base58 representation.
       */
      readonly encode: (data: Uint8Array) => string,
      
      /**
       * Converts a Base58 string into bytes.
       *
       * @param data - The Base58 string to decode.
       * @returns The decoded bytes.
       */
      readonly decode: (data: string) => Uint8Array,
    };
  }
>()("raquel/Crypto") {}
