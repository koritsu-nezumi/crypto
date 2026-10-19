import { Context, Effect, Redacted } from "effect";

/** @internal DO NOT EXPORT */
const TypeId = "~raquel/Crypto";

export class Crypto extends Context.Service<
  Crypto,
  {
    /** @internal */
    readonly [TypeId]: typeof TypeId;
    readonly randomBytes: (bytesLength: number) => Effect.Effect<Uint8Array>;
    readonly equalBytes: (
      a: Uint8Array,
      b: Uint8Array,
    ) => Effect.Effect<boolean>;
    readonly concatBytes: (
      ...arrays: Uint8Array[]
    ) => Effect.Effect<Uint8Array>;
    readonly copyBytes: (bytes: Uint8Array) => Effect.Effect<Uint8Array>;
    readonly sha256: (msg: Uint8Array) => Effect.Effect<Uint8Array>;
    readonly hkdf: (
      ikm: Redacted.Redacted<Uint8Array>,
      salt: Uint8Array | undefined,
      info: Uint8Array | undefined,
      length: number,
    ) => Effect.Effect<Uint8Array>;
    readonly argon2id: (
      ikm: Redacted.Redacted<Uint8Array>,
      salt: Uint8Array,
      opts?: { m: number; t: number; p: number },
    ) => Effect.Effect<Uint8Array>;
    readonly xchacha20poly1305: (
      key: Redacted.Redacted<Uint8Array>,
      nonce: Uint8Array,
      aad?: Uint8Array,
    ) => {
      readonly encrypt: (
        plaintext: Redacted.Redacted<Uint8Array>,
      ) => Effect.Effect<Uint8Array>;
      readonly decrypt: (
        ciphertext: Uint8Array,
      ) => Effect.Effect<Redacted.Redacted<Uint8Array>>;
    };
    readonly hmac: (
      key: Redacted.Redacted<Uint8Array>,
      message: Uint8Array,
    ) => Effect.Effect<Uint8Array>;
    readonly x25519: {
      readonly getPublicKey: (
        secretKey: Redacted.Redacted<Uint8Array>,
      ) => Effect.Effect<Uint8Array>;
      readonly getSharedSecret: (
        secretKeyA: Redacted.Redacted<Uint8Array>,
        publicKeyB: Uint8Array,
      ) => Effect.Effect<Redacted.Redacted<Uint8Array>>;
    };
    readonly ed25519: {
      readonly getPublicKey: (
        secretKey: Redacted.Redacted<Uint8Array>,
      ) => Effect.Effect<Uint8Array>;
      readonly sign: (
        message: Uint8Array,
        secretKey: Redacted.Redacted<Uint8Array>,
      ) => Effect.Effect<Uint8Array>;
      readonly verify: (
        signature: Uint8Array,
        message: Uint8Array,
        publicKey: Uint8Array,
      ) => Effect.Effect<boolean>;
    };
    readonly utf8: {
      readonly encode: (data: Uint8Array) => Effect.Effect<string>;
      readonly decode: (data: string) => Effect.Effect<Uint8Array>;
    };
    readonly hex: {
      readonly encode: (data: Uint8Array) => Effect.Effect<string>;
      readonly decode: (data: string) => Effect.Effect<Uint8Array>;
    };
    readonly base64: {
      readonly encode: (data: Uint8Array) => Effect.Effect<string>;
      readonly decode: (data: string) => Effect.Effect<Uint8Array>;
    };
    readonly base58: {
      readonly encode: (data: Uint8Array) => Effect.Effect<string>;
      readonly decode: (data: string) => Effect.Effect<Uint8Array>;
    };
  }
>()("raquel/Crypto") {}
