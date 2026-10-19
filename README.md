# crypto

An [Effect](https://effect.website) service that exposes cryptographic
primitives behind a single injectable `Crypto` interface.

Depending on the interface instead of a concrete library makes your code easy
to test (swap in a deterministic implementation) and easy to migrate (swap the
underlying library without touching call sites).

## Features

- **Bytes utilities**: `randomBytes`, `equalBytes`, `concatBytes`, `copyBytes`
- **Hashing**: `sha256`
- **Key derivation**: `hkdf`
- **Password hashing**: `argon2id`
- **Authenticated encryption**: `xchacha20poly1305`
- **Message authentication**: `hmac`
- **Key exchange**: `x25519`
- **Signatures**: `ed25519`
- **Encodings**: `utf8`, `hex`, `base64`, `base58`

## Usage

```ts
import { Effect } from "effect";
import { Crypto } from "...";

const program = Effect.gen(function* () {
  const crypto = yield* Crypto;

  const key = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(24);
  const cipher = crypto.xchacha20poly1305(key, nonce);

  const plaintext = crypto.utf8.decode("hello");
  const ciphertext = cipher.encrypt(plaintext);

  return crypto.utf8.encode(cipher.decrypt(ciphertext)); // "hello"
});
```

Provide an implementation when running the program:

```ts
program.pipe(Effect.provide(CryptoLive), Effect.runSync);
```
