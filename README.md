# crypto

An [Effect](https://effect.website) service that exposes cryptographic
primitives behind a single injectable `Crypto` interface.

Depending on the interface instead of a concrete library makes your code easy
to migrate (swap the underlying library without touching call sites).

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
import { Effect, Redacted } from "effect";
import { Crypto } from "...";

export const program = Effect.gen(function* () {
  const crypto = yield* Crypto;

  const key = Redacted.make(yield* crypto.randomBytes(32));
  const nonce = yield* crypto.randomBytes(24);
  const cipher = crypto.xchacha20poly1305(key, nonce);

  const plaintext = Redacted.make(yield* crypto.utf8.decode("hello"));
  const ciphertext = yield* cipher.encrypt(plaintext);

  return yield* crypto.utf8.encode(Redacted.value(yield* cipher.decrypt(ciphertext)));
});
```

Provide an implementation when running the program:

```ts
import { Effect } from "effect";
import { program } from "...";
import { CryptoLayer } from "...";

const output = await program.pipe(Effect.provide(CryptoLayer), Effect.runPromise);
console.log(output); // "hello"
```
