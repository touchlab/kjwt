# Key Rotation

> [!IMPORTANT]
> The key-parsing and registry extension APIs used on this page are provided by
> `co.touchlab:kjwt-cryptography-kotlin-processor-ext`. Add it to your dependencies if it is not
> already present.

The parser can hold multiple keys for the same algorithm, each identified by an optional `kid`. This
is useful for key rotation — where old and new keys need to coexist during a transition period — or
for multi-tenant scenarios where different parties use different keys.

## Registering Multiple Signing Keys

Embed a `kid` in each key via the `keyId` parameter when constructing it. Each `(algorithm, kid)`
pair must be unique; registering the same combination twice throws `IllegalArgumentException` at
builder time.

```kotlin
import co.touchlab.kjwt.cryptography.ext.parsePublicKey

val key2024 = SigningAlgorithm.RS256.parsePublicKey(pem2024, keyId = "key-2024")
val key2025 = SigningAlgorithm.RS256.parsePublicKey(pem2025, keyId = "key-2025")

val parser = Jwt.parser()
    .verifyWith(key2024)
    .verifyWith(key2025)
    .build()

// Token signed with kid="key-2024" → verified with key2024
// Token signed with kid="key-2025" → verified with key2025
```

## Lookup Priority

When parsing a token the key is selected by this ordered strategy:

1. **Exact match** — find a registered key whose algorithm and `kid` both match the token's header.
2. **Algo-only fallback** — if the token has a `kid` but no exact match exists, use the key
   registered for that algorithm *without* a `kid` (constructed without a `keyId`). This lets you
   register a single "catch-all" key alongside specific ones.
3. **`noVerify()` fallback** — if no key is found and `noVerify()` was configured on the builder,
   signature verification is skipped entirely.

```kotlin
val specificKey = SigningAlgorithm.RS256.parsePublicKey(pem2024, keyId = "key-2024")
val fallbackKey = SigningAlgorithm.RS256.parsePublicKey(pemFallback)  // no keyId → catch-all

val parser = Jwt.parser()
    .verifyWith(specificKey)  // matched first by exact kid
    .verifyWith(fallbackKey)  // used when no exact kid match
    .build()
```

If no key matches and `noVerify()` was not set, parsing throws `IllegalStateException`.

## Multiple Decryption Keys (JWE)

The same rules apply to `decryptWith`:

```kotlin
import co.touchlab.kjwt.cryptography.ext.parsePrivateKey

val privateKey2024 = EncryptionAlgorithm.RsaOaep256.parsePrivateKey(pem2024, keyId = "enc-key-2024")
val privateKey2025 = EncryptionAlgorithm.RsaOaep256.parsePrivateKey(pem2025, keyId = "enc-key-2025")

val parser = Jwt.parser()
    .decryptWith(privateKey2024)
    .decryptWith(privateKey2025)
    .build()
```

## Using a Shared `JwtProcessorRegistry`

`JwtProcessorRegistry` is a centralised key store that can be shared across multiple builder and
parser instances. This is useful when you want to manage keys in one place — for example in a
dependency injection container — and reuse them without repeating configuration.

`DefaultJwtProcessorRegistry` is the standard in-memory implementation.

```kotlin
import co.touchlab.kjwt.annotations.ExperimentalKJWTApi
import co.touchlab.kjwt.model.registry.DefaultJwtProcessorRegistry
import co.touchlab.kjwt.model.registry.JwtProcessorRegistry
import co.touchlab.kjwt.cryptography.ext.registerSigningKey

@OptIn(ExperimentalKJWTApi::class)
val registry: JwtProcessorRegistry = DefaultJwtProcessorRegistry()
```

### Signing with a registry

Pass a `JwtProcessorRegistry` to `signWith` instead of a raw key:

```kotlin
val token = Jwt.builder()
    .subject("user-123")
    .signWith(SigningAlgorithm.HS256, registry)       // looks up the signing processor from the registry
    .compact()
```

If no matching processor is found in the registry an `IllegalStateException` is thrown.

### Encrypting with a registry

Same pattern for JWE encryption:

```kotlin
val token = Jwt.builder()
    .subject("user-123")
    .encryptWith(registry, EncryptionAlgorithm.RsaOaep256, EncryptionContentAlgorithm.A256GCM)
    .compact()
```

### Sharing a registry with the parser — `useKeysFrom`

`useKeysFrom` configures a parser to delegate key look-up to an existing registry. Keys registered
directly on the parser builder (via `verifyWith` or `decryptWith`) take precedence; the registry is
only consulted when no local key matches.

```kotlin
val parser = Jwt.parser()
    .useKeysFrom(registry)    // delegate to shared registry
    .requireIssuer("my-app")
    .build()

val jws = parser.parseSigned(token)
```

You can combine `useKeysFrom` with direct `verifyWith` / `decryptWith` calls. The parser's own keys
take priority; the registry is only consulted when no local key matches:

```kotlin
val localKey = SigningAlgorithm.HS256.newKey()

val parser = Jwt.parser()
    .verifyWith(localKey)               // checked first
    .useKeysFrom(sharedRegistry)        // fallback if no local key matches
    .build()
```

### Registering keys into a registry

Keys and processors can be registered directly into a `JwtProcessorRegistry` using the extension
functions from `co.touchlab.kjwt.cryptography.ext`:

```kotlin
import co.touchlab.kjwt.cryptography.ext.registerSigningKey
import co.touchlab.kjwt.cryptography.ext.registerEncryptionKey

registry.registerSigningKey(signingKey)
registry.registerEncryptionKey(encryptionKey)
```
