# Usage Guide

All signing, verifying, encrypting, and decrypting operations are `suspend` functions and must be called from a coroutine.

## Quick Start

### Sign a JWT (JWS)

```kotlin
import co.touchlab.kjwt.Jwt
import co.touchlab.kjwt.model.JwtInstance
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours

val signingKey = SigningAlgorithm.HS256.newKey()

val jws: JwtInstance.Jws = Jwt.builder()
    .issuer("my-app")
    .subject("user-123")
    .audience("api")
    .expiresIn(1.hours)
    .issuedAt(Clock.System.now())
    .signWith(signingKey)

val token: String = jws.compact()
```

### Verify / Parse a JWS

```kotlin
val parser = Jwt.parser()
    .verifyWith(signingKey)
    .requireIssuer("my-app")
    .requireAudience("api")
    .clockSkew(30L) // seconds of tolerance
    .build()

val jws = parser.parseSigned(token)
val subject: String = jws.payload.subject
```

### Encrypt a JWT (JWE)

```kotlin
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm

val encKey = EncryptionAlgorithm.RsaOaep256.newKey()

val jwe: JwtInstance.Jwe = Jwt.builder()
    .subject("user-123")
    .expiresIn(1.hours)
    .encryptWith(encKey, EncryptionContentAlgorithm.A256GCM)

val token: String = jwe.compact()
```

### Decrypt a JWE

```kotlin
val parser = Jwt.parser()
    .decryptWith(encKey)
    .build()

val jwe = parser.parseEncrypted(token)
val subject: String = jwe.payload.subject
```

---

## Keys

The `co.touchlab.kjwt.ext` package provides extension functions on each algorithm family for
generating and decoding keys. The goal of those extensions are hide the `cryptography-kotlin` API,
and simplify the integration for the developers.

### HMAC keys (HS256 / HS384 / HS512)

```kotlin
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm

// Generate a new random key
val signingKey = SigningAlgorithm.HS256.newKey()

// Decode an existing key from raw bytes
val signingKey = SigningAlgorithm.HS256.parse(keyBytes)

// Decode from a non-default format (e.g. JWK)
val signingKey = SigningAlgorithm.HS256.parse(keyBytes, format = HMAC.Key.Format.JWK)
```

The returned `SigningKey` is a `SigningKeyPair` — usable for both signing and verification because
HMAC uses a single symmetric key.

### RSA PKCS#1 v1.5 keys (RS256 / RS384 / RS512)

```kotlin
// Generate a new key pair (defaults: 4096-bit modulus, exponent 65537)
val signingKey = SigningAlgorithm.RS256.newKey()
val signingKey = SigningAlgorithm.RS256.newKey(keySize = 2048.bits)

// Decode individual keys (PEM is the default format)
val verifyKey  = SigningAlgorithm.RS256.parsePublicKey(pemBytes)   // VerifyOnlyKey
val signKey    = SigningAlgorithm.RS256.parsePrivateKey(pemBytes)  // SigningOnlyKey

// Decode both at once
val signingKey = SigningAlgorithm.RS256.parseKeyPair(publicPem, privatePem)
```

### RSA PSS keys (PS256 / PS384 / PS512)

```kotlin
// Generate a new key pair
val signingKey = SigningAlgorithm.PS256.newKey()

// Decode individual keys
val verifyKey  = SigningAlgorithm.PS256.parsePublicKey(pemBytes)
val signKey    = SigningAlgorithm.PS256.parsePrivateKey(pemBytes)

// Decode both at once
val signingKey = SigningAlgorithm.PS256.parseKeyPair(publicPem, privatePem)
```

### ECDSA keys (ES256 / ES384 / ES512)

The curve is inferred from the algorithm — P-256 for ES256, P-384 for ES384, P-521 for ES512.

```kotlin
// Generate a new key pair
val signingKey = SigningAlgorithm.ES256.newKey()

// Decode individual keys (RAW is the default format)
val verifyKey  = SigningAlgorithm.ES256.parsePublicKey(rawBytes)
val signKey    = SigningAlgorithm.ES256.parsePrivateKey(rawBytes)

// Decode both at once
val signingKey = SigningAlgorithm.ES256.parseKeyPair(publicBytes, privateBytes)

// PEM format
val verifyKey  = SigningAlgorithm.ES256.parsePublicKey(pemBytes, format = EC.PublicKey.Format.PEM)
```

### Associating a `kid` with a key

All helpers accept an optional `keyId` parameter. When set, it is embedded in the `SigningKey`
identifier so the parser can select the right key by matching the token's `kid` header field:

```kotlin
val signingKey = SigningAlgorithm.RS256.parseKeyPair(publicPem, privatePem, keyId = "key-2024")
```

### Using a signing key with the parser

The `SigningKey` returned by any of these helpers can be passed directly to
`JwtParserBuilder.verifyWith`:

```kotlin
val key = SigningAlgorithm.HS256.parse(keyBytes)

val parser = Jwt.parser()
    .verifyWith(key)
    .build()
```

---

## Encryption Keys

The `co.touchlab.kjwt.ext` package also provides extension functions on each encryption algorithm
family for generating and decoding JWE keys.

### Direct key (`dir`)

The `dir` algorithm uses the raw key bytes directly as the Content Encryption Key (CEK). The byte
length must match the content algorithm's required size (16 bytes for A128GCM/A128CBC-HS256,
24 bytes for A192GCM/A192CBC-HS384, 32 bytes for A256GCM/A256CBC-HS512).

```kotlin
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm

// Wrap existing bytes (length must match the content algorithm)
val encKey = EncryptionAlgorithm.Dir.key(cekBytes)

// Generate random bytes of a given size (defaults to 256 bits)
val encKey = EncryptionAlgorithm.Dir.newKey()
val encKey = EncryptionAlgorithm.Dir.newKey(keySize = 128.bits)
```

The returned `EncryptionKey` is an `EncryptionKeyPair` — usable for both encryption and
decryption since `dir` uses the same symmetric key for both operations.

### RSA-OAEP keys (RSA-OAEP / RSA-OAEP-256)

```kotlin
// Generate a new key pair (defaults: 4096-bit modulus, exponent 65537)
val encKey = EncryptionAlgorithm.RsaOaep.newKey()
val encKey = EncryptionAlgorithm.RsaOaep256.newKey(keySize = 2048.bits)

// Decode individual keys (PEM is the default format)
val encryptKey  = EncryptionAlgorithm.RsaOaep.parsePublicKey(pemBytes)   // EncryptionOnlyKey
val decryptKey  = EncryptionAlgorithm.RsaOaep.parsePrivateKey(pemBytes)  // DecryptionOnlyKey

// Decode both at once
val encKey = EncryptionAlgorithm.RsaOaep.parseKeyPair(publicPem, privatePem)
```

### Associating a `kid` with an encryption key

All helpers accept an optional `keyId` parameter, which is embedded in the `EncryptionKey`
identifier so the parser can select the right key by matching the token's `kid` header field:

```kotlin
val encKey = EncryptionAlgorithm.RsaOaep.parseKeyPair(publicPem, privatePem, keyId = "enc-key-2024")
```

### Using an encryption key with the parser

The `EncryptionKey` returned by any of these helpers can be passed directly to
`JwtParserBuilder.decryptWith`:

```kotlin
val key = EncryptionAlgorithm.RsaOaep.parsePrivateKey(pemBytes)

val parser = Jwt.parser()
    .decryptWith(key)
    .build()
```

---

## Standard Claims

All seven RFC 7519 registered claims are supported via the builder:

```kotlin
val signingKey = SigningAlgorithm.HS256.newKey()

val jws: JwtInstance.Jws = Jwt.builder()
    .issuer("my-app")                           // iss
    .subject("user-123")                        // sub
    .audience("api", "admin")                   // aud (multiple → JSON array)
    .expiration(Clock.System.now() + 1.hours)   // exp (absolute Instant)
    .expiresIn(1.hours)                         // exp (convenience: now + duration)
    .notBefore(Clock.System.now())              // nbf (absolute Instant)
    .notBeforeNow()                             // nbf (convenience: now)
    .issuedAt(Clock.System.now())               // iat
    .issuedNow()                                // iat (convenience: now)
    .id("unique-token-id")                      // jti
    .randomId()                                 // jti (convenience: random UUID, @ExperimentalUuidApi)
    .signWith(signingKey)

val token: String = jws.compact()
```

## Custom Claims

```kotlin
import kotlinx.serialization.json.JsonPrimitive

val jws: JwtInstance.Jws = Jwt.builder()
    .subject("user-123")
    // reified generic - most convenient
    .claim("role", "admin")
    .claim("permissions", listOf("read", "write"))
    // explicit serializer
    .claim("metadata", MyMetadata.serializer(), MyMetadata(version = 2))
    // raw JsonElement
    .claim("raw", JsonPrimitive(42))
    .signWith(signingKey)

val token: String = jws.compact()
```

## Header Parameters

```kotlin
val rsaSigningKey = SigningAlgorithm.RS256.parsePrivateKey(pemBytes, keyId = "key-2024-01")

val jws: JwtInstance.Jws = Jwt.builder()
    .subject("user-123")
    .header {
        type = "JWT"                            // typ (default: "JWT")
        contentType = "application/json"        // cty
    }
    .signWith(rsaSigningKey)

val token: String = jws.compact()
```

## Key ID (`kid`)

The `kid` header parameter identifies which key was used to sign or encrypt a token — defined in RFC 7515 §4.1.4 for JWS and RFC 7516 §4.1.6 for JWE. It is useful when a server holds multiple keys or rotates keys over time — the recipient can use `kid` to look up the correct verification or decryption key without trying each one.

### Setting `kid` when signing

Pass the key ID via the `keyId` parameter when constructing the key — it is automatically embedded
in the key's identifier and written to the JWT header:

```kotlin
val signingKey = SigningAlgorithm.RS256.parsePrivateKey(pemBytes, keyId = "key-2024-01")

val jws: JwtInstance.Jws = Jwt.builder()
    .subject("user-123")
    .signWith(signingKey)

// → header: {"typ":"JWT","alg":"RS256","kid":"key-2024-01"}
```

### Setting `kid` when encrypting

Same pattern for `encryptWith`:

```kotlin
val encKey = EncryptionAlgorithm.RsaOaep256.parsePublicKey(pemBytes, keyId = "enc-key-1")

val jwe: JwtInstance.Jwe = Jwt.builder()
    .subject("user-123")
    .encryptWith(encKey, EncryptionContentAlgorithm.A256GCM)

// → header: {"alg":"RSA-OAEP-256","enc":"A256GCM","kid":"enc-key-1"}
```

### JWK extensions

When using the JWK builder extensions, `kid` defaults to the JWK's own `kid` field so you don't have to repeat it:

```kotlin
val jwk = Jwk.Rsa(/* ... */, kid = "key-2024-01")

Jwt.builder().subject("user-123")
    .signWith(SigningAlgorithm.RS256, jwk)               // kid = "key-2024-01" (from jwk.kid)
    .signWith(SigningAlgorithm.RS256, jwk, null)          // kid omitted
    .signWith(SigningAlgorithm.RS256, jwk, "other-key")   // kid = "other-key" (explicit override)
```

### Reading `kid` from a parsed token

```kotlin
val jws = parser.parseSigned(token)
val kid: String? = jws.header.keyId   // null if the header did not include kid
```

---

## Multiple Keys (Key Rotation)

The parser can hold multiple keys for the same algorithm, each identified by an optional `kid`. This is useful for key rotation — where old and new keys need to coexist during a transition period — or for multi-tenant scenarios where different parties use different keys.

### Registering multiple signing keys

Embed a `kid` in each key via the `keyId` parameter when constructing it. Each `(algorithm, kid)` pair must be unique; registering the same combination twice throws `IllegalArgumentException` at builder time.

```kotlin
val key2024 = SigningAlgorithm.RS256.parsePublicKey(pem2024, keyId = "key-2024")
val key2025 = SigningAlgorithm.RS256.parsePublicKey(pem2025, keyId = "key-2025")

val parser = Jwt.parser()
    .verifyWith(key2024)
    .verifyWith(key2025)
    .build()

// Token signed with kid="key-2024" → verified with key2024
// Token signed with kid="key-2025" → verified with key2025
```

### Lookup priority

When parsing a token the key is selected by this ordered strategy:

1. **Exact match** — find a registered key whose algorithm and `kid` both match the token's header.
2. **Algo-only fallback** — if the token has a `kid` but no exact match exists, use the key registered for that algorithm *without* a `kid` (constructed without a `keyId`). This lets you register a single "catch-all" key alongside specific ones.
3. **`noVerify()` fallback** — if no key is found and `noVerify()` was configured on the builder, signature verification is skipped entirely.

```kotlin
val specificKey = SigningAlgorithm.RS256.parsePublicKey(pem2024, keyId = "key-2024")
val fallbackKey = SigningAlgorithm.RS256.parsePublicKey(pemFallback)  // no keyId → catch-all

val parser = Jwt.parser()
    .verifyWith(specificKey)  // matched first by exact kid
    .verifyWith(fallbackKey)  // used when no exact kid match
    .build()
```

If no key matches and `noVerify()` was not set, parsing throws `IllegalStateException`.

### Multiple decryption keys (JWE)

The same rules apply to `decryptWith`:

```kotlin
val privateKey2024 = EncryptionAlgorithm.RsaOaep256.parsePrivateKey(pem2024, keyId = "enc-key-2024")
val privateKey2025 = EncryptionAlgorithm.RsaOaep256.parsePrivateKey(pem2025, keyId = "enc-key-2025")

val parser = Jwt.parser()
    .decryptWith(privateKey2024)
    .decryptWith(privateKey2025)
    .build()
```

### Using a shared `JwtKeyRegistry`

`JwtKeyRegistry` is a centralised key store that can be shared across multiple builder and parser
instances. This is useful when you want to manage keys in one place — for example in a dependency
injection container — and reuse them without repeating configuration.

#### Signing with a registry

Pass a `JwtKeyRegistry` to `signWith` instead of a raw key:

```kotlin
val registry = JwtKeyRegistry()
// Keys are added to the registry via JwtParserBuilder and shared by reference,
// or by registering them directly when both parties share the same module.

val token = Jwt.builder()
    .subject("user-123")
    .signWith(SigningAlgorithm.HS256, registry)       // looks up the private key from the registry
    .compact()
```

If no matching key is found in the registry an `IllegalStateException` is thrown.

#### Encrypting with a registry

Same pattern for JWE encryption:

```kotlin
val token = Jwt.builder()
    .subject("user-123")
    .encryptWith(registry, EncryptionAlgorithm.RsaOaep256, EncryptionContentAlgorithm.A256GCM)
    .compact()
```

#### Sharing a registry with the parser — `useKeysFrom`

`useKeysFrom` configures a parser to delegate key look-up to an existing registry. The registry is
searched **before** any keys registered directly on the parser builder, so a shared registry acts
as the primary key source.

```kotlin
val parser = Jwt.parser()
    .useKeysFrom(registry)    // delegate to shared registry
    .requireIssuer("my-app")
    .build()

val jws = parser.parseSigned(token)
```

You can combine `useKeysFrom` with direct `verifyWith` / `decryptWith` calls. The parser's own
keys take priority; the registry is only consulted when no local key matches:

```kotlin
val localKey = SigningAlgorithm.HS256.newKey()

val parser = Jwt.parser()
    .verifyWith(localKey)               // checked first
    .useKeysFrom(sharedRegistry)        // fallback if no local key matches
    .build()
```

---

## Parsing Claims

Access standard claims via extension properties. Mandatory variants throw `MissingClaimException` if the claim is absent; `OrNull` variants return `null`:

```kotlin
val payload = jws.payload

// Mandatory - throws MissingClaimException if absent
val iss: String       = payload.issuer
val sub: String       = payload.subject
val aud: Set<String>  = payload.audience
val exp: Instant      = payload.expiration
val nbf: Instant      = payload.notBefore
val iat: Instant      = payload.issuedAt
val jti: String       = payload.jwtId

// Optional - null if absent
val issOrNull: String? = payload.issuerOrNull
// ... same pattern for all claims
```

Access custom claims via `getClaim` / `getClaimOrNull`:

```kotlin
val role: String  = payload.getClaim<String>("role")
val role: String? = payload.getClaimOrNull<String>("role")
```

## Claim Validation

Configure required claims on the parser; any failure throws an appropriate exception:

```kotlin
val ecSigningKey = SigningAlgorithm.ES256.parsePublicKey(rawBytes)

val parser = Jwt.parser()
    .verifyWith(ecSigningKey)
    .requireIssuer("my-app")           // throws IncorrectClaimException on mismatch
    .requireSubject("user-123")
    .requireAudience("api")
    .requireClaim("role", "admin")     // generic claim equality check
    .clockSkew(30L)                    // seconds of exp/nbf tolerance
    .build()
```

`exp` and `nbf` are validated automatically. No extra configuration is needed.

## Unsecured JWTs (`alg=none`)

Unsecured JWTs are rejected by default. There are two distinct opt-in mechanisms:

### `allowUnsecured(true)` — accept `alg=none` tokens

Permits tokens where `alg=none` was used at creation time. All other algorithms still require a key configured via `verifyWith()`.

```kotlin
// Create an unsecured JWT
val jws: JwtInstance.Jws = Jwt.builder()
    .subject("user-123")
    .build()

val token: String = jws.compact()

// Parse — only alg=none tokens are accepted without a key;
// signed tokens still require verifyWith()
val parser = Jwt.parser()
    .allowUnsecured(true)
    .build()

val parsed = parser.parseSigned(token)
```

### `noVerify()` — skip signature verification entirely

Accepts any token regardless of algorithm without verifying its signature. Use only in contexts where authenticity is not required (e.g. inspecting an already-trusted token's claims).

```kotlin
val parser = Jwt.parser()
    .noVerify()
    .build()

// Parses successfully even if the token was signed with HS256/RS256/etc.
// — the signature is NOT checked
val jws = parser.parseSigned(signedToken)
```

## Auto-Detect JWS vs JWE

When you don't know whether a token is signed or encrypted, use `parse` which detects by part count (3 = JWS, 5 = JWE):

```kotlin
val instance: JwtInstance = parser.parse(token)

when (instance) {
    is JwtInstance.Jws -> println("Signed, subject=${instance.payload.subject}")
    is JwtInstance.Jwe -> println("Encrypted, subject=${instance.payload.subject}")
}
```

## Custom Payload Types

Implement a plain `@Serializable` data class. Use `@SerialName` to map fields to JWT claim names. Fields should have default values so deserialization works when a claim is absent. Unmapped claims are silently ignored.

You can reference standard claim name constants from `JwtPayload.SUB`, `JwtPayload.ISS`, etc.

```kotlin
import co.touchlab.kjwt.model.JwtPayload
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class UserClaims(
    @SerialName(JwtPayload.SUB) val subject: String? = null,
    @SerialName("role") val role: String? = null,
    @SerialName("level") val level: Int? = null,
)
```

Parse using `parseSigned` (or `parseEncrypted`), then call `getPayload<T>()` on the result:

```kotlin
val jws: JwtInstance.Jws = parser.parseSigned(token)
val payload: UserClaims = jws.getPayload<UserClaims>()
println(payload.role)
println(payload.subject)
```

`getPayload<T>()` is available on both `JwtInstance.Jws` and `JwtInstance.Jwe`.

## JWE with Direct Key (`dir`)

For symmetric encryption where the key is used directly as the CEK (no key wrapping):

```kotlin
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm

// Wrap existing raw bytes as a symmetric encryption key
val encKey = EncryptionAlgorithm.Dir.key(cekBytes)
// Or generate a fresh random key: EncryptionAlgorithm.Dir.newKey()

val jwe: JwtInstance.Jwe = Jwt.builder()
    .subject("user-123")
    .encryptWith(encKey, EncryptionContentAlgorithm.A256GCM)

val token: String = jwe.compact()

// Decrypt — use the same key (Dir is symmetric)
val parser = Jwt.parser()
    .decryptWith(encKey)
    .build()

val jwe = parser.parseEncrypted(token)
```
