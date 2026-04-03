# Building Tokens

All token-building operations are `suspend` functions and must be called from a coroutine.

> [!IMPORTANT]
> The `signWith(key)` and `encryptWith(key, contentAlgorithm)` builder extensions, as well as the
> key-generation and key-parsing helpers used in the examples below, are provided by
> `co.touchlab:kjwt-cryptography-kotlin-processor-ext`. Add it to your dependencies if it is not
> already present.

## Standard Claims

All seven RFC 7519 registered claims are supported via the builder:

```kotlin
import co.touchlab.kjwt.Jwt
import co.touchlab.kjwt.cryptography.ext.newKey
import co.touchlab.kjwt.model.JwtInstance
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours

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

## Merging a Serializable Object into the Payload

Use `payload(value)` to merge all fields from a `@Serializable` object into the token payload at
once, instead of setting each claim individually:

```kotlin
@Serializable
data class UserClaims(
    @SerialName("role") val role: String? = null,
    @SerialName("level") val level: Int? = null,
)

val jws: JwtInstance.Jws = Jwt.builder()
    .subject("user-123")
    .payload(UserClaims(role = "admin", level = 5))   // merges all fields
    .signWith(signingKey)
```

Each field in the object is written as a claim, overwriting any existing value with the same name.
Standard claims set before or after the call (e.g. `.subject()`) are not affected unless the
serializable type defines a field that maps to the same claim name.

## Header Parameters

Header fields can be set either with flat setter methods or with the `header { }` DSL block:

```kotlin
val rsaSigningKey = SigningAlgorithm.RS256.parsePrivateKey(pemBytes, keyId = "key-2024-01")

// Flat setters
val jws: JwtInstance.Jws = Jwt.builder()
    .subject("user-123")
    .type("JWT")                               // typ
    .contentType("application/json")           // cty
    .header("x-custom", "value")              // extra parameter (reified)
    .signWith(rsaSigningKey)

// DSL block
val jws: JwtInstance.Jws = Jwt.builder()
    .subject("user-123")
    .header {
        type = "JWT"                            // typ (default: "JWT")
        contentType = "application/json"        // cty
    }
    .signWith(rsaSigningKey)

val token: String = jws.compact()
```

## Merging a Serializable Object into the Header

Use `header(value)` to merge all fields from a `@Serializable` object into the JOSE header at once:

```kotlin
@Serializable
data class MyHeader(
    @SerialName("x-tenant") val tenant: String? = null,
    @SerialName("x-version") val version: Int? = null,
)

val jws: JwtInstance.Jws = Jwt.builder()
    .subject("user-123")
    .header(MyHeader(tenant = "acme", version = 2))   // merges all fields
    .signWith(signingKey)
```

Each field in the object is written as a header parameter, overwriting any existing value with the
same name.

## Key ID (`kid`)

The `kid` header parameter identifies which key was used to sign or encrypt a token — defined in
RFC 7515 §4.1.4 for JWS and RFC 7516 §4.1.6 for JWE. It is useful when a server holds multiple
keys or rotates keys over time — the recipient can use `kid` to look up the correct verification or
decryption key without trying each one.

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

When using the JWK builder extensions, `kid` defaults to the JWK's own `kid` field so you don't
have to repeat it:

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

## JWE with Direct Key (`dir`)

For symmetric encryption where the key is used directly as the CEK (no key wrapping):

```kotlin
import co.touchlab.kjwt.cryptography.ext.key
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
