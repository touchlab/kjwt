# Parsing Tokens

All parsing operations are `suspend` functions and must be called from a coroutine.

## Parsing Claims

Access standard claims via extension properties. Mandatory variants throw `MissingClaimException`
if the claim is absent; `OrNull` variants return `null`:

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

> [!IMPORTANT]
> This section uses key-parsing and `verifyWith(key)` extensions from
> `co.touchlab:kjwt-cryptography-kotlin-processor-ext`.

Configure required claims on the parser; any failure throws an appropriate exception:

```kotlin
import co.touchlab.kjwt.cryptography.ext.parsePublicKey

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

Permits tokens where `alg=none` was used at creation time. All other algorithms still require a key
configured via `verifyWith()`.

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

Accepts any token regardless of algorithm without verifying its signature. Use only in contexts
where authenticity is not required (e.g. inspecting an already-trusted token's claims).

```kotlin
val parser = Jwt.parser()
    .noVerify()
    .build()

// Parses successfully even if the token was signed with HS256/RS256/etc.
// — the signature is NOT checked
val jws = parser.parseSigned(signedToken)
```

## Auto-Detect JWS vs JWE

When you don't know whether a token is signed or encrypted, use `parse` which detects by part count
(3 = JWS, 5 = JWE):

```kotlin
val instance: JwtInstance = parser.parse(token)

when (instance) {
    is JwtInstance.Jws -> println("Signed, subject=${instance.payload.subject}")
    is JwtInstance.Jwe -> println("Encrypted, subject=${instance.payload.subject}")
}
```

## Custom Payload Types

Implement a plain `@Serializable` data class. Use `@SerialName` to map fields to JWT claim names.
Fields should have default values so deserialization works when a claim is absent. Unmapped claims
are silently ignored.

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

## Custom Header Types

The same pattern works for the JOSE header. Define a `@Serializable` data class whose fields map
to the header parameter names you care about, then call `getHeader<T>()`:

```kotlin
@Serializable
data class MyHeader(
    @SerialName("alg") val algorithm: String? = null,
    @SerialName("kid") val keyId: String? = null,
    @SerialName("x-tenant") val tenant: String? = null,
)

val jws: JwtInstance.Jws = parser.parseSigned(token)
val header: MyHeader = jws.getHeader<MyHeader>()
println(header.keyId)
println(header.tenant)
```

`getHeader<T>()` is available on both `JwtInstance.Jws` and `JwtInstance.Jwe`.
