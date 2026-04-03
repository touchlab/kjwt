# Quick Start

All signing, verifying, encrypting, and decrypting operations are `suspend` functions and must be
called from a coroutine.

> [!IMPORTANT]
> The examples below use key-generation and builder/parser extension APIs from
> `co.touchlab:kjwt-cryptography-kotlin-processor-ext`. Add it to your dependencies if it is not
> already present.

## Sign a JWT (JWS)

```kotlin
import co.touchlab.kjwt.Jwt
import co.touchlab.kjwt.cryptography.ext.newKey
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

## Verify / Parse a JWS

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

## Encrypt a JWT (JWE)

```kotlin
import co.touchlab.kjwt.cryptography.ext.newKey
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import co.touchlab.kjwt.model.algorithm.EncryptionContentAlgorithm

val encKey = EncryptionAlgorithm.RsaOaep256.newKey()

val jwe: JwtInstance.Jwe = Jwt.builder()
    .subject("user-123")
    .expiresIn(1.hours)
    .encryptWith(encKey, EncryptionContentAlgorithm.A256GCM)

val token: String = jwe.compact()
```

## Decrypt a JWE

```kotlin
val parser = Jwt.parser()
    .decryptWith(encKey)
    .build()

val jwe = parser.parseEncrypted(token)
val subject: String = jwe.payload.subject
```
