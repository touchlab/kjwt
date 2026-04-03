# Keys

> [!IMPORTANT]
> All APIs on this page are provided by `co.touchlab:kjwt-cryptography-kotlin-processor-ext`.
> Add it to your dependencies if it is not already present.

## Signing Keys

The `co.touchlab.kjwt.cryptography.ext` package provides extension functions on each algorithm
family for generating and decoding signing keys. These extensions hide the `cryptography-kotlin` API
and simplify integration.

### HMAC keys (HS256 / HS384 / HS512)

```kotlin
import co.touchlab.kjwt.cryptography.ext.newKey
import co.touchlab.kjwt.cryptography.ext.parse
import co.touchlab.kjwt.model.algorithm.SigningAlgorithm

// Generate a new random key
val signingKey = SigningAlgorithm.HS256.newKey()

// Decode an existing key from raw bytes
val signingKey = SigningAlgorithm.HS256.parse(keyBytes)

// Decode from a non-default format (e.g. JWK)
val signingKey = SigningAlgorithm.HS256.parse(keyBytes, format = HMAC.Key.Format.JWK)
```

The returned `SigningKey` is a `SigningKey.SigningKeyPair` — usable for both signing and
verification because HMAC uses a single symmetric key.

### RSA PKCS#1 v1.5 keys (RS256 / RS384 / RS512)

```kotlin
import co.touchlab.kjwt.cryptography.ext.newKey
import co.touchlab.kjwt.cryptography.ext.parsePublicKey
import co.touchlab.kjwt.cryptography.ext.parsePrivateKey
import co.touchlab.kjwt.cryptography.ext.parseKeyPair
import dev.whyoleg.cryptography.BinarySize.Companion.bits

// Generate a new key pair (defaults: 2048-bit modulus, exponent 65537)
val signingKey = SigningAlgorithm.RS256.newKey()
val signingKey = SigningAlgorithm.RS256.newKey(keySize = 4096.bits)

// Decode individual keys (PEM is the default format)
val verifyKey  = SigningAlgorithm.RS256.parsePublicKey(pemBytes)   // SigningKey.VerifyOnlyKey
val signKey    = SigningAlgorithm.RS256.parsePrivateKey(pemBytes)  // SigningKey.SigningOnlyKey

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

### Associating a `kid` with a signing key

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

The `co.touchlab.kjwt.cryptography.ext` package also provides extension functions on each
encryption algorithm family for generating and decoding JWE keys.

### Direct key (`dir`)

The `dir` algorithm uses the raw key bytes directly as the Content Encryption Key (CEK). The byte
length must match the content algorithm's required size (16 bytes for A128GCM/A128CBC-HS256,
24 bytes for A192GCM/A192CBC-HS384, 32 bytes for A256GCM/A256CBC-HS512).

```kotlin
import co.touchlab.kjwt.cryptography.ext.key
import co.touchlab.kjwt.cryptography.ext.newKey
import co.touchlab.kjwt.model.algorithm.EncryptionAlgorithm
import dev.whyoleg.cryptography.BinarySize.Companion.bits

// Wrap existing bytes (length must match the content algorithm)
val encKey = EncryptionAlgorithm.Dir.key(cekBytes)

// Generate random bytes of a given size (defaults to 256 bits)
val encKey = EncryptionAlgorithm.Dir.newKey()
val encKey = EncryptionAlgorithm.Dir.newKey(keySize = 128.bits)
```

The returned `EncryptionKey` is an `EncryptionKey.EncryptionKeyPair` — usable for both encryption
and decryption since `dir` uses the same symmetric key for both operations.

### RSA-OAEP keys (RSA-OAEP / RSA-OAEP-256)

```kotlin
// Generate a new key pair (defaults: 2048-bit modulus, exponent 65537)
val encKey = EncryptionAlgorithm.RsaOaep.newKey()
val encKey = EncryptionAlgorithm.RsaOaep256.newKey(keySize = 4096.bits)

// Decode individual keys (PEM is the default format)
val encryptKey  = EncryptionAlgorithm.RsaOaep.parsePublicKey(pemBytes)   // EncryptionKey.EncryptionOnlyKey
val decryptKey  = EncryptionAlgorithm.RsaOaep.parsePrivateKey(pemBytes)  // EncryptionKey.DecryptionOnlyKey

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

## Using cryptography-kotlin Keys Directly

The `co.touchlab.kjwt.cryptography.ext` package also provides `verifyWith` and `decryptWith`
overloads on `JwtParserBuilder` that accept a raw `String` key plus the corresponding
cryptography-kotlin format type.

### HMAC (HS256 / HS384 / HS512)

```kotlin
import dev.whyoleg.cryptography.algorithms.HMAC

val parser = Jwt.parser()
    .verifyWith(SigningAlgorithm.HS256, hmacKeyString, HMAC.Key.Format.RAW)
    .build()
```

### RSA PKCS#1 v1.5 (RS256 / RS384 / RS512)

```kotlin
import dev.whyoleg.cryptography.algorithms.RSA

val parser = Jwt.parser()
    .verifyWith(SigningAlgorithm.RS256, pemString, RSA.PublicKey.Format.PEM)
    .build()
```

### RSA PSS (PS256 / PS384 / PS512)

```kotlin
val parser = Jwt.parser()
    .verifyWith(SigningAlgorithm.PS256, pemString, RSA.PublicKey.Format.PEM)
    .build()
```

### ECDSA (ES256 / ES384 / ES512)

```kotlin
import dev.whyoleg.cryptography.algorithms.EC

val parser = Jwt.parser()
    .verifyWith(SigningAlgorithm.ES256, rawKeyString, EC.PublicKey.Format.RAW)
    .build()
```

All overloads accept an optional `keyId` parameter so the key participates in the standard `kid`
matching strategy described in [Key Rotation](./key-rotation.md#lookup-priority).

### Direct key (`dir`) decryption from `ByteArray` or `String`

```kotlin
// from raw bytes
val parser = Jwt.parser()
    .decryptWith(cekBytes, EncryptionAlgorithm.Dir)
    .build()

// from a UTF-8 string (converted to bytes automatically)
val parser = Jwt.parser()
    .decryptWith(cekString, EncryptionAlgorithm.Dir)
    .build()
```
