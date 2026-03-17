# KJWT

[![Tests](https://github.com/touchlab/kjwt/actions/workflows/tests.yml/badge.svg?event=push)](https://github.com/touchlab/kjwt/actions/workflows/tests.yml)
[![Detekt Checks](https://github.com/touchlab/kjwt/actions/workflows/detekt.yml/badge.svg)](https://github.com/touchlab/kjwt/actions/workflows/detekt.yml)


[![Maven Central](https://img.shields.io/maven-central/v/co.touchlab/kjwt?label=Maven%20Central)](https://search.maven.org/artifact/co.touchlab/kjwt)
![Maven Central (Snapshots)](https://img.shields.io/maven-metadata/v?metadataUrl=https%3A%2F%2Fcentral.sonatype.com%2Frepository%2Fmaven-snapshots%2Fco%2Ftouchlab%2Fkjwt%2Fmaven-metadata.xml&label=Snapshot)

A JSON Web Token (JWT) is a compact, URL-safe standard for representing data to be transferred between two parties. The
data within a JWT - referred to as claims - is encoded as a JSON object that serves as the payload for either a JSON Web
Signature (JWS) or a JSON Web Encryption (JWE) structure. This design allows claims to be digitally signed for
integrity (using a Message Authentication Code or MAC) and/or encrypted for privacy.

The most common JWT format is a string composed of three dot-separated segments: header, payload, and signature. This
structure represents a JWS, as defined by RFC 7515. In this format, the header and payload are Base64URL-encoded,
meaning they can be easily decoded by anyone to reveal their contents. The third segment, the signature, is also
Base64URL-encoded and is used to verify that the first two parts of the token have not been tampered with.

While less common, JWTs can also follow the JWE format defined by RFC 7516, which consists of five dot-separated parts:
header, encrypted key, initialization vector, ciphertext, and authentication tag. Unlike a JWS, where data is merely
signed, a JWE encrypts the data. While the header remains decodable, the remaining segments are encrypted and cannot be
read without the appropriate cryptographic key.

### How about the other formats and RFCs?

The JWT is just a part of the JOSE family of standards. JOSE stands for JSON Object Signing and Encryption, and it
groups several related RFCs that define how to sign, encrypt, and manage keys for JSON data. To support all of these
features, the JOSE family includes a few different standards, such as:

- [RFC 7519 (JWT)](https://datatracker.ietf.org/doc/html/rfc7519) - JSON Web Token
- [RFC 7515 (JWS)](https://datatracker.ietf.org/doc/html/rfc7515) - JSON Web Signature
- [RFC 7516 (JWE)](https://datatracker.ietf.org/doc/html/rfc7516) - JSON Web Encryption
- [RFC 7517 (JWK)](https://datatracker.ietf.org/doc/html/rfc7517) - JSON Web Key
- [RFC 7518 (JWA)](https://datatracker.ietf.org/doc/html/rfc7518) - JSON Web Algorithms
- [RFC 7520 (JOSE)](https://datatracker.ietf.org/doc/html/rfc7520) - JSON Object Signing and Encryption (JOSE)
- [RFC 7638 (JWK Thumbprint)](https://datatracker.ietf.org/doc/html/rfc7638) - JWK Thumbprint

While the JWT is a specific format for representing claims (payload), the JOSE standards provide the tools and
specifications for creating, signing, encrypting, and managing those claims in a secure and interoperable way. The JWT
is just one of the possible formats for representing claims, and it is designed to be compact and URL-safe.

When we first conceived KJWT, our goal was to support the JWS format of JWTs. However, as we developed the library, we
realized that supporting the full range of JOSE standards would provide a more robust solution for users.
Therefore, we decided to implement support for JWS, JWE, JWK, and JWA in addition to JWT. This allows KJWT to be a
comprehensive library for working with JSON Web Tokens and related standards.

That said, our plan is not to implement all the RFCs. We will focus our efforts on implementing the ones that are
necessary and relevant for JWT use cases. Some RFCs that are not relevant, or that explicitly state they should not be
used with JWTs, may not be implemented. One example is the
[RFC-7797 - JSON Web Signature (JWS) Unencoded Payload Option](https://www.rfc-editor.org/rfc/rfc7797.html) which
states in section 7 that it should not be used with JWTs.

## Features

As of now, the library supports the following operations:

| Operations      | Signing Algorithms | Encryption Algorithms     | Platforms                                   |
|-----------------|--------------------|---------------------------|---------------------------------------------|
| ✅ Sign          | ✅ HS256            | ✅ RSA-OAEP `(alg)`        | ✅ JVM (incl. Android)                       |
| ✅ Verify        | ✅ HS384            | ✅ RSA-OAEP-256 `(alg)`    | ✅ JS (node + browser)⁴                      |
| ✅ `iss` check¹  | ✅ HS512            | ✅ dir `(alg)`             | ✅ wasmJs (node + browser)⁴                  |
| ✅ `sub` check¹  | ✅ RS256            | ❌ A128KW `(alg)`          | ❌ wasmWasi⁵                                 |
| ✅ `aud` check¹  | ✅ RS384            | ❌ A192KW `(alg)`          | ✅ iOS (arm64, x64, simulatorArm64)⁶         |
| ✅ `exp` check   | ✅ RS512            | ❌ A256KW `(alg)`          | ✅ macOS (x64, arm64)⁶                       |
| ✅ `nbf` check   | ✅ ES256            | ❌ ECDH-ES `(alg)`         | ✅ watchOS (x64, arm32, arm64, sim, device)⁶ |
| ⚠️ `iat` check² | ❌ ES256K           | ✅ A128GCM `(enc)`         | ✅ tvOS (x64, arm64, sim)⁶                   |
| ⚠️ `jti` check² | ✅ ES384            | ⚠️ A192GCM `(enc)`⁴       | ✅ Linux (x64, arm64)                        |
| ❌ `typ` check   | ✅ ES512            | ✅ A256GCM `(enc)`         | ✅ Windows/MinGW (x64)                       |
|                 | ✅ PS256³           | ✅ A128CBC-HS256 `(enc)`   | ✅ Android Native (x64, x86, arm64, arm32)   |
|                 | ✅ PS384³           | ⚠️ A192CBC-HS384 `(enc)`⁴ |                                             |
|                 | ✅ PS512³           | ✅ A256CBC-HS512 `(enc)`   |                                             |
|                 | ❌ EdDSA            |                           |                                             |

> ¹ Opt-in: call `requireIssuer()` / `requireSubject()` / `requireAudience()` on the parser builder. A missing claim
> throws `MissingClaimException`; a mismatched value throws `IncorrectClaimException`.
>
> ² Accessible via `payload.issuedAtOrNull` / `payload.jwtIdOrNull` but not automatically validated. Use the generic
`requireClaim()` for custom validation.
>
> ³ PS256 / PS384 / PS512 are not supported by Android's default JDK security provider. Register BouncyCastle as the
> security provider to enable them. Android Native targets use OpenSSL3 and are unaffected.
>
> ⁴ JS and wasmJs use WebCrypto, which does not support 192-bit AES keys. `A192GCM` and `A192CBC-HS384` are unavailable
> on these platforms.
>
> ⁵ wasmWasi has no `cryptography-kotlin` provider. The library compiles for this target but all cryptographic
> operations throw at runtime.
>
> ⁶ Apple targets (iOS, macOS, watchOS, tvOS): use `cryptography-provider-optimal` for full algorithm support (CryptoKit
> for AES-GCM; Apple/CommonCrypto for AES-CBC+HMAC and RSA). `cryptography-provider-openssl3-prebuilt` also supports all
> algorithms and is a good choice when a single consistent provider is needed across Apple, Linux, and Android Native.
> With only `cryptography-provider-cryptokit`, RSA and AES-CBC algorithms are unavailable. With only
> `cryptography-provider-apple`, AES-GCM algorithms are unavailable.

---

## Setup

Add the library to your project and register a cryptography provider. The `cryptography-provider-optimal` artifact
auto-registers on startup and is the recommended choice:

```kotlin
// build.gradle.kts
dependencies {
    implementation("co.touchlab:kjwt:<kjwt-version>")

    // Include the provider you want to use from Cryptography Kotlin
    // For more details, see https://whyoleg.github.io/cryptography-kotlin/providers/
    implementation("dev.whyoleg.cryptography:cryptography-provider-optimal:<cryptography-kotlin-version>")
}
```

### Snapshot builds

Every merge to `main` is automatically published to the Maven snapshot repository. To use a snapshot version, add the
repository and use the `-SNAPSHOT` suffix:

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        maven("https://central.sonatype.com/repository/maven-snapshots")
    }
}
```

```kotlin
// build.gradle.kts
dependencies {
    implementation("co.touchlab:kjwt:<kjwt-version>-SNAPSHOT")
}
```

## Why another library?

[Signum](https://a-sit-plus.github.io/signum/) is a community KMP library that aims to support many cryptographic
operations, such as JWT operations. Their library is more feature-rich and supports many algorithms. However, it has a
requirement of SDK 30+ for Android projects. This limitation is needed as they support hardware-backed operations that
have such a requirement.

On the other hand, [Cryptography Kotlin](https://whyoleg.github.io/cryptography-kotlin/) is another community library
with a much narrower scope. It supports a wide range of platforms and algorithms, but its goal is to provide access to
the cryptographic APIs, and not to implement any specific protocol on top of it.

Our goal is to support JWT on top of the cryptographic library. We aim to provide an easy-to-migrate API for
Kotlin/Java-only applications that are using JJWT for this purpose, supporting the main KMP platforms available.
As of now, the library is compliant with the JWS and JWE specifications.

## Usage

All actions were designed to be chainable, and start from the `Jwt` (`import co.touchlab.kjwt.Jwt`) object. It is the
entrypoint for most JWT operations. In that object, you will find methods to `build` and `parse` JWTs.

### Building a JWT

The most common usage of JWTs is to generate signed tokens. You can achieve this by using the `.signWith(...)` method
when building a JWT.

```kotlin
val token: JwtInstance = Jwt.builder()
    .subject("1234567890")
    .signWith(JwsAlgorithm.HS256, hmacKey)
```

The result of the operation is a `JwtInstance` object. That object is a Kotlin representation of the JWT. You can use
it to access the defined claims and headers, as well as generate the famous compact version of the JWT.

```kotlin
val token: JwtInstance = // build the token as shown above
val serialized: String = token.compact()
// This call will generate the string version of the JWT, in the compact format
// Note: the compact format is the one split by the dots, with the header, payload and signature encoded in Base64URL
// format. It will look like this:
// <header>.<payload>.<signature> 👈This is the compact format template 👇And this is a real example
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.yaquqtp1qJ9uDVaWMdRtujneuFqIBkImorBu9hdLVl4
```

### Parsing a JWT

Another common usage of JWTs is to verify the authenticity of a token. If you are a backend application, you need to
ensure that the user hasn't modified the token on their side. That is achieved by verifying the signature of the token.

```kotlin
val compactToken: String = // 

val jwtParser = Jwt.parser()
    .verifyWith(JwsAlgorithm.HS256, hmacKey)
    .build()

val parsedToken = jwtParser.parse(compactToken)
```

Note that if the content has been changed on the client side, the signature will be invalid and the parsing will throw
an
exception. If the parse succeeds, the token is valid and ready to be used.

```kotlin
// Use content from the JWT:
val subject = parsedToken.payload.subjectOrNull
```

### Keys

As you probably noticed, we skipped the keys part in the previous examples. The main reason for that is that we do not
implement any cryptographic operations. Instead, we rely on
the [Cryptography Kotlin](https://github.com/whyoleg/cryptography-kotlin) library. It's an amazing and robust library
that provides a wide range of cryptographic operations, and providers for most of the Kotlin Multiplatform targets.

To generate the `hmacKey` we used in the previous examples, you can use the following code:

```kotlin
val myKeyString = "a-string-secret-at-least-256-bits-long"
    .encodeToByteArray() // Convert the string into a byte array to perform the crypto operations

val hmacKey =
    CryptographyProvider.Default // Get the provider you use for your project. CryptographyProvider.Default is most common
        .get(HMAC) // Get the HMAC algorithm
        .keyDecoder(SHA256) // Use the correct digest for your operation. For HS256, use SHA256. For HS384 use SHA384, etc.
        .decodeFromByteArray(HMAC.Key.Format.RAW, myKeyString) // Decode your key bytes into a HMAC key

// Then you can use the HMAC key to sign or verify tokens
val token: JwtInstance = Jwt.builder()
    .subject("1234567890")
    .signWith(JwsAlgorithm.HS256, hmacKey)

val jwtParser = Jwt.parser()
    .verifyWith(JwsAlgorithm.HS256, hmacKey)
    .build()
```

### More features

For a more detailed list of features, check out the usage documentation available at the [docs](docs/USAGE.md).