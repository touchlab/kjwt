# KJWT

[![Maven Central](https://img.shields.io/maven-central/v/co.touchlab/kjwt?label=Maven%20Central)](https://search.maven.org/artifact/co.touchlab/kjwt)
![Maven Central (Snapshots)](https://img.shields.io/maven-metadata/v?metadataUrl=https%3A%2F%2Fcentral.sonatype.com%2Frepository%2Fmaven-snapshots%2Fco%2Ftouchlab%2Fkjwt%2Fmaven-metadata.xml&label=Snapshot)

Kotlin Multiplatform library implementing JWT ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)).

## Features

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
operations, such as JWT Operations. Their library is more feature-rich and supports many algorithms. However, it has a
requirement of SDK 30+ for Android projects. This limitation is needed as they support hardware backed operations that
have such requirement.

On the other hand, [Cryptography Kotlin](https://whyoleg.github.io/cryptography-kotlin/) is another community library
with a much narrow scope. It supports a wide range of platforms and algorithms, but its goal is to provide access to
the cryptographic APIs, and not to implement any specific protocol on top of it.

Our proposal is to support JWT on top of the cryptographic library. We aim to provide an easy-to-migrate API for
Kotlin/Java only applications that are using JJWT for this purpose, supporting the main KMP platforms available.
As of now, the library is compliant with Jws and Jwe specifications.

## Usage

All actions were designed to be chainable, and start from the `Jwt` (`import co.touchlab.kjwt.Jwt`) object. It the
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
// <header>.<payload>.<signature> 👈This is the compact format template 👇And this a real example
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

Note that if the content was changed on the client side, the signature will be invalid and the parsing will throw an
exception. If the parse succeeds, the token is valid and ready to be used.

```kotlin
// Use content from the JWT:
val subject = jws.payload.subjectOrNull
```

### Keys

As you probably noticed, we skipped the keys part in the previous examples. The main reason for that, is that we do not
implement any cryptographic operations. Instead, we rely on
the [Cryptography Kotlin](https://github.com/whyoleg/cryptography-kotlin) library. It's an amazing and robust library
that provides a wide range of cryptographic operations, and providers for most of the Kotlin Multiplatform targets.

To generate the `hmacKey` we used in the previous examples, you can use the following code:

```kotlin
val myKeyString = "a-string-secret-at-least-256-bits-long"
    .encodeToByteArray() // Convert the string into byte array to perform the crypto operations 

val hmacKey =
    CryptographyProvider.Default // Get the provider you use for your project. CryptographyProvider.Default most common 
        .get(HMAC) // Get the HMAC algorithm
        .keyDecoder(SHA256) // Use the correct digest for your operation. For HS256. For HS384 use SHA384, etc..
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