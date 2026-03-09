# KJWT

Kotlin Multiplatform library implementing JWT ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)), JWS ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)), and JWE ([RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)).

**Targets:** JVM, JS, wasmJs, Apple (iOS, macOS, watchOS, tvOS), Linux, MinGW, Android Native, wasmWasi

**Dependencies:**
- [kotlinx-coroutines](https://github.com/Kotlin/kotlinx.coroutines) - all crypto operations are `suspend` functions
- [kotlinx-serialization](https://github.com/Kotlin/kotlinx.serialization) - header and claims serialization
- [cryptography-kotlin](https://github.com/whyoleg/cryptography-kotlin) - all cryptographic operations

---

## Setup

Add the library to your project and register a cryptography provider. The `cryptography-provider-optimal` artifact auto-registers on startup and is the recommended choice:

```kotlin
// build.gradle.kts
dependencies {
    implementation("co.touchlab:kjwt:<version>")

    // Include the providers you may need from Cryptography Kotlin
    // More details on https://whyoleg.github.io/cryptography-kotlin/providers/
    implementation("dev.whyoleg.cryptography:cryptography-provider-optimal:<version>")
}
```

No explicit provider registration is needed when using `cryptography-provider-optimal` - it registers itself when the class is loaded. For other providers, call `CryptographyProvider.Default` registration before any KJWT calls.

## Documentation

- [Usage Guide](docs/usage.md) - Quick start, API walkthrough, and code examples
- [Algorithms](docs/algorithms.md) - Supported JWS and JWE algorithms with key types
- [Platform Compatibility](docs/platform-compatibility.md) - Per-platform provider selection and algorithm availability
- [Error Handling](docs/error-handling.md) - Exception reference and handling patterns
- [RFC 7519 Compliance](docs/rfc-7519.md) - Compliance checklist against RFC 7519/7518

## Why another library?

[Signum](https://a-sit-plus.github.io/signum/) is a community KMP library that aims to support many cryptographic operations,
such as JWT Operations. Their library is more feature-rich and supports many algorithms. However, it has a requirement
of SDK 30+ for Android projects. This limitation is needed as they support hardware backed operations that have such requirement.

On the other hand, [Cryptography Kotlin](https://whyoleg.github.io/cryptography-kotlin/) is another community library
with a much narrow scope. It supports a wide range of platforms and algorithms, but its goal is to provide access to
the cryptographic APIs, and not to implement any specific protocol on top of it.

Our proposal is to support JWT on top of the cryptographic library. We aim to provide an easy-to-migrate API for
Kotlin/Java only applications that are using JJWT for this purpose, supporting the main KMP platforms available.
As of now, the library is compliant with Jws and Jwe specifications.
