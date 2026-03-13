# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

KJWT is a Kotlin Multiplatform library for creating, signing, encrypting, parsing, and validating JWT (RFC 7519), JWS (RFC 7515), and JWE (RFC 7516) tokens across JVM, JavaScript, WebAssembly, and Native platforms.

## Build & Test Commands

```bash
# Build
./gradlew build

# Run all tests (aggregated report)
./gradlew allTests

# Run tests for specific platforms
./gradlew jvmTest
./gradlew jsTest
./gradlew macosArm64Test
./gradlew linuxX64Test

# Run all checks
./gradlew check
```

Tests live in `lib/src/commonTest/kotlin/` and run on all platforms.

## Architecture

### Entry Points
- `Jwt.builder()` — create and sign/encrypt tokens
- `Jwt.parser()` — parse and verify tokens

### Key Packages (`lib/src/commonMain/kotlin/co/touchlab/kjwt/`)

| Package | Purpose |
|---|---|
| `algorithm/` | JWS (HMAC, RSA, ECDSA) and JWE algorithm definitions |
| `builder/` | `JwtBuilder` — fluent API for creating tokens |
| `parser/` | `JwtParser` / `JwtParserBuilder` — parsing, verification, claim validation |
| `model/` | `Claims`, `JwtPayload`, `JwtHeader`, `JwtInstance` (sealed Jws/Jwe) |
| `cryptography/` | Key wrapper types for each algorithm |
| `ext/` | Extension functions for builder (`JwtBuilderExt`) and parser (`JwtParserExt`) |
| `serializers/` | kotlinx.serialization adapters (audience, instant, headers) |
| `internal/` | Base64URL and JSON utilities |
| `dsl/` | DSL helpers for claim blocks |
| `exception/` | `JwtException` hierarchy |

### Platform Crypto Providers
- JVM: `cryptography-provider-jdk`
- JS/WASM: `cryptography-provider-web`
- Apple: `cryptography-provider-apple`
- Linux/MinGW: `cryptography-provider-openssl3`

Providers are registered per-platform; all crypto is delegated to the [cryptography-kotlin](https://github.com/whyoleg/cryptography-kotlin) library.

### Design Conventions
- All signing and encryption operations are `suspend` functions
- Custom payload types must implement `JwtPayload` and be `@Serializable`
- JWE tokens have 5 parts; JWS tokens have 3 parts
- `alg=none` (unsecured tokens) must be explicitly opted into via `allowUnsecured(true)` on the parser

### Supported Algorithms
- **JWS:** HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512
- **JWE Key:** RSA-OAEP, RSA-OAEP-256, dir
- **JWE Content:** A128GCM, A192GCM, A256GCM, A128CbcHs256, A192CbcHs384, A256CbcHs512

## Dependencies (via `gradle/libs.versions.toml`)
- Kotlin 2.x with Kotlin Multiplatform
- kotlinx-serialization
- kotlinx-coroutines
- cryptography-kotlin 0.5.0
  - For an overview of the API, use the official webpage https://whyoleg.github.io/cryptography-kotlin/api/ 
