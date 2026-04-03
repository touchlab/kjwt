# KJWT Documentation

KJWT is a Kotlin Multiplatform library for creating, signing, encrypting, parsing, and validating
JWT (RFC 7519), JWS (RFC 7515), and JWE (RFC 7516) tokens. It runs on JVM, JavaScript, WebAssembly,
and Native platforms. All signing, verifying, encrypting, and decrypting operations are `suspend`
functions and must be called from a coroutine.

## Table of Contents

- [Quick Start](./quick-start.md) — sign, verify, encrypt, and decrypt in minutes
- [Keys](./keys.md) — signing keys (HMAC, RSA, ECDSA, PS) and encryption keys (Dir, RSA-OAEP), `kid` assignment, and using raw cryptography-kotlin keys
- [Building Tokens](./building-tokens.md) — standard claims, custom claims, payload merging, header parameters, header merging
- [Parsing Tokens](./parsing-tokens.md) — reading claims, claim validation, unsecured JWTs, auto-detect JWS vs JWE, custom payload and header types
- [Key Rotation](./key-rotation.md) — multiple keys, lookup priority, shared `JwtProcessorRegistry`, `useKeysFrom`
- [Advanced](./advanced.md) — customising the `Json` instance, API stability annotations

## Quick Links

| Operation | Location |
|---|---|
| Sign a JWT | [Quick Start — Sign a JWT](./quick-start.md#sign-a-jwt-jws) |
| Verify a JWS | [Quick Start — Verify a JWS](./quick-start.md#verify--parse-a-jws) |
| Encrypt a JWT | [Quick Start — Encrypt a JWT](./quick-start.md#encrypt-a-jwt-jwe) |
| Decrypt a JWE | [Quick Start — Decrypt a JWE](./quick-start.md#decrypt-a-jwe) |
| Parse claims | [Parsing Tokens — Parsing Claims](./parsing-tokens.md#parsing-claims) |
