# Algorithms

KJWT supports JWS (signing) algorithms via `JwsAlgorithm` and JWE (encryption) algorithms via `JweKeyAlgorithm` + `JweContentAlgorithm`. Unsupported algorithms are noted with the reason.

> **Platform note:** algorithm availability depends on the `cryptography-kotlin` provider in use. See [Platform Compatibility](platform-compatibility.md) for details on which algorithms are available per platform and provider.

## JWS Algorithms (Signing)

`signWith()` takes the **private** key; `verifyWith()` takes the **public** key. For HMAC (`HS*`), the same key is used for both operations.

| Constant | `alg` value | Key type | RFC 7518 status | KJWT | Platform notes |
|---|---|---|---|---|---|
| `JwsAlgorithm.HS256` | `HS256` | `HMAC.Key` | Required | Supported | |
| `JwsAlgorithm.HS384` | `HS384` | `HMAC.Key` | Optional | Supported | |
| `JwsAlgorithm.HS512` | `HS512` | `HMAC.Key` | Optional | Supported | |
| `JwsAlgorithm.RS256` | `RS256` | `RSA.PKCS1.PrivateKey` / `RSA.PKCS1.PublicKey` | Recommended | Supported | |
| `JwsAlgorithm.RS384` | `RS384` | `RSA.PKCS1.PrivateKey` / `RSA.PKCS1.PublicKey` | Optional | Supported | |
| `JwsAlgorithm.RS512` | `RS512` | `RSA.PKCS1.PrivateKey` / `RSA.PKCS1.PublicKey` | Optional | Supported | |
| `JwsAlgorithm.PS256` | `PS256` | `RSA.PSS.PrivateKey` / `RSA.PSS.PublicKey` | Optional | Supported | Android: not supported by default JDK provider¹ |
| `JwsAlgorithm.PS384` | `PS384` | `RSA.PSS.PrivateKey` / `RSA.PSS.PublicKey` | Optional | Supported | Android: not supported by default JDK provider¹ |
| `JwsAlgorithm.PS512` | `PS512` | `RSA.PSS.PrivateKey` / `RSA.PSS.PublicKey` | Optional | Supported | Android: not supported by default JDK provider¹ |
| `JwsAlgorithm.ES256` | `ES256` | `ECDSA.PrivateKey` / `ECDSA.PublicKey` (P-256) | Recommended+ | Supported | |
| `JwsAlgorithm.ES384` | `ES384` | `ECDSA.PrivateKey` / `ECDSA.PublicKey` (P-384) | Optional | Supported | |
| `JwsAlgorithm.ES512` | `ES512` | `ECDSA.PrivateKey` / `ECDSA.PublicKey` (P-521) | Optional | Supported | |
| `JwsAlgorithm.None` | `none` | — | Required | Supported (opt-in only) | |

### Unsecured JWT (`none`)

`alg=none` is supported but **rejected by the parser by default**. Opt in via `parser.allowUnsecured(true)` or `parser.noVerify()`. See [usage.md](usage.md#unsecured-jwts-algnone) for details.

¹ RSA-PSS (`PS*`) is not available in Android's default JDK security provider. To use PS256/PS384/PS512 on Android, register BouncyCastle as the security provider. Android Native targets are unaffected — they use OpenSSL3, which supports RSA-PSS.

---

## JWE Key Algorithms

Controls how the Content Encryption Key (CEK) is established. `encryptWith()` takes the **public** key; `decryptWith()` takes the **private** key. For `Dir`, the same `SimpleKey` wraps the raw CEK bytes for both operations.

| Constant | `alg` value | Key type | RFC 7518 status | KJWT |
|---|---|---|---|---|
| `JweKeyAlgorithm.Dir` | `dir` | `SimpleKey(cekBytes)` | Optional | Supported |
| `JweKeyAlgorithm.RsaOaep` | `RSA-OAEP` | `RSA.OAEP.PublicKey` / `RSA.OAEP.PrivateKey` | Optional | Supported |
| `JweKeyAlgorithm.RsaOaep256` | `RSA-OAEP-256` | `RSA.OAEP.PublicKey` / `RSA.OAEP.PrivateKey` | Optional | Supported |
| — | `ECDH-ES` | — | Recommended | Not supported — ECDH-ES is not available in cryptography-kotlin 0.5.0 |
| — | `A128KW` / `A192KW` / `A256KW` | — | Optional | Not supported — AES Key Wrap is not available in cryptography-kotlin 0.5.0 |

#### `RSA-OAEP` vs `RSA-OAEP-256`

Both use RSA-OAEP but differ in the hash used for the OAEP mask generation function. The key pair must be generated with the matching digest:

```kotlin
// RSA-OAEP (SHA-1)
val keyPair = CryptographyProvider.Default.get(RSA.OAEP)
    .keyPairGenerator(digest = SHA1)
    .generateKey()

// RSA-OAEP-256 (SHA-256)
val keyPair = CryptographyProvider.Default.get(RSA.OAEP)
    .keyPairGenerator(digest = SHA256)
    .generateKey()
```

---

## JWE Content Algorithms

Controls how the plaintext payload is encrypted once the CEK is established.

| Constant | `enc` value | CEK size | RFC 7518 status | KJWT | Platform notes |
|---|---|---|---|---|---|
| `JweContentAlgorithm.A128GCM` | `A128GCM` | 128-bit | Recommended | Supported | Apple: works with optimal provider¹ |
| `JweContentAlgorithm.A192GCM` | `A192GCM` | 192-bit | Optional | Supported | Apple: works with optimal provider¹ |
| `JweContentAlgorithm.A256GCM` | `A256GCM` | 256-bit | Recommended | Supported | Apple: works with optimal provider¹ |
| `JweContentAlgorithm.A128CbcHs256` | `A128CBC-HS256` | 256-bit (128 MAC + 128 enc) | Required | Supported | Apple: works with optimal provider² |
| `JweContentAlgorithm.A192CbcHs384` | `A192CBC-HS384` | 384-bit (192 MAC + 192 enc) | Optional | Supported | Apple: works with optimal provider² |
| `JweContentAlgorithm.A256CbcHs512` | `A256CBC-HS512` | 512-bit (256 MAC + 256 enc) | Optional | Supported | Apple: works with optimal provider² |

¹ AES-GCM is provided by CryptoKit. If you use the Apple (CommonCrypto) provider explicitly instead of `cryptography-provider-optimal`, these algorithms are unavailable and will throw at runtime.

² AES-CBC is provided by Apple (CommonCrypto). If you use the CryptoKit provider explicitly instead of `cryptography-provider-optimal`, these algorithms are unavailable and will throw at runtime.

For `Dir`, the CEK size must exactly match the requirement of the chosen content algorithm. For `RSA-OAEP` / `RSA-OAEP-256`, the CEK is generated randomly and wrapped by the library automatically.