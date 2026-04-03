# Advanced

## Customising the `Json` Instance

By default, KJWT uses an internal `Json` configured with `ignoreUnknownKeys = true` and
`explicitNulls = false`. This handles the most common use cases. If your application needs different
serialization behaviour — for example, `encodeDefaults = true` or custom serializers registered via
a `SerializersModule` — you can supply your own `Json` instance.

### Builder and parser

Pass a custom `Json` to `Jwt.builder()` or `Jwt.parser()`. The instance propagates automatically
to every JSON operation performed by that builder or parser (claim serialization, payload and header
encoding/decoding, etc.):

```kotlin
val customJson = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
    serializersModule = mySerializersModule
}

// builder — affects claim/payload/header serialization
val jws = Jwt.builder(customJson)
    .subject("user-123")
    .payload(UserClaims(role = "admin"))
    .signWith(signingKey)

// parser — affects payload/header deserialization
val parser = Jwt.parser(customJson)
    .verifyWith(signingKey)
    .build()
```

### Per-call overrides

Methods that directly perform JSON serialization also accept an optional `jsonInstance` parameter,
so you can override the instance for a single call without rebuilding the whole builder or parser:

```kotlin
// Deserialize the payload with a custom Json
val claims: UserClaims = jws.getPayload<UserClaims>(jsonInstance = customJson)

// Deserialize the header with a custom Json
val header: MyHeader = jws.getHeader<MyHeader>(jsonInstance = customJson)

// Read a custom claim with a custom Json
val role: String = jws.payload.getClaim(String.serializer(), "role", jsonInstance = customJson)

// Set a header parameter using a custom Json (JwtHeader.Builder)
headerBuilder.extra("x-meta", MyMeta.serializer(), meta, jsonInstance = customJson)
headerBuilder.takeFrom(MyHeader.serializer(), myHeader, jsonInstance = customJson)

// Set a payload claim using a custom Json (JwtPayload.Builder)
payloadBuilder.claim("meta", MyMeta.serializer(), meta, jsonInstance = customJson)
payloadBuilder.takeFrom(UserClaims.serializer(), claims, jsonInstance = customJson)
```

All `jsonInstance` parameters default to `Jwt.defaultJsonParser`, so existing code requires no
changes.

### Global default — `Jwt.defaultJsonParser`

`Jwt.defaultJsonParser` is a `var` on the `Jwt` object. Reassigning it changes the default used by
every subsequent `Jwt.builder()` and `Jwt.parser()` call that does not supply an explicit
`jsonInstance`. This is useful when you want a single configuration point for the whole application:

```kotlin
// Application startup — set once, affects all future builders and parsers
Jwt.defaultJsonParser = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
    serializersModule = mySerializersModule
}

// No explicit jsonInstance needed — picks up the new default
val jws = Jwt.builder()
    .subject("user-123")
    .signWith(signingKey)
```

Per-call `jsonInstance` parameters still take precedence over `Jwt.defaultJsonParser`.

---

## API Stability Annotations

KJWT uses three opt-in annotations to communicate the stability of its API surface.

### `@ExperimentalKJWTApi`

Marks APIs that are functional but whose design may change before they are promoted to stable. Using
an annotated declaration produces a **compiler warning** unl
ess you opt in.

Opt in for a single call site with the annotation:

```kotlin
@OptIn(ExperimentalKJWTApi::class)
fun myFunction() {
    val registry = DefaultJwtProcessorRegistry()
    // ...
}
```

Or suppress warnings for a whole module in `build.gradle.kts`:

```kotlin
kotlin {
    sourceSets {
        commonMain {
            languageSettings.optIn("co.touchlab.kjwt.annotations.ExperimentalKJWTApi")
        }
    }
}
```

### `@InternalKJWTApi`

Marks APIs intended only for use within the KJWT library itself. Using an annotated declaration
produces a **compiler error** — these APIs may change or be removed without notice and are not part
of the public contract.

Do not opt in to `@InternalKJWTApi` in application or library code. If you find yourself needing
something that is marked internal, open an issue so it can be considered for promotion to a stable
API.

### `@DelicateKJWTApi`

Marks APIs that are not meant for typical client usage. These APIs are publicly accessible but carry
security implications or require precise usage to avoid undefined behaviour. Using an annotated
declaration produces a **compiler error** unless you opt in.

Prefer the higher-level helpers (e.g. the algorithm extension functions in
`co.touchlab.kjwt.cryptography.ext`) over any `@DelicateKJWTApi`-annotated constructors or
functions. Opt in only when you fully understand the implications:

```kotlin
@OptIn(DelicateKJWTApi::class)
fun myFunction() {
    // direct constructor usage, e.g. SigningKey.SigningOnlyKey(...)
}
```
