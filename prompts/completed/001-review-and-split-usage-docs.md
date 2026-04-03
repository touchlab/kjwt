<objective>
Review the current `docs/usage.md` documentation, update it to reflect all API changes introduced in
the current branch (`gv/decoupling-refactor`), and split it into focused per-topic files. The goal
is a docs folder that is easy to navigate and always accurate against the current codebase.
</objective>

<context>
This is KJWT — a Kotlin Multiplatform JWT/JWS/JWE library. The `docs/usage.md` file was written
before recent refactors on this branch and is now outdated in places. Key changes visible in the git
log include:

- `KeyRegistry` was renamed to `ProcessorRegistry`
- `SigningKey` and `EncryptionKey` types were made compatible with processors
- Cryptography usages were moved to a dedicated `cryptography/` package
- General modularization

Before rewriting anything, diff the current source against the docs to find every discrepancy.
</context>

<research>
1. Run `git log main..HEAD --oneline` to get the full list of commits on this branch.
2. Run `git diff main -- lib/src/commonMain/kotlin/` to see all API-level changes.
3. Read `docs/usage.md` to understand the current documented API surface.
4. Search the source for any types or functions mentioned in the docs to verify they still exist
   and have not been renamed or removed (pay special attention to `JwtKeyRegistry`,
   `ProcessorRegistry`, `SigningKey`, `EncryptionKey`, and any `useKeysFrom` / `signWith` /
   `encryptWith` overloads that accept a registry).
5. Read `CLAUDE.md` for project conventions before writing any documentation.

After receiving tool results, carefully reflect on what is outdated, what is accurate, and what is
missing before writing a single word of new documentation.
</research>

<requirements>
### Content accuracy
- Every code sample must compile against the **current** public API.
- If a type or function was renamed, use the new name and do not mention the old one.
- If a feature was removed, remove its documentation entirely.
- If a new feature was added that is not yet documented, add a concise section for it.

### File structure (split by feature area)
Create the following files under `docs/`:

| File | Contents |
|---|---|
| `docs/README.md` | Index / entry point — one-paragraph overview + table of contents linking to each file |
| `docs/quick-start.md` | The current "Quick Start" section (sign, verify, encrypt, decrypt) |
| `docs/keys.md` | Signing keys (HMAC, RSA, ECDSA, PS) + Encryption keys (Dir, RSA-OAEP) + `kid` assignment + using raw cryptography-kotlin keys with the parser |
| `docs/building-tokens.md` | Standard claims, custom claims, payload merging, header parameters, header merging |
| `docs/parsing-tokens.md` | Parsing claims, claim validation, unsecured JWTs (`alg=none`), auto-detect JWS vs JWE, custom payload types, custom header types |
| `docs/key-rotation.md` | Multiple keys, lookup priority, shared key registry / `ProcessorRegistry` (or whatever the current API name is), `useKeysFrom` |
| `docs/advanced.md` | Customising the `Json` instance, API stability annotations (`@ExperimentalKJWTApi`, `@InternalKJWTApi`) |

Delete `docs/usage.md` once all content has been migrated and verified.

### Index file (`docs/README.md`)
- One short paragraph describing KJWT.
- A "Table of Contents" section with bullet links to each split file.
- A "Quick links" section with anchored links to the most common operations (sign, verify, encrypt,
  decrypt, parse claims).
</requirements>

<constraints>
- Do **not** add new features, tutorials, or content that does not already exist in `docs/usage.md`
  or in the current source — only migrate + fix.
- Do **not** change prose style or tone — keep the same concise, reference-manual voice.
- All code samples must use Kotlin and must match the library's current public API exactly.
- Use relative Markdown links between files (e.g. `[Keys](./keys.md)`).
</constraints>

<output>
Create or overwrite the following files:
- `./docs/README.md`
- `./docs/quick-start.md`
- `./docs/keys.md`
- `./docs/building-tokens.md`
- `./docs/parsing-tokens.md`
- `./docs/key-rotation.md`
- `./docs/advanced.md`

Then delete `./docs/usage.md`.
</output>

<verification>
Before declaring the task complete:
1. Confirm every type and function name in all code samples exists in the current source (grep if needed).
2. Confirm `docs/usage.md` has been deleted.
3. Confirm `docs/README.md` links to every split file.
4. Confirm no section from the original `docs/usage.md` was accidentally dropped.
</verification>

<success_criteria>
- `docs/usage.md` no longer exists.
- Seven new files exist under `docs/` matching the table above.
- All code samples reflect the current public API of the `gv/decoupling-refactor` branch.
- `docs/README.md` serves as a navigable entry point with links to all sections.
</success_criteria>
