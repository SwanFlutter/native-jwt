# Changelog

All notable changes to `swanflutter/native-jwt` will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] — 2026-07-15

### Added

- **ES512** (`ECDSA P-521 / SHA-512`) algorithm support with correct 132-byte `R||S` concatenation.
- **EdDSA** (`Ed25519`) algorithm support via `ext-sodium` (`sodium_crypto_sign_detached` / `_verify_detached`).
  - Keys accepted as base64url-encoded, base64-encoded, or raw 32/64-byte strings.
- **PS256 / PS384 / PS512** (`RSASSA-PSS`) algorithm support via a pure-PHP RFC 8017 EMSA-PSS implementation on top of `ext-openssl` — no `phpseclib` required.
  - EMSA-PSS encode/verify with salt length = hash length and MGF1.
- **`JWK` class** — parses JSON Web Key Set (JWKS) documents into `array<kid, Key>`.
  - Supports `kty=RSA` (RS256/384/512, PS256/384/512) — requires `ext-gmp`.
  - Supports `kty=EC` — P-256 (ES256), P-384 (ES384), P-521 (ES512).
  - Supports `kty=OKP` — Ed25519 (EdDSA).
  - Filters out non-signing keys (`use=enc`, `key_ops` without `verify`).
  - Silently skips unsupported / malformed individual keys.
  - `JWK::parseKey()` for single-key parsing.
- **`CachedKeySet` class** — lazy PSR-6-cached remote JWKS fetching.
  - Implements `ArrayAccess<string, Key>` — passes directly to `JWT::decode()`.
  - PSR-18 HTTP client + PSR-17 request factory (no hard dependency on any HTTP library).
  - TTL from explicit `expiresAfter` parameter or parsed from `Cache-Control: max-age`.
  - Automatic single cache-bust on unknown `kid` to support key rotation.
  - Optional rate limiting (max 10 HTTP refreshes per second).
- `suggest` entries in `composer.json` for optional extensions (`ext-sodium`, `ext-gmp`, PSR interfaces).
- New test class `JWKTest` covering RSA / EC / OKP key parsing, error cases, and a Google-style FCM JWKS fixture test.

### Changed

- `JWT::ALGORITHMS` extended with `ES512`, `EdDSA`, `PS256`, `PS384`, `PS512`.
- `JWT::SUPPORTED_ALGS` extended to include all new algorithms.
- `JWT::sign()` and `JWT::verify()` extended with `ecdsa`, `eddsa`, and `rsa-pss` branches.
- ECDSA `derToConcat` now uses a `ECDSA_CONCAT_LENGTHS` map (`ES256=64`, `ES384=96`, `ES512=132`) instead of an inline condition.
- `composer.json` description, keywords, and version updated.

---

## [1.0.0] — 2026-07-15

### Added
- Standalone, **dependency-free** JWT library for PHP 8.1+ (only `ext-openssl`, `ext-hash`, `ext-json` required).
- `JWT::encode()` / `JWT::decode()` API, drop-in compatible with `firebase/php-jwt`'s signing call.
- Algorithm support:
  - HMAC (symmetric): `HS256`, `HS384`, `HS512`
  - RSA (asymmetric): `RS256`, `RS384`, `RS512`
  - ECDSA (asymmetric): `ES256`, `ES384` (with correct DER ↔ `R||S` conversion)
- `Key` object that binds a key to a single algorithm.
- Typed exception hierarchy (all extend `JWTException`):
  - `ExpiredException` (`exp`)
  - `BeforeValidException` (`nbf` / `iat`)
  - `SignatureInvalidException` (bad signature / disallowed algorithm)
  - `InvalidTokenException` (malformed token)
- `kid`-based key sets for multi-key rotation.
- Configurable clock-skew `leeway`.

### Security
- The `alg: none` attack is explicitly rejected.
- Algorithm-confusion is prevented: the token algorithm must exactly match the trusted key's bound algorithm.
- HMAC signatures are compared in constant time via `hash_equals`.
- `exp` / `nbf` / `iat` claims are validated.
- PHPUnit test suite (28 tests, including the RFC 7515 Appendix A.3 ECDSA P-256 vector) verifying the DER ↔ `R||S` conversion.

---

[1.1.0]: https://github.com/swanflutter/native-jwt/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/swanflutter/native-jwt/releases/tag/v1.0.0
