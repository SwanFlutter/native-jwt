# Changelog

All notable changes to `swanflutter/native-jwt` will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

### Changed
- PHPUnit test suite and `phpunit.xml` added.
- `Laravel Pint` configuration applied for code style.

---

[1.0.0]: https://github.com/swanflutter/native-jwt/releases/tag/v1.0.0
