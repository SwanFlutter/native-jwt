# swanflutter/native-jwt

A **standalone, dependency-free** JWT library for PHP 8.1+.

It only relies on PHP's bundled extensions (`openssl`, `hash`, `json`) — **no
Composer dependencies** — and is a drop-in replacement for `firebase/php-jwt`'s
`JWT::encode()` / `JWT::decode()` signing API.

## Supported algorithms

| Family | Algorithms |
|--------|------------|
| HMAC (symmetric) | `HS256`, `HS384`, `HS512` |
| RSA (asymmetric)  | `RS256`, `RS384`, `RS512` |
| ECDSA (asymmetric)| `ES256`, `ES384` |

## Security

- **`alg: none` is explicitly rejected.**
- **Algorithm confusion is prevented**: every trusted key is bound to a single
  algorithm via the `Key` object, and the token algorithm must match it exactly.
- HMAC signatures are compared in **constant time** (`hash_equals`).
- `exp` / `nbf` / `iat` claims are validated with configurable `leeway`.
- ECDSA signatures are correctly converted between OpenSSL's DER format and the
  `R||S` concatenation required by the JWT specification.

## Installation

```bash
composer require swanflutter/native-jwt
```

## Usage

```php
use SwanFlutter\NativeJwt\JWT;
use SwanFlutter\NativeJwt\Key;

// HMAC (symmetric)
$secret = 'your-super-secret-key-of-at-least-32-bytes!!';

$payload = [
    'iss' => 'https://example.com',
    'sub' => 'user-123',
    'iat' => time(),
    'exp' => time() + 3600,
];

$token = JWT::encode($payload, $secret, 'HS256');
$decoded = JWT::decode($token, new Key($secret, 'HS256'));

// RSA / ECDSA (asymmetric)
$privateKey = file_get_contents('private.pem');
$publicKey  = file_get_contents('public.pem');

$token   = JWT::encode($payload, $privateKey, 'RS256', 'my-key-id');
$decoded = JWT::decode($token, new Key($publicKey, 'RS256'));

// Multiple keys resolved by "kid"
$keys = [
    'key-2024' => new Key($publicKeyOld, 'RS256'),
    'key-2025' => new Key($publicKeyNew, 'RS256'),
];
$decoded = JWT::decode($token, $keys);
```

### Exception hierarchy

All exceptions extend `SwanFlutter\NativeJwt\Exceptions\JWTException`:

- `ExpiredException` – `exp` exceeded
- `BeforeValidException` – `nbf` / `iat` in the future
- `SignatureInvalidException` – bad signature / disallowed algorithm
- `InvalidTokenException` – malformed token

## Generating keys

```bash
# RSA
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# ECDSA (ES256)
openssl ecparam -genkey -name prime256v1 -noout -out ec-private.pem
openssl ec -in ec-private.pem -pubout -out ec-public.pem
```

## Testing

```bash
composer install
composer test
```

## License

MIT
