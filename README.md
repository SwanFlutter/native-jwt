# swanflutter/native-jwt

A **PHP 8.1+** JWT library with no mandatory runtime dependencies.

It relies only on PHP's bundled extensions (`openssl`, `hash`, `json`) for the core algorithms, and adds optional support for EdDSA (libsodium), RSA JWK parsing (GMP), and remote JWKS caching (PSR-18 / PSR-17 / PSR-6).

Drop-in replacement for `firebase/php-jwt`'s `JWT::encode()` / `JWT::decode()` API, with full feature parity.

## Supported algorithms

| Family | Algorithms | Requires |
|---|---|---|
| HMAC (symmetric) | `HS256`, `HS384`, `HS512` | built-in |
| RSA PKCS#1 v1.5 | `RS256`, `RS384`, `RS512` | `ext-openssl` |
| RSA-PSS | `PS256`, `PS384`, `PS512` | `ext-openssl` |
| ECDSA | `ES256`, `ES384`, `ES512` | `ext-openssl` |
| EdDSA (Ed25519) | `EdDSA` | `ext-sodium` |

## Security

- **`alg: none` is explicitly rejected.**
- **Algorithm-confusion is prevented**: every trusted key is bound to a single algorithm via the `Key` object.
- HMAC and EdDSA signatures are compared in **constant time**.
- `exp` / `nbf` / `iat` claims are validated with configurable `leeway`.
- ECDSA signatures are correctly converted between OpenSSL's DER format and the `R||S` concatenation required by the JWT spec.
- RSASSA-PSS is implemented with RFC 8017-compliant EMSA-PSS encoding (salt length = hash length, MGF1).

## Installation

```bash
composer require swanflutter/native-jwt
```

Optional extras:

```bash
# EdDSA (Ed25519) support
# Linux: apt install php-sodium  |  macOS: brew install php
# Windows: enable extension=sodium in php.ini

# RSA JWK parsing (JWK::parseKeySet with RSA keys)
# Linux: apt install php-gmp  |  macOS: brew install php
# Windows: enable extension=gmp in php.ini

# CachedKeySet (remote JWKS fetch + PSR-6 cache)
composer require psr/http-client psr/http-factory psr/cache
# Then add a concrete implementation, e.g.:
composer require guzzlehttp/guzzle guzzlehttp/psr7 symfony/cache
```

---

## Usage

### HMAC (symmetric)

```php
use SwanFlutter\NativeJwt\JWT;
use SwanFlutter\NativeJwt\Key;

$secret = 'your-super-secret-key-of-at-least-32-bytes!!';

$payload = [
    'iss' => 'https://example.com',
    'sub' => 'user-123',
    'iat' => time(),
    'exp' => time() + 3600,
];

$token   = JWT::encode($payload, $secret, 'HS256');
$decoded = JWT::decode($token, new Key($secret, 'HS256'));
```

### RSA / ECDSA (asymmetric)

```php
$privateKey = file_get_contents('private.pem');
$publicKey  = file_get_contents('public.pem');

$token   = JWT::encode($payload, $privateKey, 'RS256', 'my-key-id');
$decoded = JWT::decode($token, new Key($publicKey, 'RS256'));
```

### RSASSA-PSS (PS256 / PS384 / PS512)

```php
// Same key format as RS* — just change the algorithm name.
$token   = JWT::encode($payload, $privateKey, 'PS256');
$decoded = JWT::decode($token, new Key($publicKey, 'PS256'));
```

### EdDSA (Ed25519)

```php
// Keys are base64url-encoded raw bytes (compatible with sodium_crypto_sign_*).
$keyPair = sodium_crypto_sign_keypair();
$privKey = base64_encode(sodium_crypto_sign_secretkey($keyPair));
$pubKey  = base64_encode(sodium_crypto_sign_publickey($keyPair));

$token   = JWT::encode($payload, $privKey, 'EdDSA');
$decoded = JWT::decode($token, new Key($pubKey, 'EdDSA'));
```

### Multiple keys by `kid`

```php
$keys = [
    'key-2024' => new Key($publicKeyOld, 'RS256'),
    'key-2025' => new Key($publicKeyNew, 'RS256'),
];
$decoded = JWT::decode($token, $keys);
```

### Clock skew / leeway

```php
JWT::$leeway = 60; // tolerate up to 60 seconds of clock skew
$decoded = JWT::decode($token, new Key($publicKey, 'RS256'));
```

---

## JWK / JWKS

### Parse a static JWKS document

```php
use SwanFlutter\NativeJwt\JWK;

// $jwks is the decoded JSON from a JWKS endpoint (e.g. Google, Firebase).
$keys = JWK::parseKeySet($jwks);           // returns array<kid, Key>
$decoded = JWT::decode($token, $keys);
```

Supported key types:

| `kty` | Curves / algorithms |
|---|---|
| `RSA` | RS256, RS384, RS512, PS256, PS384, PS512 |
| `EC` | P-256 (ES256), P-384 (ES384), P-521 (ES512) |
| `OKP` | Ed25519 (EdDSA) |

> RSA JWK parsing requires `ext-gmp`.

### CachedKeySet — remote JWKS with PSR-6 cache

```php
use SwanFlutter\NativeJwt\CachedKeySet;

$keySet = new CachedKeySet(
    jwksUri:           'https://www.googleapis.com/oauth2/v3/certs',
    httpClient:        $psrHttpClient,      // PSR-18 ClientInterface
    requestFactory:    $psrRequestFactory,  // PSR-17 RequestFactoryInterface
    cache:             $psrCachePool,       // PSR-6 CacheItemPoolInterface
    expiresAfter:      3600,                // TTL in seconds (null = use Cache-Control)
    rateLimit:         true,                // max 10 refreshes/second
);

$decoded = JWT::decode($token, $keySet);
```

`CachedKeySet` automatically refreshes the cache once when an unknown `kid` is encountered, which supports key rotation without manual intervention.

**Example with Guzzle + Symfony Cache:**

```php
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use SwanFlutter\NativeJwt\CachedKeySet;

$keySet = new CachedKeySet(
    jwksUri:        'https://www.googleapis.com/oauth2/v3/certs',
    httpClient:     new Client(),
    requestFactory: new HttpFactory(),
    cache:          new FilesystemAdapter(),
    expiresAfter:   3600,
);
```

---

## Firebase FCM HTTP v1 — access token

Firebase FCM HTTP v1 requires a short-lived OAuth 2.0 access token signed with a Google service account key. The service account JSON contains an RSA private key (`RS256`).

```php
use SwanFlutter\NativeJwt\JWT;
use SwanFlutter\NativeJwt\Key;

$serviceAccount = json_decode(file_get_contents('service-account.json'), true);

$now = time();
$jwtPayload = [
    'iss'   => $serviceAccount['client_email'],
    'sub'   => $serviceAccount['client_email'],
    'aud'   => 'https://oauth2.googleapis.com/token',
    'iat'   => $now,
    'exp'   => $now + 3600,
    'scope' => 'https://www.googleapis.com/auth/firebase.messaging',
];

$assertion = JWT::encode(
    $jwtPayload,
    $serviceAccount['private_key'],
    'RS256',
    $serviceAccount['private_key_id']
);

// Exchange the JWT assertion for an access token.
$response = (new GuzzleHttp\Client())->post('https://oauth2.googleapis.com/token', [
    'form_params' => [
        'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion'  => $assertion,
    ],
]);

$accessToken = json_decode((string) $response->getBody(), true)['access_token'];
```

---

## Exception hierarchy

All exceptions extend `SwanFlutter\NativeJwt\Exceptions\JWTException`:

| Exception | Cause |
|---|---|
| `ExpiredException` | `exp` claim exceeded |
| `BeforeValidException` | `nbf` or `iat` is in the future |
| `SignatureInvalidException` | bad signature, disallowed algorithm, algorithm mismatch |
| `InvalidTokenException` | malformed token, missing claims, bad Base64 |

```php
use SwanFlutter\NativeJwt\Exceptions\JWTException;
use SwanFlutter\NativeJwt\Exceptions\ExpiredException;
use SwanFlutter\NativeJwt\Exceptions\SignatureInvalidException;

try {
    $decoded = JWT::decode($token, $keys);
} catch (ExpiredException $e) {
    // token has expired
} catch (SignatureInvalidException $e) {
    // signature verification failed
} catch (JWTException $e) {
    // all other JWT errors
}
```

---

## Generating keys

```bash
# RSA (for RS256 / PS256)
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# ECDSA P-256 (ES256)
openssl ecparam -genkey -name prime256v1 -noout -out ec-private.pem
openssl ec -in ec-private.pem -pubout -out ec-public.pem

# ECDSA P-384 (ES384)
openssl ecparam -genkey -name secp384r1 -noout -out ec384-private.pem
openssl ec -in ec384-private.pem -pubout -out ec384-public.pem

# ECDSA P-521 (ES512)
openssl ecparam -genkey -name secp521r1 -noout -out ec521-private.pem
openssl ec -in ec521-private.pem -pubout -out ec521-public.pem

# Ed25519 (EdDSA) — via PHP sodium
php -r "
    \$kp = sodium_crypto_sign_keypair();
    file_put_contents('ed25519.priv.b64', base64_encode(sodium_crypto_sign_secretkey(\$kp)));
    file_put_contents('ed25519.pub.b64',  base64_encode(sodium_crypto_sign_publickey(\$kp)));
"
```

---

## Testing

```bash
composer install
composer test
```

---

## License

MIT
