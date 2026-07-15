<?php

declare(strict_types=1);

namespace SwanFlutter\NativeJwt\Tests;

use PHPUnit\Framework\TestCase;
use SwanFlutter\NativeJwt\Exceptions\BeforeValidException;
use SwanFlutter\NativeJwt\Exceptions\ExpiredException;
use SwanFlutter\NativeJwt\Exceptions\InvalidTokenException;
use SwanFlutter\NativeJwt\Exceptions\JWTException;
use SwanFlutter\NativeJwt\Exceptions\SignatureInvalidException;
use SwanFlutter\NativeJwt\JWT;
use SwanFlutter\NativeJwt\Key;

final class JWTTest extends TestCase
{
    private string $secret = 'this-is-a-very-long-shared-secret-key-of-at-least-32-bytes!!';

    /** @var string */
    private $cnf;

    /** @var string */
    private $rsaPrivate;

    /** @var string */
    private $rsaPublic;

    /** @var string */
    private $ecPrivate;

    /** @var string */
    private $ecPublic;

    protected function setUp(): void
    {
        parent::setUp();

        // Reset global state between tests.
        JWT::$leeway = 0;
        JWT::$timestamp = null;

        // A minimal OpenSSL config is bundled so key generation works even on
        // systems where the default openssl.cnf is missing (e.g. some Windows
        // PHP builds). It is used only by the tests, never by the library.
        $this->cnf = __DIR__.'/fixtures/openssl.cnf';

        $rsa = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'digest_alg' => 'sha256',
            'bits' => 2048,
            'config' => $this->cnf,
        ]);
        openssl_pkey_export($rsa, $this->rsaPrivate, null, ['config' => $this->cnf]);
        $this->rsaPublic = (string) openssl_pkey_get_details($rsa)['key'];

        $ec = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'config' => $this->cnf,
        ]);
        openssl_pkey_export($ec, $this->ecPrivate, null, ['config' => $this->cnf]);
        $this->ecPublic = (string) openssl_pkey_get_details($ec)['key'];
    }

    // ---------------------------------------------------------------------
    //  HMAC
    // ---------------------------------------------------------------------

    public function test_hs256_round_trip(): void
    {
        $payload = ['sub' => 'user-1', 'exp' => time() + 3600];

        $token = JWT::encode($payload, $this->secret, 'HS256');
        $decoded = JWT::decode($token, new Key($this->secret, 'HS256'));

        self::assertSame($payload, $decoded);
    }

    public function test_hs384_and_hs512_round_trip(): void
    {
        foreach (['HS384', 'HS512'] as $alg) {
            $token = JWT::encode(['a' => 1], $this->secret, $alg);
            self::assertSame(['a' => 1], JWT::decode($token, new Key($this->secret, $alg)));
        }
    }

    // ---------------------------------------------------------------------
    //  RSA
    // ---------------------------------------------------------------------

    public function test_rs256_round_trip(): void
    {
        $payload = ['sub' => 'user-2', 'exp' => time() + 3600];

        $token = JWT::encode($payload, $this->rsaPrivate, 'RS256');
        $decoded = JWT::decode($token, new Key($this->rsaPublic, 'RS256'));

        self::assertSame($payload, $decoded);
    }

    public function test_rs384_and_rs512_round_trip(): void
    {
        foreach (['RS384', 'RS512'] as $alg) {
            $token = JWT::encode(['b' => 2], $this->rsaPrivate, $alg);
            self::assertSame(['b' => 2], JWT::decode($token, new Key($this->rsaPublic, $alg)));
        }
    }

    // ---------------------------------------------------------------------
    //  ECDSA
    // ---------------------------------------------------------------------

    public function test_es256_round_trip(): void
    {
        $payload = ['sub' => 'user-3', 'exp' => time() + 3600];

        $token = JWT::encode($payload, $this->ecPrivate, 'ES256');
        $decoded = JWT::decode($token, new Key($this->ecPublic, 'ES256'));

        self::assertSame($payload, $decoded);
    }

    public function test_es384_round_trip(): void
    {
        $token = JWT::encode(['c' => 3], $this->ecPrivate, 'ES384');
        self::assertSame(['c' => 3], JWT::decode($token, new Key($this->ecPublic, 'ES384')));
    }

    /**
     * Verifies the library against the official RFC 7515 Appendix A.3 vector.
     * This independently confirms the DER <-> R||S signature conversion.
     */
    public function test_es256_rfc7515_vector(): void
    {
        $header = 'eyJhbGciOiJFUzI1NiJ9';
        $payload = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
        $signature = 'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q';

        $token = $header.'.'.$payload.'.'.$signature;

        $pubKey = self::buildP256PublicKey(
            'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0'
        );

        // Pin the clock just before "exp" so the time-based checks pass.
        JWT::$timestamp = 1300819379;

        $decoded = JWT::decode($token, new Key($pubKey, 'ES256'));

        self::assertSame('joe', $decoded['iss']);
        self::assertSame(1300819380, $decoded['exp']);
        self::assertTrue($decoded['http://example.com/is_root']);
    }

    // ---------------------------------------------------------------------
    //  Security: alg=none and algorithm confusion
    // ---------------------------------------------------------------------

    public function test_alg_none_is_rejected(): void
    {
        $token = JWT::encode(['sub' => 'x'], $this->secret, 'HS256');
        $token = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.'.substr($token, strpos($token, '.') + 1);

        $this->expectException(SignatureInvalidException::class);

        JWT::decode($token, new Key($this->secret, 'HS256'));
    }

    public function test_unsupported_algorithm_is_rejected(): void
    {
        $token = JWT::encode(['sub' => 'x'], $this->secret, 'HS256');
        $token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.'.substr($token, strpos($token, '.') + 1);

        $this->expectException(SignatureInvalidException::class);

        JWT::decode($token, new Key($this->secret, 'HS256'));
    }

    public function test_algorithm_confusion_is_prevented(): void
    {
        // Token is signed with HMAC but the trusted key is bound to RSA.
        $token = JWT::encode(['sub' => 'x'], $this->secret, 'HS256');

        $this->expectException(SignatureInvalidException::class);

        JWT::decode($token, new Key($this->rsaPublic, 'RS256'));
    }

    // ---------------------------------------------------------------------
    //  Signature / tampering
    // ---------------------------------------------------------------------

    public function test_invalid_signature_is_rejected(): void
    {
        $token = JWT::encode(['sub' => 'x'], $this->secret, 'HS256');
        $token = substr($token, 0, -3).'AAA';

        $this->expectException(SignatureInvalidException::class);

        JWT::decode($token, new Key($this->secret, 'HS256'));
    }

    public function test_tampered_payload_is_rejected(): void
    {
        $token = JWT::encode(['sub' => 'x', 'role' => 'user'], $this->secret, 'HS256');
        [$h, $p, $s] = explode('.', $token);

        $payload = json_decode(JWT::urlsafeB64Decode($p), true);
        $payload['role'] = 'admin';
        $p = JWT::urlsafeB64Encode((string) json_encode($payload));

        $this->expectException(SignatureInvalidException::class);

        JWT::decode($h.'.'.$p.'.'.$s, new Key($this->secret, 'HS256'));
    }

    public function test_wrong_hmac_key_is_rejected(): void
    {
        $token = JWT::encode(['sub' => 'x'], $this->secret, 'HS256');

        $this->expectException(SignatureInvalidException::class);

        JWT::decode($token, new Key('a-totally-different-secret-key-also-long-enough-32', 'HS256'));
    }

    // ---------------------------------------------------------------------
    //  Time-based claims
    // ---------------------------------------------------------------------

    public function test_expired_token_throws(): void
    {
        JWT::$timestamp = 1_000_000_000;
        $token = JWT::encode(['exp' => 1_000_000_000], $this->secret, 'HS256');

        JWT::$timestamp = 1_000_000_001;

        $this->expectException(ExpiredException::class);

        JWT::decode($token, new Key($this->secret, 'HS256'));
    }

    public function test_leeway_allows_slightly_expired_token(): void
    {
        JWT::$timestamp = 1_000_000_000;
        $token = JWT::encode(['exp' => 1_000_000_000], $this->secret, 'HS256');

        JWT::$leeway = 10;
        JWT::$timestamp = 1_000_000_005;

        $decoded = JWT::decode($token, new Key($this->secret, 'HS256'));

        self::assertSame(1_000_000_000, $decoded['exp']);
    }

    public function test_nbf_in_future_throws(): void
    {
        JWT::$timestamp = 1_000_000_000;
        $token = JWT::encode(['nbf' => 1_000_000_100], $this->secret, 'HS256');

        $this->expectException(BeforeValidException::class);

        JWT::decode($token, new Key($this->secret, 'HS256'));
    }

    public function test_iat_in_future_throws(): void
    {
        JWT::$timestamp = 1_000_000_000;
        $token = JWT::encode(['iat' => 1_000_000_100], $this->secret, 'HS256');

        $this->expectException(BeforeValidException::class);

        JWT::decode($token, new Key($this->secret, 'HS256'));
    }

    // ---------------------------------------------------------------------
    //  Keys & kid
    // ---------------------------------------------------------------------

    public function test_multiple_keys_with_kid(): void
    {
        $payload = ['sub' => 'kid-user'];

        $old = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'bits' => 2048,
            'config' => $this->cnf,
        ]);
        openssl_pkey_export($old, $oldPriv, null, ['config' => $this->cnf]);
        $oldPub = (string) openssl_pkey_get_details($old)['key'];

        $token = JWT::encode($payload, $oldPriv, 'RS256', 'key-2024');

        $keys = [
            'key-2024' => new Key($oldPub, 'RS256'),
            'key-2025' => new Key($this->rsaPublic, 'RS256'),
        ];

        self::assertSame($payload, JWT::decode($token, $keys));
    }

    public function test_missing_kid_with_key_set_throws(): void
    {
        $token = JWT::encode(['sub' => 'x'], $this->rsaPrivate, 'RS256');

        $this->expectException(InvalidTokenException::class);

        JWT::decode($token, ['key-2025' => new Key($this->rsaPublic, 'RS256')]);
    }

    public function test_unknown_kid_throws(): void
    {
        $token = JWT::encode(['sub' => 'x'], $this->rsaPrivate, 'RS256', 'key-2024');

        $this->expectException(InvalidTokenException::class);

        JWT::decode($token, ['other' => new Key($this->rsaPublic, 'RS256')]);
    }

    // ---------------------------------------------------------------------
    //  Malformed tokens
    // ---------------------------------------------------------------------

    public function test_not_three_segments_throws(): void
    {
        $this->expectException(InvalidTokenException::class);

        JWT::decode('only.two', new Key($this->secret, 'HS256'));
    }

    public function test_invalid_base64_throws(): void
    {
        $this->expectException(InvalidTokenException::class);

        JWT::decode('!!!.!!!.!!!', new Key($this->secret, 'HS256'));
    }

    public function test_missing_alg_header_throws(): void
    {
        $header = JWT::urlsafeB64Encode((string) json_encode(['typ' => 'JWT']));
        $payload = JWT::urlsafeB64Encode((string) json_encode(['sub' => 'x']));
        $sig = JWT::urlsafeB64Encode(hash_hmac('sha256', $header.'.'.$payload, $this->secret, true));

        $this->expectException(InvalidTokenException::class);

        JWT::decode($header.'.'.$payload.'.'.$sig, new Key($this->secret, 'HS256'));
    }

    // ---------------------------------------------------------------------
    //  Helpers & edge cases
    // ---------------------------------------------------------------------

    public function test_urlsafe_b64_round_trip(): void
    {
        $data = random_bytes(64);

        self::assertSame($data, JWT::urlsafeB64Decode(JWT::urlsafeB64Encode($data)));
        self::assertStringNotContainsString('=', JWT::urlsafeB64Encode($data));
        self::assertStringNotContainsString('+', JWT::urlsafeB64Encode($data));
        self::assertStringNotContainsString('/', JWT::urlsafeB64Encode($data));
    }

    public function test_unicode_payload_round_trip(): void
    {
        $payload = ['name' => 'سعید', 'emoji' => '🔐', 'nested' => ['x' => 'τεστ']];

        $token = JWT::encode($payload, $this->secret, 'HS256');
        $decoded = JWT::decode($token, new Key($this->secret, 'HS256'));

        self::assertSame($payload, $decoded);
    }

    public function test_encode_with_key_id_header(): void
    {
        $token = JWT::encode(['sub' => 'x'], $this->secret, 'HS256', 'my-kid');

        [$h] = explode('.', $token);
        $header = json_decode(JWT::urlsafeB64Decode($h), true);

        self::assertSame('my-kid', $header['kid']);
    }

    public function test_key_rejects_empty_material(): void
    {
        $this->expectException(JWTException::class);

        new Key('', 'HS256');
    }

    public function test_key_rejects_unsupported_algorithm(): void
    {
        $this->expectException(JWTException::class);

        new Key($this->secret, 'MD5');
    }

    /**
     * Builds an EC P-256 SubjectPublicKeyInfo PEM from raw x/y coordinates
     * (base64url), without any external dependencies.
     */
    private static function buildP256PublicKey(string $x, string $y): string
    {
        $point = "\x04".JWT::urlsafeB64Decode($x).JWT::urlsafeB64Decode($y);

        // BIT STRING wrapping the uncompressed point (unused-bits byte 0x00).
        $bitString = "\x03".chr(strlen($point) + 1)."\x00".$point;

        // AlgorithmIdentifier: EC public key (1.2.840.10045.2.1) + prime256v1.
        $ecPublicKey = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $prime256v1 = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
        $algId = "\x30".chr(strlen($ecPublicKey) + strlen($prime256v1)).$ecPublicKey.$prime256v1;

        $spki = "\x30".chr(strlen($algId) + strlen($bitString)).$algId.$bitString;

        $pem = "-----BEGIN PUBLIC KEY-----\n"
            .chunk_split(base64_encode($spki), 64, "\n")
            ."-----END PUBLIC KEY-----\n";

        $key = openssl_pkey_get_public($pem);
        self::assertNotFalse($key, 'Failed to load constructed P-256 public key.');

        return $pem;
    }
}
