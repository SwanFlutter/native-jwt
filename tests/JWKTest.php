<?php

declare(strict_types=1);

namespace SwanFlutter\NativeJwt\Tests;

use PHPUnit\Framework\TestCase;
use SwanFlutter\NativeJwt\Exceptions\InvalidTokenException;
use SwanFlutter\NativeJwt\Exceptions\JWTException;
use SwanFlutter\NativeJwt\JWK;
use SwanFlutter\NativeJwt\JWT;
use SwanFlutter\NativeJwt\Key;

/**
 * Tests for the JWK class.
 *
 * - RSA tests require ext-gmp and are individually guarded.
 * - EC tests use only ext-openssl (always available).
 * - OKP/EdDSA tests require ext-sodium and are individually guarded.
 * - Error-case / structural tests need no optional extensions.
 */
final class JWKTest extends TestCase
{
    private string $cnf;

    protected function setUp(): void
    {
        parent::setUp();
        JWT::$leeway    = 0;
        JWT::$timestamp = null;
        $this->cnf = __DIR__.'/fixtures/openssl.cnf';
    }

    // =========================================================================
    //  RSA JWK  (require ext-gmp)
    // =========================================================================

    public function test_rsa_public_jwk_parse_and_verify(): void
    {
        if (! function_exists('gmp_import')) {
            self::markTestSkipped('ext-gmp is required for RSA JWK tests.');
        }

        $rsa = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'bits'             => 2048,
            'config'           => $this->cnf,
        ]);
        openssl_pkey_export($rsa, $privPem, null, ['config' => $this->cnf]);
        $det = openssl_pkey_get_details($rsa);

        $jwks = ['keys' => [[
            'kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256',
            'kid' => 'rsa-test',
            'n'   => JWT::urlsafeB64Encode($det['rsa']['n']),
            'e'   => JWT::urlsafeB64Encode($det['rsa']['e']),
        ]]];

        $keySet = JWK::parseKeySet($jwks);

        self::assertArrayHasKey('rsa-test', $keySet);
        self::assertInstanceOf(Key::class, $keySet['rsa-test']);
        self::assertSame('RS256', $keySet['rsa-test']->getAlgorithm());

        $payload = ['sub' => 'jwk-rsa', 'exp' => time() + 3600];
        $token   = JWT::encode($payload, $privPem, 'RS256', 'rsa-test');
        $decoded = JWT::decode($token, $keySet);

        self::assertSame($payload, $decoded);
    }

    public function test_rsa_jwk_without_kid_falls_back_to_index(): void
    {
        if (! function_exists('gmp_import')) {
            self::markTestSkipped('ext-gmp is required for RSA JWK tests.');
        }

        $rsa = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'bits' => 2048, 'config' => $this->cnf]);
        $det = openssl_pkey_get_details($rsa);

        $keySet = JWK::parseKeySet(['keys' => [[
            'kty' => 'RSA', 'alg' => 'RS256',
            'n'   => JWT::urlsafeB64Encode($det['rsa']['n']),
            'e'   => JWT::urlsafeB64Encode($det['rsa']['e']),
        ]]]);

        self::assertArrayHasKey('0', $keySet);
    }

    public function test_rsa_jwk_no_alg_defaults_to_rs256(): void
    {
        if (! function_exists('gmp_import')) {
            self::markTestSkipped('ext-gmp is required for RSA JWK tests.');
        }

        $rsa = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'bits' => 2048, 'config' => $this->cnf]);
        $det = openssl_pkey_get_details($rsa);

        $key = JWK::parseKey([
            'kty' => 'RSA',
            'n'   => JWT::urlsafeB64Encode($det['rsa']['n']),
            'e'   => JWT::urlsafeB64Encode($det['rsa']['e']),
        ]);

        self::assertSame('RS256', $key->getAlgorithm());
    }

    public function test_rsa_jwk_ps256_algorithm(): void
    {
        if (! function_exists('gmp_import')) {
            self::markTestSkipped('ext-gmp is required for RSA JWK tests.');
        }

        $rsa = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'bits' => 2048, 'config' => $this->cnf]);
        openssl_pkey_export($rsa, $privPem, null, ['config' => $this->cnf]);
        $det = openssl_pkey_get_details($rsa);

        $keySet = JWK::parseKeySet(['keys' => [[
            'kty' => 'RSA', 'use' => 'sig', 'alg' => 'PS256',
            'kid' => 'ps256-key',
            'n'   => JWT::urlsafeB64Encode($det['rsa']['n']),
            'e'   => JWT::urlsafeB64Encode($det['rsa']['e']),
        ]]]);

        self::assertSame('PS256', $keySet['ps256-key']->getAlgorithm());

        $payload = ['sub' => 'ps256-user', 'exp' => time() + 3600];
        $token   = JWT::encode($payload, $privPem, 'PS256', 'ps256-key');
        $decoded = JWT::decode($token, $keySet);

        self::assertSame($payload, $decoded);
    }

    /**
     * Simulates Google/Firebase JWKS response for FCM token verification.
     */
    public function test_google_style_jwks_fcm_fixture(): void
    {
        if (! function_exists('gmp_import')) {
            self::markTestSkipped('ext-gmp is required for RSA JWK tests.');
        }

        $rsa = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'bits' => 2048, 'config' => $this->cnf]);
        openssl_pkey_export($rsa, $privPem, null, ['config' => $this->cnf]);
        $det = openssl_pkey_get_details($rsa);

        $jwks = ['keys' => [[
            'kty' => 'RSA', 'alg' => 'RS256', 'use' => 'sig',
            'kid' => 'fcm-001',
            'n'   => JWT::urlsafeB64Encode($det['rsa']['n']),
            'e'   => JWT::urlsafeB64Encode($det['rsa']['e']),
        ]]];

        $keySet = JWK::parseKeySet($jwks);

        $now = time();
        JWT::$timestamp = $now;

        $payload = [
            'iss' => 'https://accounts.google.com',
            'sub' => 'sa@project.iam.gserviceaccount.com',
            'aud' => 'https://fcm.googleapis.com/',
            'iat' => $now,
            'exp' => $now + 3600,
        ];

        $token   = JWT::encode($payload, $privPem, 'RS256', 'fcm-001');
        $decoded = JWT::decode($token, $keySet);

        self::assertSame($payload['iss'], $decoded['iss']);
        self::assertSame($payload['sub'], $decoded['sub']);
        self::assertSame($payload['aud'], $decoded['aud']);

        JWT::$timestamp = null;
    }

    public function test_rsa_unsupported_kty_is_skipped_valid_rsa_survives(): void
    {
        if (! function_exists('gmp_import')) {
            self::markTestSkipped('ext-gmp is required for RSA JWK tests.');
        }

        $rsa = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'bits' => 2048, 'config' => $this->cnf]);
        $det = openssl_pkey_get_details($rsa);

        $jwks = ['keys' => [
            ['kty' => 'oct', 'k' => 'c2VjcmV0', 'kid' => 'hmac-key'],
            [
                'kty' => 'RSA', 'alg' => 'RS256', 'kid' => 'rsa-ok',
                'n'   => JWT::urlsafeB64Encode($det['rsa']['n']),
                'e'   => JWT::urlsafeB64Encode($det['rsa']['e']),
            ],
        ]];

        $keySet = JWK::parseKeySet($jwks);

        self::assertArrayNotHasKey('hmac-key', $keySet);
        self::assertArrayHasKey('rsa-ok', $keySet);
    }

    // =========================================================================
    //  EC JWK  (only ext-openssl — always available)
    // =========================================================================

    public function test_ec_p256_jwk_parse_and_verify(): void
    {
        $ec = openssl_pkey_new([
            'curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC,
            'config'     => $this->cnf,
        ]);
        openssl_pkey_export($ec, $privPem, null, ['config' => $this->cnf]);
        $det = openssl_pkey_get_details($ec);

        $jwks = ['keys' => [[
            'kty' => 'EC', 'use' => 'sig', 'crv' => 'P-256', 'kid' => 'ec-p256',
            'x'   => JWT::urlsafeB64Encode($det['ec']['x']),
            'y'   => JWT::urlsafeB64Encode($det['ec']['y']),
        ]]];

        $keySet = JWK::parseKeySet($jwks);

        self::assertArrayHasKey('ec-p256', $keySet);
        self::assertSame('ES256', $keySet['ec-p256']->getAlgorithm());

        $payload = ['sub' => 'ec-user', 'exp' => time() + 3600];
        $token   = JWT::encode($payload, $privPem, 'ES256', 'ec-p256');
        $decoded = JWT::decode($token, $keySet);

        self::assertSame($payload, $decoded);
    }

    public function test_ec_p384_jwk_parse_algorithm(): void
    {
        $ec = openssl_pkey_new([
            'curve_name' => 'secp384r1', 'private_key_type' => OPENSSL_KEYTYPE_EC,
            'config'     => $this->cnf,
        ]);
        $det = openssl_pkey_get_details($ec);

        $key = JWK::parseKey([
            'kty' => 'EC', 'crv' => 'P-384',
            'x'   => JWT::urlsafeB64Encode($det['ec']['x']),
            'y'   => JWT::urlsafeB64Encode($det['ec']['y']),
        ]);

        self::assertSame('ES384', $key->getAlgorithm());
    }

    public function test_ec_p384_jwk_round_trip(): void
    {
        $ec = openssl_pkey_new([
            'curve_name' => 'secp384r1', 'private_key_type' => OPENSSL_KEYTYPE_EC,
            'config'     => $this->cnf,
        ]);
        openssl_pkey_export($ec, $privPem, null, ['config' => $this->cnf]);
        $det = openssl_pkey_get_details($ec);

        $jwks = ['keys' => [[
            'kty' => 'EC', 'crv' => 'P-384', 'kid' => 'ec-p384',
            'x'   => JWT::urlsafeB64Encode($det['ec']['x']),
            'y'   => JWT::urlsafeB64Encode($det['ec']['y']),
        ]]];

        $keySet = JWK::parseKeySet($jwks);

        $payload = ['sub' => 'p384-user', 'exp' => time() + 3600];
        $token   = JWT::encode($payload, $privPem, 'ES384', 'ec-p384');

        self::assertSame($payload, JWT::decode($token, $keySet));
    }

    public function test_ec_p521_jwk_parse_algorithm(): void
    {
        $ec = openssl_pkey_new([
            'curve_name' => 'secp521r1', 'private_key_type' => OPENSSL_KEYTYPE_EC,
            'config'     => $this->cnf,
        ]);
        $det = openssl_pkey_get_details($ec);

        $key = JWK::parseKey([
            'kty' => 'EC', 'crv' => 'P-521',
            'x'   => JWT::urlsafeB64Encode($det['ec']['x']),
            'y'   => JWT::urlsafeB64Encode($det['ec']['y']),
        ]);

        self::assertSame('ES512', $key->getAlgorithm());
    }

    public function test_ec_p521_jwk_round_trip(): void
    {
        $ec = openssl_pkey_new([
            'curve_name' => 'secp521r1', 'private_key_type' => OPENSSL_KEYTYPE_EC,
            'config'     => $this->cnf,
        ]);
        openssl_pkey_export($ec, $privPem, null, ['config' => $this->cnf]);
        $det = openssl_pkey_get_details($ec);

        $jwks = ['keys' => [[
            'kty' => 'EC', 'crv' => 'P-521', 'kid' => 'ec-p521',
            'x'   => JWT::urlsafeB64Encode($det['ec']['x']),
            'y'   => JWT::urlsafeB64Encode($det['ec']['y']),
        ]]];

        $keySet = JWK::parseKeySet($jwks);

        $payload = ['sub' => 'p521-user', 'exp' => time() + 3600];
        $token   = JWT::encode($payload, $privPem, 'ES512', 'ec-p521');

        self::assertSame($payload, JWT::decode($token, $keySet));
    }

    public function test_ec_with_no_kid_falls_back_to_index(): void
    {
        $ec = openssl_pkey_new([
            'curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC,
            'config'     => $this->cnf,
        ]);
        $det = openssl_pkey_get_details($ec);

        $keySet = JWK::parseKeySet(['keys' => [[
            'kty' => 'EC', 'crv' => 'P-256',
            'x'   => JWT::urlsafeB64Encode($det['ec']['x']),
            'y'   => JWT::urlsafeB64Encode($det['ec']['y']),
        ]]]);

        self::assertArrayHasKey('0', $keySet);
        self::assertSame('ES256', $keySet['0']->getAlgorithm());
    }

    public function test_ec_unsupported_curve_throws(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessageMatches('/Unsupported EC curve/');

        JWK::parseKey([
            'kty' => 'EC', 'crv' => 'P-192',
            'x'   => JWT::urlsafeB64Encode(random_bytes(24)),
            'y'   => JWT::urlsafeB64Encode(random_bytes(24)),
        ]);
    }

    public function test_ec_non_sig_use_is_filtered_out(): void
    {
        // A JWKS with only an enc EC key should yield no usable keys.
        $ec = openssl_pkey_new([
            'curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC,
            'config'     => $this->cnf,
        ]);
        $det = openssl_pkey_get_details($ec);

        $this->expectException(JWTException::class);

        JWK::parseKeySet(['keys' => [[
            'kty' => 'EC', 'crv' => 'P-256', 'use' => 'enc',
            'x'   => JWT::urlsafeB64Encode($det['ec']['x']),
            'y'   => JWT::urlsafeB64Encode($det['ec']['y']),
        ]]]);
    }

    public function test_ec_tampered_signature_rejected(): void
    {
        $ec = openssl_pkey_new([
            'curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC,
            'config'     => $this->cnf,
        ]);
        openssl_pkey_export($ec, $privPem, null, ['config' => $this->cnf]);
        $det = openssl_pkey_get_details($ec);

        $keySet = JWK::parseKeySet(['keys' => [[
            'kty' => 'EC', 'crv' => 'P-256', 'kid' => 'ec-tamper',
            'x'   => JWT::urlsafeB64Encode($det['ec']['x']),
            'y'   => JWT::urlsafeB64Encode($det['ec']['y']),
        ]]]);

        $token = JWT::encode(['sub' => 'x'], $privPem, 'ES256', 'ec-tamper');
        $token = substr($token, 0, -3).'AAA';

        $this->expectException(\SwanFlutter\NativeJwt\Exceptions\SignatureInvalidException::class);
        JWT::decode($token, $keySet);
    }

    // =========================================================================
    //  OKP / EdDSA JWK  (require ext-sodium)
    // =========================================================================

    public function test_okp_eddsa_jwk_parse_and_verify(): void
    {
        if (! function_exists('sodium_crypto_sign_keypair')) {
            self::markTestSkipped('ext-sodium is required for EdDSA JWK tests.');
        }

        $kp  = sodium_crypto_sign_keypair();
        $pub = sodium_crypto_sign_publickey($kp);
        $sec = sodium_crypto_sign_secretkey($kp);

        $jwks = ['keys' => [[
            'kty' => 'OKP', 'crv' => 'Ed25519', 'use' => 'sig',
            'kid' => 'ed25519-key',
            'x'   => JWT::urlsafeB64Encode($pub),
        ]]];

        $keySet = JWK::parseKeySet($jwks);

        self::assertArrayHasKey('ed25519-key', $keySet);
        self::assertSame('EdDSA', $keySet['ed25519-key']->getAlgorithm());

        $privMaterial = JWT::urlsafeB64Encode($sec);
        $payload      = ['sub' => 'eddsa-jwk', 'exp' => time() + 3600];
        $token        = JWT::encode($payload, $privMaterial, 'EdDSA', 'ed25519-key');

        self::assertSame($payload, JWT::decode($token, $keySet));
    }

    public function test_okp_unsupported_curve_throws(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessageMatches('/Ed25519/');

        JWK::parseKey([
            'kty' => 'OKP',
            'crv' => 'X25519',   // key-agreement, not signing
            'x'   => JWT::urlsafeB64Encode(random_bytes(32)),
        ]);
    }

    // =========================================================================
    //  Structural / error-case tests  (no optional extensions needed)
    // =========================================================================

    public function test_empty_keys_array_throws(): void
    {
        $this->expectException(InvalidTokenException::class);
        JWK::parseKeySet(['keys' => []]);
    }

    public function test_missing_keys_field_throws(): void
    {
        $this->expectException(InvalidTokenException::class);
        JWK::parseKeySet(['notkeys' => []]);
    }

    public function test_keys_field_not_array_throws(): void
    {
        $this->expectException(InvalidTokenException::class);
        JWK::parseKeySet(['keys' => 'string-not-array']);
    }

    public function test_missing_kty_in_single_key_throws(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessageMatches('/kty/');

        JWK::parseKey(['use' => 'sig', 'kid' => 'x']);
    }

    public function test_unsupported_kty_in_single_key_throws(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessageMatches('/Unsupported key type/');

        JWK::parseKey(['kty' => 'oct', 'k' => 'c2VjcmV0']);
    }

    public function test_rsa_missing_n_field_throws(): void
    {
        // parseKey should throw without needing GMP — it validates required fields first.
        $this->expectException(JWTException::class);
        $this->expectExceptionMessageMatches('/"n"/');

        JWK::parseKey(['kty' => 'RSA', 'e' => 'AQAB']);
    }

    public function test_rsa_missing_e_field_throws(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessageMatches('/"e"/');

        JWK::parseKey(['kty' => 'RSA', 'n' => 'dGVzdA']);
    }

    public function test_ec_missing_x_field_throws(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessageMatches('/"x"/');

        JWK::parseKey(['kty' => 'EC', 'crv' => 'P-256', 'y' => 'dGVzdA']);
    }

    public function test_ec_missing_crv_field_throws(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessageMatches('/"crv"/');

        JWK::parseKey(['kty' => 'EC', 'x' => 'dGVzdA', 'y' => 'dGVzdA']);
    }

    public function test_okp_missing_x_field_throws(): void
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessageMatches('/"x"/');

        JWK::parseKey(['kty' => 'OKP', 'crv' => 'Ed25519']);
    }

    public function test_all_keys_unsupported_throws(): void
    {
        // JWKS where every key is unsupported — should throw after processing all.
        $this->expectException(JWTException::class);
        $this->expectExceptionMessageMatches('/no usable/i');

        JWK::parseKeySet(['keys' => [
            ['kty' => 'oct', 'k' => 'c2VjcmV0', 'kid' => 'k1'],
            ['kty' => 'oct', 'k' => 'c2VjcmV0', 'kid' => 'k2'],
        ]]);
    }

    public function test_non_array_entry_in_keys_throws(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageMatches('/not an object/');

        JWK::parseKeySet(['keys' => ['not-an-object']]);
    }

    public function test_key_ops_without_verify_is_filtered(): void
    {
        // A key that has key_ops but does NOT include "verify" must be skipped.
        $ec = openssl_pkey_new([
            'curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC,
            'config'     => $this->cnf,
        ]);
        $det = openssl_pkey_get_details($ec);

        $this->expectException(JWTException::class);
        $this->expectExceptionMessageMatches('/no usable/i');

        JWK::parseKeySet(['keys' => [[
            'kty'      => 'EC', 'crv' => 'P-256', 'kid' => 'sign-only',
            'key_ops'  => ['sign'],   // no "verify"
            'x'        => JWT::urlsafeB64Encode($det['ec']['x']),
            'y'        => JWT::urlsafeB64Encode($det['ec']['y']),
        ]]]);
    }

    public function test_key_ops_with_verify_is_accepted(): void
    {
        $ec = openssl_pkey_new([
            'curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC,
            'config'     => $this->cnf,
        ]);
        $det = openssl_pkey_get_details($ec);

        $keySet = JWK::parseKeySet(['keys' => [[
            'kty'      => 'EC', 'crv' => 'P-256', 'kid' => 'verify-ok',
            'key_ops'  => ['verify', 'sign'],
            'x'        => JWT::urlsafeB64Encode($det['ec']['x']),
            'y'        => JWT::urlsafeB64Encode($det['ec']['y']),
        ]]]);

        self::assertArrayHasKey('verify-ok', $keySet);
    }
}
