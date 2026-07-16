<?php

declare(strict_types=1);

namespace SwanFlutter\NativeJwt;

use SwanFlutter\NativeJwt\Exceptions\InvalidTokenException;
use SwanFlutter\NativeJwt\Exceptions\JWTException;

/**
 * JSON Web Key (JWK) parser.
 *
 * Converts a JWKS (JSON Web Key Set) document into an associative array of
 * kid => Key objects that can be passed directly to JWT::decode().
 *
 * Supported key types:
 *  - RSA (kty=RSA) — RS256, RS384, RS512, PS256, PS384, PS512
 *  - EC  (kty=EC)  — ES256 (P-256), ES384 (P-384), ES512 (P-521)
 *  - OKP (kty=OKP) — EdDSA (Ed25519)
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7517
 * @see https://datatracker.ietf.org/doc/html/rfc7518
 */
final class JWK
{
    /**
     * EC curve name → JWT algorithm.
     *
     * @var array<string, string>
     */
    private const EC_CURVE_TO_ALG = [
        'P-256' => 'ES256',
        'P-384' => 'ES384',
        'P-521' => 'ES512',
    ];

    /**
     * EC curve name → OpenSSL curve name.
     *
     * @var array<string, string>
     */
    private const EC_CURVE_TO_OPENSSL = [
        'P-256' => 'prime256v1',
        'P-384' => 'secp384r1',
        'P-521' => 'secp521r1',
    ];

    /**
     * EC curve name → expected coordinate byte length.
     * P-521 coordinates are 66 bytes (ceil(521/8)).
     * OpenSSL sometimes returns 65-byte coordinates (leading zero stripped),
     * so we must zero-pad to this length before building the DER point.
     *
     * @var array<string, int>
     */
    private const EC_COORD_BYTES = [
        'P-256' => 32,
        'P-384' => 48,
        'P-521' => 66,
    ];

    /**
     * RSA "alg" header value → JWT algorithm name.
     * If the JWK carries an explicit "alg" field we honour it; otherwise we
     * infer from the key use ("use": "sig") and default to RS256.
     *
     * @var array<string, string>
     */
    private const RSA_ALG_MAP = [
        'RS256' => 'RS256', 'RS384' => 'RS384', 'RS512' => 'RS512',
        'PS256' => 'PS256', 'PS384' => 'PS384', 'PS512' => 'PS512',
    ];

    // -------------------------------------------------------------------------
    //  Public API
    // -------------------------------------------------------------------------

    /**
     * Parse a JWKS document and return an array of kid => Key objects.
     *
     * @param  array<string, mixed>  $jwks  decoded JSON of the JWKS endpoint
     * @param  array<string, string>  $defaultAlgorithms  fallback alg per kty if the JWK has no "alg" field.
     *                                                     e.g. ['RSA' => 'RS256', 'EC' => 'ES256', 'OKP' => 'EdDSA']
     * @return array<string, Key>  kid => Key
     *
     * @throws JWTException|InvalidTokenException
     */
    public static function parseKeySet(
        array $jwks,
        array $defaultAlgorithms = []
    ): array {
        if (empty($jwks['keys']) || ! is_array($jwks['keys'])) {
            throw new InvalidTokenException('Invalid JWKS: missing or empty "keys" array.');
        }

        $keys = [];

        foreach ($jwks['keys'] as $index => $jwkRaw) {
            if (! is_array($jwkRaw)) {
                throw new InvalidTokenException("JWK at index {$index} is not an object.");
            }

            // Skip keys not intended for signing.
            if (isset($jwkRaw['use']) && $jwkRaw['use'] !== 'sig') {
                continue;
            }

            // Skip keys that explicitly list key operations excluding signing.
            if (isset($jwkRaw['key_ops']) && is_array($jwkRaw['key_ops'])) {
                if (! in_array('verify', $jwkRaw['key_ops'], true)) {
                    continue;
                }
            }

            $kid = isset($jwkRaw['kid']) && is_string($jwkRaw['kid'])
                ? $jwkRaw['kid']
                : (string) $index;

            try {
                $key = self::parseKey($jwkRaw, $defaultAlgorithms);
            } catch (JWTException $e) {
                // Skip unsupported / malformed individual keys but continue parsing the set.
                // Re-throw if you want strict mode.
                continue;
            }

            $keys[$kid] = $key;
        }

        if (empty($keys)) {
            throw new JWTException('JWKS contains no usable signing keys.');
        }

        return $keys;
    }

    /**
     * Parse a single JWK and return a Key.
     *
     * @param  array<string, mixed>  $jwk
     * @param  array<string, string>  $defaultAlgorithms
     */
    public static function parseKey(array $jwk, array $defaultAlgorithms = []): Key
    {
        if (empty($jwk['kty']) || ! is_string($jwk['kty'])) {
            throw new JWTException('JWK is missing the required "kty" field.');
        }

        return match (strtoupper($jwk['kty'])) {
            'RSA' => self::parseRsaKey($jwk, $defaultAlgorithms),
            'EC'  => self::parseEcKey($jwk, $defaultAlgorithms),
            'OKP' => self::parseOkpKey($jwk, $defaultAlgorithms),
            default => throw new JWTException("Unsupported key type: {$jwk['kty']}"),
        };
    }

    // -------------------------------------------------------------------------
    //  RSA
    // -------------------------------------------------------------------------

    /**
     * @param  array<string, mixed>  $jwk
     * @param  array<string, string>  $defaults
     */
    private static function parseRsaKey(array $jwk, array $defaults): Key
    {
        foreach (['n', 'e'] as $field) {
            if (empty($jwk[$field]) || ! is_string($jwk[$field])) {
                throw new JWTException("RSA JWK is missing required field \"{$field}\".");
            }
        }

        $n = self::base64UrlToBignum($jwk['n']);
        $e = self::base64UrlToBignum($jwk['e']);

        $keyData = ['n' => $n, 'e' => $e];

        // Include private key components if present (for signing).
        foreach (['d', 'p', 'q', 'dp', 'dq', 'qi'] as $field) {
            if (isset($jwk[$field]) && is_string($jwk[$field])) {
                $keyData[$field] = self::base64UrlToBignum($jwk[$field]);
            }
        }

        $pem = self::rsaKeyDataToPem($keyData);

        // Determine algorithm.
        $alg = self::resolveAlgorithm($jwk, 'RSA', $defaults, 'RS256');

        if (! isset(self::RSA_ALG_MAP[$alg])) {
            throw new JWTException("Unsupported RSA JWK algorithm: {$alg}");
        }

        return new Key($pem, $alg);
    }

    /**
     * @param  array<string, mixed>  $keyData  keys: n, e and optionally d, p, q, dp, dq, qi
     *                                          values: GMP resources from gmp_import()
     */
    private static function rsaKeyDataToPem(array $keyData): string
    {
        if (! function_exists('gmp_export')) {
            throw new JWTException(
                'RSA JWK parsing requires the GMP extension (php-gmp). '.
                'Install php-gmp or php8.x-gmp.'
            );
        }

        $isPrivate = isset($keyData['d']);

        if ($isPrivate) {
            // Reconstruct the remaining CRT parameters when missing.
            if (! isset($keyData['p']) || ! isset($keyData['q'])) {
                throw new JWTException(
                    'RSA private JWK must contain "p" and "q" parameters.'
                );
            }

            $components = [
                'version'          => 0,
                'modulus'          => $keyData['n'],
                'publicExponent'   => $keyData['e'],
                'privateExponent'  => $keyData['d'],
                'prime1'           => $keyData['p'],
                'prime2'           => $keyData['q'],
                'exponent1'        => $keyData['dp'],
                'exponent2'        => $keyData['dq'],
                'coefficient'      => $keyData['qi'],
            ];

            return self::buildRsaPrivatePem($components);
        }

        return self::buildRsaPublicPem($keyData['n'], $keyData['e']);
    }

    /**
     * Build a PKCS#1 RSA public key PEM from GMP n and e.
     *
     * @param  \GMP  $n
     * @param  \GMP  $e
     */
    private static function buildRsaPublicPem($n, $e): string
    {
        $nBytes = self::gmpToUnsignedBytes($n);
        $eBytes = self::gmpToUnsignedBytes($e);

        // INTEGER n
        $nDer = "\x02".self::derLen(strlen($nBytes)).$nBytes;
        // INTEGER e
        $eDer = "\x02".self::derLen(strlen($eBytes)).$eBytes;

        // SEQUENCE { n, e }
        $seq = "\x30".self::derLen(strlen($nDer.$eDer)).$nDer.$eDer;

        // BIT STRING wrapping SEQUENCE (prepend 0x00 unused-bits byte).
        $bitString = "\x03".self::derLen(strlen($seq) + 1)."\x00".$seq;

        // AlgorithmIdentifier for rsaEncryption (1.2.840.113549.1.1.1) with NULL params.
        $algId = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";

        // SubjectPublicKeyInfo SEQUENCE
        $spki = "\x30".self::derLen(strlen($algId.$bitString)).$algId.$bitString;

        return "-----BEGIN PUBLIC KEY-----\n"
            .chunk_split(base64_encode($spki), 64, "\n")
            ."-----END PUBLIC KEY-----\n";
    }

    /**
     * Build a PKCS#1 RSA private key PEM from GMP components.
     *
     * @param  array<string, int|\GMP>  $c
     */
    private static function buildRsaPrivatePem(array $c): string
    {
        $fields = ['version', 'modulus', 'publicExponent', 'privateExponent',
                   'prime1', 'prime2', 'exponent1', 'exponent2', 'coefficient'];

        $body = '';

        foreach ($fields as $field) {
            $val = $c[$field];
            $bytes = is_int($val)
                ? ($val === 0 ? "\x00" : self::gmpToUnsignedBytes(gmp_init($val)))
                : self::gmpToUnsignedBytes($val);

            $body .= "\x02".self::derLen(strlen($bytes)).$bytes;
        }

        $seq = "\x30".self::derLen(strlen($body)).$body;

        return "-----BEGIN RSA PRIVATE KEY-----\n"
            .chunk_split(base64_encode($seq), 64, "\n")
            ."-----END RSA PRIVATE KEY-----\n";
    }

    // -------------------------------------------------------------------------
    //  EC
    // -------------------------------------------------------------------------

    /**
     * @param  array<string, mixed>  $jwk
     * @param  array<string, string>  $defaults
     */
    private static function parseEcKey(array $jwk, array $defaults): Key
    {
        foreach (['crv', 'x', 'y'] as $field) {
            if (empty($jwk[$field]) || ! is_string($jwk[$field])) {
                throw new JWTException("EC JWK is missing required field \"{$field}\".");
            }
        }

        $crv = $jwk['crv'];

        if (! isset(self::EC_CURVE_TO_ALG[$crv])) {
            throw new JWTException("Unsupported EC curve: {$crv}");
        }

        $alg = self::resolveAlgorithm($jwk, 'EC', $defaults, self::EC_CURVE_TO_ALG[$crv]);

        $coordLen = self::EC_COORD_BYTES[$crv];
        $xBytes   = str_pad(JWT::urlsafeB64Decode($jwk['x']), $coordLen, "\x00", STR_PAD_LEFT);
        $yBytes   = str_pad(JWT::urlsafeB64Decode($jwk['y']), $coordLen, "\x00", STR_PAD_LEFT);

        // Uncompressed EC point: 0x04 || x || y
        $point = "\x04".$xBytes.$yBytes;

        $opensslCurve = self::EC_CURVE_TO_OPENSSL[$crv];

        if (isset($jwk['d']) && is_string($jwk['d'])) {
            // Private key path.
            $dBytes = str_pad(JWT::urlsafeB64Decode($jwk['d']), $coordLen, "\x00", STR_PAD_LEFT);
            $pem    = self::buildEcPrivatePem($opensslCurve, $dBytes, $point);
        } else {
            $pem = self::buildEcPublicPem($opensslCurve, $point);
        }

        return new Key($pem, $alg);
    }

    /**
     * Build an EC SubjectPublicKeyInfo PEM.
     */
    private static function buildEcPublicPem(string $curve, string $point): string
    {
        $curveOid = self::ecCurveOid($curve);

        // BIT STRING wrapping point (0x00 unused bits).
        $bitString = "\x03".self::derLen(strlen($point) + 1)."\x00".$point;

        // AlgorithmIdentifier: EC public key OID + curve OID.
        $ecOid  = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $algId  = "\x30".self::derLen(strlen($ecOid.$curveOid)).$ecOid.$curveOid;

        $spki = "\x30".self::derLen(strlen($algId.$bitString)).$algId.$bitString;

        return "-----BEGIN PUBLIC KEY-----\n"
            .chunk_split(base64_encode($spki), 64, "\n")
            ."-----END PUBLIC KEY-----\n";
    }

    /**
     * Build an EC private key PEM (SEC1 format wrapped in PKCS#8).
     */
    private static function buildEcPrivatePem(string $curve, string $d, string $point): string
    {
        $curveOid = self::ecCurveOid($curve);

        // ECPrivateKey ::= SEQUENCE { version INTEGER (1), privateKey OCTET STRING,
        //                             [0] ECParameters OPTIONAL, [1] publicKey OPTIONAL }
        $privateKeyOctet = "\x04".self::derLen(strlen($d)).$d;
        $contextTag0 = "\xa0".self::derLen(strlen($curveOid)).$curveOid;
        $publicKeyBit = "\x03".self::derLen(strlen($point) + 1)."\x00".$point;
        $contextTag1 = "\xa1".self::derLen(strlen($publicKeyBit)).$publicKeyBit;

        $ecPrivKey = "\x02\x01\x01".$privateKeyOctet.$contextTag0.$contextTag1;
        $ecPrivSeq = "\x30".self::derLen(strlen($ecPrivKey)).$ecPrivKey;

        return "-----BEGIN EC PRIVATE KEY-----\n"
            .chunk_split(base64_encode($ecPrivSeq), 64, "\n")
            ."-----END EC PRIVATE KEY-----\n";
    }

    /**
     * Return the DER-encoded OID for the given OpenSSL curve name.
     */
    private static function ecCurveOid(string $curve): string
    {
        return match ($curve) {
            'prime256v1' => "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
            'secp384r1'  => "\x06\x05\x2b\x81\x04\x00\x22",
            'secp521r1'  => "\x06\x05\x2b\x81\x04\x00\x23",
            default      => throw new JWTException("Unknown EC curve for OID mapping: {$curve}"),
        };
    }

    // -------------------------------------------------------------------------
    //  OKP / EdDSA
    // -------------------------------------------------------------------------

    /**
     * @param  array<string, mixed>  $jwk
     * @param  array<string, string>  $defaults
     */
    private static function parseOkpKey(array $jwk, array $defaults): Key
    {
        if (empty($jwk['crv']) || $jwk['crv'] !== 'Ed25519') {
            throw new JWTException(
                'Only Ed25519 OKP keys are supported (crv=Ed25519). Got: '.($jwk['crv'] ?? 'none')
            );
        }

        if (empty($jwk['x']) || ! is_string($jwk['x'])) {
            throw new JWTException('OKP JWK is missing the required "x" (public key) field.');
        }

        $alg = self::resolveAlgorithm($jwk, 'OKP', $defaults, 'EdDSA');

        if ($alg !== 'EdDSA') {
            throw new JWTException("OKP keys only support EdDSA algorithm, got: {$alg}");
        }

        // For public key: store as base64url-encoded x coordinate (32 bytes).
        // JWT::verify() accepts base64url-encoded Ed25519 public keys.
        if (isset($jwk['d']) && is_string($jwk['d'])) {
            // Private key: store seed (d) + public key (x) concatenated as base64url.
            $dRaw = JWT::urlsafeB64Decode($jwk['d']);
            $xRaw = JWT::urlsafeB64Decode($jwk['x']);
            // libsodium expects seed (32 bytes) for keypair derivation.
            $keyMaterial = JWT::urlsafeB64Encode($dRaw.$xRaw);
        } else {
            $keyMaterial = $jwk['x'];
        }

        return new Key($keyMaterial, 'EdDSA');
    }

    // -------------------------------------------------------------------------
    //  Algorithm resolution
    // -------------------------------------------------------------------------

    /**
     * Determine the JWT algorithm from a JWK, given precedence:
     *  1. Explicit "alg" field in the JWK.
     *  2. Caller-supplied defaults keyed by kty.
     *  3. Library fallback.
     *
     * @param  array<string, mixed>  $jwk
     * @param  array<string, string>  $defaults
     */
    private static function resolveAlgorithm(
        array $jwk,
        string $kty,
        array $defaults,
        string $fallback
    ): string {
        if (! empty($jwk['alg']) && is_string($jwk['alg'])) {
            return $jwk['alg'];
        }

        return $defaults[$kty] ?? $fallback;
    }

    // -------------------------------------------------------------------------
    //  DER / GMP helpers
    // -------------------------------------------------------------------------

    /**
     * Decode a base64url-encoded big-endian integer into a GMP resource.
     *
     * @return \GMP
     */
    private static function base64UrlToBignum(string $b64url)
    {
        if (! function_exists('gmp_import')) {
            throw new JWTException(
                'RSA JWK parsing requires the GMP extension.'
            );
        }

        $raw = JWT::urlsafeB64Decode($b64url);

        return gmp_import($raw, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    }

    /**
     * Export a GMP number to an unsigned big-endian byte string,
     * prepending 0x00 if the MSB is set (to keep it positive in DER).
     *
     * @param  \GMP  $gmp
     */
    private static function gmpToUnsignedBytes($gmp): string
    {
        $bytes = gmp_export($gmp, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);

        // Prepend null byte to avoid sign ambiguity in DER INTEGER.
        if (strlen($bytes) > 0 && (ord($bytes[0]) & 0x80)) {
            $bytes = "\x00".$bytes;
        }

        return $bytes;
    }

    /**
     * Encode a DER length.
     */
    private static function derLen(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = '';

        while ($length > 0) {
            $bytes = chr($length & 0xFF).$bytes;
            $length >>= 8;
        }

        return chr(0x80 | strlen($bytes)).$bytes;
    }
}
