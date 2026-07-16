<?php

declare(strict_types=1);

namespace SwanFlutter\NativeJwt;

use SwanFlutter\NativeJwt\Exceptions\BeforeValidException;
use SwanFlutter\NativeJwt\Exceptions\ExpiredException;
use SwanFlutter\NativeJwt\Exceptions\InvalidTokenException;
use SwanFlutter\NativeJwt\Exceptions\JWTException;
use SwanFlutter\NativeJwt\Exceptions\SignatureInvalidException;

/**
 * A standalone JWT implementation for PHP.
 *
 * Supports HMAC (HS256/384/512), RSA (RS256/384/512), ECDSA (ES256/384/512),
 * EdDSA (Ed25519 via libsodium) and RSASSA-PSS (PS256/384/512 via OpenSSL).
 *
 * Security guarantees:
 *  - The "alg: none" attack is explicitly rejected.
 *  - Algorithm confusion is prevented because every trusted Key is bound to
 *    a single algorithm and the token algorithm must match it exactly.
 *  - Signatures are compared in constant time (HMAC/EdDSA) and verified via OpenSSL.
 *  - Time-based claims (exp/nbf/iat) are validated with configurable leeway.
 */
final class JWT
{
    /**
     * Algorithm map.
     * type 'hmac'    => symmetric (hash_hmac)
     * type 'openssl' => asymmetric RSA PKCS#1v1.5 (openssl_sign / openssl_verify)
     * type 'ecdsa'   => asymmetric ECDSA (DER <-> R||S conversion applied)
     * type 'eddsa'   => asymmetric Ed25519 (libsodium)
     * type 'rsa-pss' => asymmetric RSASSA-PSS (OpenSSL native PSS padding)
     *
     * @var array<string, array{0: string, 1: string|int}>
     */
    public const ALGORITHMS = [
        'HS256'  => ['hmac',    'sha256'],
        'HS384'  => ['hmac',    'sha384'],
        'HS512'  => ['hmac',    'sha512'],
        'RS256'  => ['openssl', OPENSSL_ALGO_SHA256],
        'RS384'  => ['openssl', OPENSSL_ALGO_SHA384],
        'RS512'  => ['openssl', OPENSSL_ALGO_SHA512],
        'ES256'  => ['ecdsa',   OPENSSL_ALGO_SHA256],
        'ES384'  => ['ecdsa',   OPENSSL_ALGO_SHA384],
        'ES512'  => ['ecdsa',   OPENSSL_ALGO_SHA512],
        'EdDSA'  => ['eddsa',   'EdDSA'],
        'PS256'  => ['rsa-pss', OPENSSL_ALGO_SHA256],
        'PS384'  => ['rsa-pss', OPENSSL_ALGO_SHA384],
        'PS512'  => ['rsa-pss', OPENSSL_ALGO_SHA512],
    ];

    /**
     * Map of ECDSA algorithm to R||S byte-length (both r and s concatenated).
     *
     * @var array<string, int>
     */
    private const ECDSA_CONCAT_LENGTHS = [
        'ES256' => 64,
        'ES384' => 96,
        'ES512' => 132,
    ];

    /**
     * @var list<string>
     */
    public const SUPPORTED_ALGS = [
        'HS256', 'HS384', 'HS512',
        'RS256', 'RS384', 'RS512',
        'ES256', 'ES384', 'ES512',
        'EdDSA',
        'PS256', 'PS384', 'PS512',
    ];

    /**
     * Clock skew tolerance (in seconds) to allow for server time differences.
     */
    public static int $leeway = 0;

    /**
     * Overridable "now" timestamp, used to make verification testable.
     */
    public static ?int $timestamp = null;

    // ---------------------------------------------------------------------
    //  Encode
    // ---------------------------------------------------------------------

    /**
     * Encode and sign a payload into a JWT string.
     *
     * @param  array<string, mixed>  $payload  claim set
     * @param  string|\OpenSSLAsymmetricKey  $key  signing key
     * @param  string  $alg  algorithm name (e.g. HS256)
     * @param  string|null  $keyId  optional "kid" header value
     * @param  array<string, mixed>  $extraHeaders  additional header entries
     */
    public static function encode(
        array $payload,
        $key,
        string $alg,
        ?string $keyId = null,
        array $extraHeaders = []
    ): string {
        if (! isset(self::ALGORITHMS[$alg])) {
            throw new JWTException("Unsupported algorithm: {$alg}");
        }

        $header = ['typ' => 'JWT', 'alg' => $alg];

        if ($keyId !== null) {
            $header['kid'] = $keyId;
        }

        $header = array_merge($extraHeaders, $header);

        $segments   = [];
        $segments[] = self::urlsafeB64Encode(self::jsonEncode($header));
        $segments[] = self::urlsafeB64Encode(self::jsonEncode($payload));

        $signingInput = implode('.', $segments);
        $signature    = self::sign($signingInput, $key, $alg);
        $segments[]   = self::urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    // ---------------------------------------------------------------------
    //  Decode & verify
    // ---------------------------------------------------------------------

    /**
     * Decode and verify a JWT.
     *
     * @param  string  $jwt  the token
     * @param  Key|array<string, Key>  $keyOrKeys  a single Key or a kid => Key map
     * @return array<string, mixed> the verified payload
     */
    public static function decode(string $jwt, $keyOrKeys): array
    {
        $timestamp = self::$timestamp ?? time();

        $parts = explode('.', $jwt);

        if (count($parts) !== 3) {
            throw new InvalidTokenException('Malformed token: it must contain exactly three segments.');
        }

        [$headB64, $payloadB64, $sigB64] = $parts;

        $headerRaw  = self::urlsafeB64Decode($headB64);
        $payloadRaw = self::urlsafeB64Decode($payloadB64);
        $signature  = self::urlsafeB64Decode($sigB64);

        $header  = self::jsonDecode($headerRaw);
        $payload = self::jsonDecode($payloadRaw);

        if (! is_array($header)) {
            throw new InvalidTokenException('Invalid token header.');
        }

        if (! is_array($payload)) {
            throw new InvalidTokenException('Invalid token payload.');
        }

        if (empty($header['alg']) || ! is_string($header['alg'])) {
            throw new InvalidTokenException('Algorithm is missing from the header.');
        }

        $alg = $header['alg'];

        // Explicitly reject the "alg: none" attack.
        if (strtolower($alg) === 'none') {
            throw new SignatureInvalidException('The "none" algorithm is not allowed.');
        }

        if (! isset(self::ALGORITHMS[$alg])) {
            throw new SignatureInvalidException("Unsupported algorithm: {$alg}");
        }

        $key = self::selectKey($keyOrKeys, $header);

        // Prevent algorithm confusion: the token algorithm must match the
        // algorithm the trusted key is bound to, exactly.
        if (! hash_equals($key->getAlgorithm(), $alg)) {
            throw new SignatureInvalidException(
                'Token algorithm does not match the expected key algorithm.'
            );
        }

        $signingInput = $headB64.'.'.$payloadB64;

        if (! self::verify($signingInput, $signature, $key->getKeyMaterial(), $alg)) {
            throw new SignatureInvalidException('Token signature is invalid.');
        }

        self::validateClaims($payload, $timestamp);

        return $payload;
    }

    // ---------------------------------------------------------------------
    //  Key selection
    // ---------------------------------------------------------------------

    /**
     * @param  Key|array<string, Key>  $keyOrKeys
     */
    private static function selectKey($keyOrKeys, array $header): Key
    {
        if ($keyOrKeys instanceof Key) {
            return $keyOrKeys;
        }

        if (is_array($keyOrKeys)) {
            if (empty($header['kid']) || ! is_string($header['kid'])) {
                throw new InvalidTokenException(
                    'Token must contain a "kid" when a key set is provided.'
                );
            }

            $kid = $header['kid'];

            if (! isset($keyOrKeys[$kid])) {
                throw new InvalidTokenException("No key found for kid \"{$kid}\".");
            }

            if (! ($keyOrKeys[$kid] instanceof Key)) {
                throw new JWTException('Each entry must be an instance of Key.');
            }

            return $keyOrKeys[$kid];
        }

        throw new JWTException('Key must be a Key instance or an array of Key instances.');
    }

    // ---------------------------------------------------------------------
    //  Claim validation
    // ---------------------------------------------------------------------

    /**
     * @param  array<string, mixed>  $payload
     */
    private static function validateClaims(array $payload, int $now): void
    {
        if (isset($payload['nbf'])) {
            if (! is_numeric($payload['nbf'])) {
                throw new InvalidTokenException('The "nbf" claim is invalid.');
            }

            if ($payload['nbf'] > ($now + self::$leeway)) {
                throw new BeforeValidException('Token is not yet valid (nbf).');
            }
        }

        if (isset($payload['iat'])) {
            if (! is_numeric($payload['iat'])) {
                throw new InvalidTokenException('The "iat" claim is invalid.');
            }

            if ($payload['iat'] > ($now + self::$leeway)) {
                throw new BeforeValidException('Token was issued in the future (iat).');
            }
        }

        if (isset($payload['exp'])) {
            if (! is_numeric($payload['exp'])) {
                throw new InvalidTokenException('The "exp" claim is invalid.');
            }

            if (($now - self::$leeway) >= $payload['exp']) {
                throw new ExpiredException('Token has expired (exp).');
            }
        }
    }

    // ---------------------------------------------------------------------
    //  Cryptographic sign & verify
    // ---------------------------------------------------------------------

    /**
     * @param  string|\OpenSSLAsymmetricKey  $key
     */
    private static function sign(string $input, $key, string $alg): string
    {
        [$type, $hashAlg] = self::ALGORITHMS[$alg];

        switch ($type) {

            case 'hmac':
                if (! is_string($key)) {
                    throw new JWTException('HMAC key must be a string.');
                }

                return hash_hmac($hashAlg, $input, $key, true);

            case 'openssl':
                $signature = '';
                $ok = openssl_sign($input, $signature, $key, $hashAlg);

                if (! $ok) {
                    throw new JWTException('OpenSSL signing failed: '.openssl_error_string());
                }

                return $signature;

            case 'ecdsa':
                $signature = '';
                $ok = openssl_sign($input, $signature, $key, $hashAlg);

                if (! $ok) {
                    throw new JWTException('ECDSA signing failed: '.openssl_error_string());
                }

                // Convert the DER signature produced by OpenSSL into the
                // concatenated R||S format required by the JWT specification.
                return self::derToConcat($signature, self::ECDSA_CONCAT_LENGTHS[$alg]);

            case 'eddsa':
                // Requires PHP ext-sodium (libsodium).
                if (! function_exists('sodium_crypto_sign_detached')) {
                    throw new JWTException(
                        'EdDSA (Ed25519) requires the sodium extension. '.
                        'Install php-sodium or php8.x-sodium.'
                    );
                }

                if (! is_string($key)) {
                    throw new JWTException('EdDSA private key must be a base64-encoded string.');
                }

                $rawKey = self::decodeEdDsaKey($key);

                // libsodium expects a 64-byte seed||public key for signing.
                if (strlen($rawKey) === 32) {
                    // Seed only — derive the full keypair.
                    $kp     = sodium_crypto_sign_seed_keypair($rawKey);
                    $rawKey = sodium_crypto_sign_secretkey($kp);
                }

                if (strlen($rawKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
                    throw new JWTException('EdDSA private key must be 64 bytes (seed+public).');
                }

                return sodium_crypto_sign_detached($input, $rawKey);

            case 'rsa-pss':
                // RSASSA-PSS (RFC 8017) — pure PHP EMSA-PSS + raw RSA via openssl_private_encrypt.
                // openssl_sign() only does PKCS#1 v1.5, so we implement PSS ourselves.
                return self::rsaPssSign($input, $key, $hashAlg);

            default:
                throw new JWTException('Unknown algorithm type.');
        }
    }

    /**
     * @param  string|\OpenSSLAsymmetricKey  $key
     */
    private static function verify(string $input, string $signature, $key, string $alg): bool
    {
        [$type, $hashAlg] = self::ALGORITHMS[$alg];

        switch ($type) {

            case 'hmac':
                if (! is_string($key)) {
                    throw new JWTException('HMAC key must be a string.');
                }

                $expected = hash_hmac($hashAlg, $input, $key, true);

                // Constant-time comparison to mitigate timing attacks.
                return hash_equals($expected, $signature);

            case 'openssl':
                $result = openssl_verify($input, $signature, $key, $hashAlg);

                if ($result === -1) {
                    throw new JWTException('OpenSSL error: '.openssl_error_string());
                }

                return $result === 1;

            case 'ecdsa':
                // Convert the concatenated R||S signature back into DER for OpenSSL.
                $der    = self::concatToDer($signature);
                $result = openssl_verify($input, $der, $key, $hashAlg);

                if ($result === -1) {
                    throw new JWTException('OpenSSL error (ECDSA): '.openssl_error_string());
                }

                return $result === 1;

            case 'eddsa':
                if (! function_exists('sodium_crypto_sign_verify_detached')) {
                    throw new JWTException(
                        'EdDSA (Ed25519) requires the sodium extension.'
                    );
                }

                if (! is_string($key)) {
                    throw new JWTException('EdDSA public key must be a base64-encoded string.');
                }

                $rawKey = self::decodeEdDsaKey($key);

                if (strlen($rawKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                    throw new JWTException('EdDSA public key must be 32 bytes.');
                }

                try {
                    return sodium_crypto_sign_verify_detached($signature, $input, $rawKey);
                } catch (\SodiumException $e) {
                    return false;
                }

            case 'rsa-pss':
                return self::rsaPssVerify($input, $signature, $key, $hashAlg);

            default:
                throw new JWTException('Unknown algorithm type.');
        }
    }

    // ---------------------------------------------------------------------
    //  RSASSA-PSS helpers
    // ---------------------------------------------------------------------

    /**
     * Sign using RSASSA-PSS with MGF1 and salt length == hash length.
     *
     * @param  string|\OpenSSLAsymmetricKey  $privateKey
     */
    private static function rsaPssSign(string $input, $privateKey, int $hashAlg): string
    {
        $hashName = self::opensslAlgoToHashName($hashAlg);
        $digest   = hash($hashName, $input, true);
        $hashLen  = strlen($digest);

        // Get RSA modulus length in bytes.
        $details = openssl_pkey_get_details(
            is_string($privateKey)
                ? (openssl_pkey_get_private($privateKey) ?: throw new JWTException('Invalid RSA private key.'))
                : $privateKey
        );

        if ($details === false || ! isset($details['bits'])) {
            throw new JWTException('Could not retrieve RSA key details for PSS signing.');
        }

        $emLen = (int) ceil(($details['bits'] - 1) / 8);

        $em = self::emsaPssEncode($digest, $hashName, $hashLen, $emLen);

        // Raw RSA private operation (no padding from OpenSSL side).
        $sig = '';
        $key = is_string($privateKey)
            ? (openssl_pkey_get_private($privateKey) ?: throw new JWTException('Invalid RSA private key.'))
            : $privateKey;

        if (openssl_private_encrypt($em, $sig, $key, OPENSSL_NO_PADDING) === false) {
            throw new JWTException('RSA-PSS raw encrypt failed: '.openssl_error_string());
        }

        return $sig;
    }

    /**
     * Verify RSASSA-PSS signature.
     *
     * @param  string|\OpenSSLAsymmetricKey  $publicKey
     */
    private static function rsaPssVerify(string $input, string $signature, $publicKey, int $hashAlg): bool
    {
        $hashName = self::opensslAlgoToHashName($hashAlg);
        $digest   = hash($hashName, $input, true);
        $hashLen  = strlen($digest);

        $key = is_string($publicKey)
            ? (openssl_pkey_get_public($publicKey) ?: throw new JWTException('Invalid RSA public key.'))
            : $publicKey;

        $details = openssl_pkey_get_details($key);

        if ($details === false || ! isset($details['bits'])) {
            throw new JWTException('Could not retrieve RSA key details for PSS verification.');
        }

        $emLen = (int) ceil(($details['bits'] - 1) / 8);

        // Raw RSA public operation.
        $em = '';

        if (openssl_public_decrypt($signature, $em, $key, OPENSSL_NO_PADDING) === false) {
            return false;
        }

        return self::emsaPssVerify($digest, $em, $hashName, $hashLen, $emLen);
    }

    /**
     * EMSA-PSS encoding (RFC 8017 §9.1.1).
     */
    private static function emsaPssEncode(
        string $mHash,
        string $hashName,
        int $hLen,
        int $emLen
    ): string {
        $sLen = $hLen; // salt length == hash length (matches firebase/php-jwt default)

        if ($emLen < $hLen + $sLen + 2) {
            throw new JWTException('EMSA-PSS: encoding error — emLen too small.');
        }

        $salt   = random_bytes($sLen);
        $mPrime = str_repeat("\x00", 8).$mHash.$salt;
        $h      = hash($hashName, $mPrime, true);
        $ps     = str_repeat("\x00", $emLen - $sLen - $hLen - 2);
        $db     = $ps."\x01".$salt;
        $dbMask = self::mgf1($h, $emLen - $hLen - 1, $hashName);
        $maskedDb = $db ^ $dbMask;

        // Clear the leftmost bits.
        $maskedDb[0] = chr(ord($maskedDb[0]) & 0x7F);

        return $maskedDb.$h."\xBC";
    }

    /**
     * EMSA-PSS verification (RFC 8017 §9.1.2).
     */
    private static function emsaPssVerify(
        string $mHash,
        string $em,
        string $hashName,
        int $hLen,
        int $emLen
    ): bool {
        $sLen = $hLen;

        if ($emLen < $hLen + $sLen + 2) {
            return false;
        }

        if (ord($em[$emLen - 1]) !== 0xBC) {
            return false;
        }

        $maskedDb = substr($em, 0, $emLen - $hLen - 1);
        $h        = substr($em, $emLen - $hLen - 1, $hLen);

        if (ord($maskedDb[0]) & 0x80) {
            return false;
        }

        $dbMask = self::mgf1($h, $emLen - $hLen - 1, $hashName);
        $db     = $maskedDb ^ $dbMask;
        $db[0]  = chr(ord($db[0]) & 0x7F);

        // Check that the first emLen-hLen-sLen-2 bytes of DB are zero, followed by 0x01.
        $psLen = $emLen - $hLen - $sLen - 2;

        for ($i = 0; $i < $psLen; $i++) {
            if ($db[$i] !== "\x00") {
                return false;
            }
        }

        if ($db[$psLen] !== "\x01") {
            return false;
        }

        $salt   = substr($db, $psLen + 1);
        $mPrime = str_repeat("\x00", 8).$mHash.$salt;
        $hPrime = hash($hashName, $mPrime, true);

        return hash_equals($h, $hPrime);
    }

    /**
     * MGF1 mask generation function (RFC 8017 Appendix B.2.1).
     */
    private static function mgf1(string $seed, int $length, string $hashName): string
    {
        $mask = '';
        $count = (int) ceil($length / strlen(hash($hashName, '', true)));

        for ($i = 0; $i < $count; $i++) {
            $c = pack('N', $i);
            $mask .= hash($hashName, $seed.$c, true);
        }

        return substr($mask, 0, $length);
    }

    /**
     * Map OPENSSL_ALGO_* constant to a hash() algorithm name.
     */
    private static function opensslAlgoToHashName(int $algo): string
    {
        return match ($algo) {
            OPENSSL_ALGO_SHA256 => 'sha256',
            OPENSSL_ALGO_SHA384 => 'sha384',
            OPENSSL_ALGO_SHA512 => 'sha512',
            default             => throw new JWTException("Unsupported OpenSSL hash algorithm constant: {$algo}"),
        };
    }

    // ---------------------------------------------------------------------
    //  EdDSA helpers
    // ---------------------------------------------------------------------

    /**
     * Accept a key in base64, base64url, or raw binary form and return raw bytes.
     */
    private static function decodeEdDsaKey(string $key): string
    {
        // Already raw binary of the expected length?
        if (strlen($key) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES ||
            strlen($key) === SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            return $key;
        }

        // Try base64url first, then standard base64.
        try {
            $raw = self::urlsafeB64Decode($key);
        } catch (\Throwable) {
            $raw = base64_decode($key, true);
        }

        if ($raw === false || $raw === '') {
            throw new JWTException('EdDSA key could not be decoded. Provide base64url, base64, or raw bytes.');
        }

        return $raw;
    }

    // ---------------------------------------------------------------------
    //  ECDSA helpers (DER <-> R||S)
    // ---------------------------------------------------------------------

    private static function derToConcat(string $der, int $length): string
    {
        $offset = 0;

        if (ord($der[$offset++]) !== 0x30) {
            throw new JWTException('Invalid DER structure.');
        }

        // Total sequence length (may be one or two bytes).
        if (ord($der[$offset]) & 0x80) {
            $offset += (ord($der[$offset]) & 0x7F) + 1;
        } else {
            $offset++;
        }

        $r = self::readDerInteger($der, $offset);
        $s = self::readDerInteger($der, $offset);

        $half = (int) ($length / 2);
        $r = str_pad(ltrim($r, "\x00"), $half, "\x00", STR_PAD_LEFT);
        $s = str_pad(ltrim($s, "\x00"), $half, "\x00", STR_PAD_LEFT);

        return $r.$s;
    }

    private static function readDerInteger(string $der, int &$offset): string
    {
        if (ord($der[$offset++]) !== 0x02) {
            throw new JWTException('Invalid DER integer.');
        }

        $len   = ord($der[$offset++]);
        $value = substr($der, $offset, $len);
        $offset += $len;

        return $value;
    }

    private static function concatToDer(string $sig): string
    {
        $len = strlen($sig);

        if ($len % 2 !== 0) {
            throw new JWTException('Invalid ECDSA signature length.');
        }

        $half = (int) ($len / 2);
        $r    = substr($sig, 0, $half);
        $s    = substr($sig, $half);

        $r    = self::encodeDerInteger($r);
        $s    = self::encodeDerInteger($s);

        $body = $r.$s;

        return "\x30".self::encodeDerLength(strlen($body)).$body;
    }

    private static function encodeDerInteger(string $int): string
    {
        $int = ltrim($int, "\x00");

        if ($int === '') {
            $int = "\x00";
        }

        // If the high bit is set, prepend 0x00 so the integer stays positive.
        if (ord($int[0]) & 0x80) {
            $int = "\x00".$int;
        }

        return "\x02".self::encodeDerLength(strlen($int)).$int;
    }

    private static function encodeDerLength(int $length): string
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

    // ---------------------------------------------------------------------
    //  Base64Url & JSON helpers
    // ---------------------------------------------------------------------

    public static function urlsafeB64Encode(string $data): string
    {
        return str_replace('=', '', strtr(base64_encode($data), '+/', '-_'));
    }

    public static function urlsafeB64Decode(string $data): string
    {
        $remainder = strlen($data) % 4;

        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode(strtr($data, '-_', '+/'), true);

        if ($decoded === false) {
            throw new InvalidTokenException('Invalid Base64Url string.');
        }

        return $decoded;
    }

    public static function jsonEncode(array $input): string
    {
        $json = json_encode($input, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        if ($json === false || json_last_error() !== JSON_ERROR_NONE) {
            throw new JWTException('JSON encoding error: '.json_last_error_msg());
        }

        return $json;
    }

    /**
     * @return mixed
     */
    public static function jsonDecode(string $input)
    {
        $data = json_decode($input, true, 512, JSON_BIGINT_AS_STRING);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new InvalidTokenException('JSON decoding error: '.json_last_error_msg());
        }

        return $data;
    }
}
