<?php

declare(strict_types=1);

namespace SwanFlutter\NativeJwt;

use SwanFlutter\NativeJwt\Exceptions\BeforeValidException;
use SwanFlutter\NativeJwt\Exceptions\ExpiredException;
use SwanFlutter\NativeJwt\Exceptions\InvalidTokenException;
use SwanFlutter\NativeJwt\Exceptions\JWTException;
use SwanFlutter\NativeJwt\Exceptions\SignatureInvalidException;

/**
 * A standalone, dependency-free JWT implementation for PHP.
 *
 * Supports HMAC (HS256/384/512), RSA (RS256/384/512) and ECDSA (ES256/384).
 *
 * Security guarantees:
 *  - The "alg: none" attack is explicitly rejected.
 *  - Algorithm confusion is prevented because every trusted Key is bound to
 *    a single algorithm and the token algorithm must match it exactly.
 *  - Signatures are compared in constant time (HMAC) and verified via OpenSSL.
 *  - Time-based claims (exp/nbf/iat) are validated with configurable leeway.
 */
final class JWT
{
    /**
     * Algorithm map.
     * type 'hmac'   => symmetric (hash_hmac)
     * type 'openssl' => asymmetric RSA (openssl_sign / openssl_verify)
     * type 'ecdsa'  => asymmetric ECDSA (DER <-> R||S conversion applied).
     *
     * @var array<string, array{0: string, 1: string|int}>
     */
    public const ALGORITHMS = [
        'HS256' => ['hmac', 'sha256'],
        'HS384' => ['hmac', 'sha384'],
        'HS512' => ['hmac', 'sha512'],
        'RS256' => ['openssl', OPENSSL_ALGO_SHA256],
        'RS384' => ['openssl', OPENSSL_ALGO_SHA384],
        'RS512' => ['openssl', OPENSSL_ALGO_SHA512],
        'ES256' => ['ecdsa', OPENSSL_ALGO_SHA256],
        'ES384' => ['ecdsa', OPENSSL_ALGO_SHA384],
    ];

    /**
     * @var list<string>
     */
    public const SUPPORTED_ALGS = [
        'HS256', 'HS384', 'HS512',
        'RS256', 'RS384', 'RS512',
        'ES256', 'ES384',
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
     * @param array                            $payload      claim set
     * @param string|\OpenSSLAsymmetricKey     $key          signing key
     * @param string                           $alg          algorithm name (e.g. HS256)
     * @param string|null                      $keyId        optional "kid" header value
     * @param array<string, mixed>             $extraHeaders additional header entries
     */
    public static function encode(
        array $payload,
        $key,
        string $alg,
        ?string $keyId = null,
        array $extraHeaders = []
    ): string {
        if (!isset(self::ALGORITHMS[$alg])) {
            throw new JWTException("Unsupported algorithm: {$alg}");
        }

        $header = ['typ' => 'JWT', 'alg' => $alg];

        if ($keyId !== null) {
            $header['kid'] = $keyId;
        }

        $header = array_merge($extraHeaders, $header);

        $segments = [];
        $segments[] = self::urlsafeB64Encode(self::jsonEncode($header));
        $segments[] = self::urlsafeB64Encode(self::jsonEncode($payload));

        $signingInput = implode('.', $segments);
        $signature = self::sign($signingInput, $key, $alg);
        $segments[] = self::urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    // ---------------------------------------------------------------------
    //  Decode & verify
    // ---------------------------------------------------------------------

    /**
     * Decode and verify a JWT.
     *
     * @param string                  $jwt        the token
     * @param Key|array<string, Key>  $keyOrKeys  a single Key or a kid => Key map
     *
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

        $headerRaw = self::urlsafeB64Decode($headB64);
        $payloadRaw = self::urlsafeB64Decode($payloadB64);
        $signature = self::urlsafeB64Decode($sigB64);

        $header = self::jsonDecode($headerRaw);
        $payload = self::jsonDecode($payloadRaw);

        if (!is_array($header)) {
            throw new InvalidTokenException('Invalid token header.');
        }

        if (!is_array($payload)) {
            throw new InvalidTokenException('Invalid token payload.');
        }

        if (empty($header['alg']) || !is_string($header['alg'])) {
            throw new InvalidTokenException('Algorithm is missing from the header.');
        }

        $alg = $header['alg'];

        // Explicitly reject the "alg: none" attack.
        if (strtolower($alg) === 'none') {
            throw new SignatureInvalidException('The "none" algorithm is not allowed.');
        }

        if (!isset(self::ALGORITHMS[$alg])) {
            throw new SignatureInvalidException("Unsupported algorithm: {$alg}");
        }

        $key = self::selectKey($keyOrKeys, $header);

        // Prevent algorithm confusion: the token algorithm must match the
        // algorithm the trusted key is bound to, exactly.
        if (!hash_equals($key->getAlgorithm(), $alg)) {
            throw new SignatureInvalidException(
                'Token algorithm does not match the expected key algorithm.'
            );
        }

        $signingInput = $headB64 . '.' . $payloadB64;

        if (!self::verify($signingInput, $signature, $key->getKeyMaterial(), $alg)) {
            throw new SignatureInvalidException('Token signature is invalid.');
        }

        self::validateClaims($payload, $timestamp);

        return $payload;
    }

    // ---------------------------------------------------------------------
    //  Key selection
    // ---------------------------------------------------------------------

    /**
     * @param Key|array<string, Key> $keyOrKeys
     */
    private static function selectKey($keyOrKeys, array $header): Key
    {
        if ($keyOrKeys instanceof Key) {
            return $keyOrKeys;
        }

        if (is_array($keyOrKeys)) {
            if (empty($header['kid']) || !is_string($header['kid'])) {
                throw new InvalidTokenException(
                    'Token must contain a "kid" when a key set is provided.'
                );
            }

            $kid = $header['kid'];

            if (!isset($keyOrKeys[$kid])) {
                throw new InvalidTokenException("No key found for kid \"{$kid}\".");
            }

            if (!($keyOrKeys[$kid] instanceof Key)) {
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
     * @param array<string, mixed> $payload
     */
    private static function validateClaims(array $payload, int $now): void
    {
        if (isset($payload['nbf'])) {
            if (!is_numeric($payload['nbf'])) {
                throw new InvalidTokenException('The "nbf" claim is invalid.');
            }

            if ($payload['nbf'] > ($now + self::$leeway)) {
                throw new BeforeValidException('Token is not yet valid (nbf).');
            }
        }

        if (isset($payload['iat'])) {
            if (!is_numeric($payload['iat'])) {
                throw new InvalidTokenException('The "iat" claim is invalid.');
            }

            if ($payload['iat'] > ($now + self::$leeway)) {
                throw new BeforeValidException('Token was issued in the future (iat).');
            }
        }

        if (isset($payload['exp'])) {
            if (!is_numeric($payload['exp'])) {
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
     * @param string|\OpenSSLAsymmetricKey $key
     */
    private static function sign(string $input, $key, string $alg): string
    {
        [$type, $hashAlg] = self::ALGORITHMS[$alg];

        switch ($type) {
            case 'hmac':
                if (!is_string($key)) {
                    throw new JWTException('HMAC key must be a string.');
                }

                return hash_hmac($hashAlg, $input, $key, true);

            case 'openssl':
                $signature = '';
                $ok = openssl_sign($input, $signature, $key, $hashAlg);

                if (!$ok) {
                    throw new JWTException('OpenSSL signing failed: ' . openssl_error_string());
                }

                return $signature;

            case 'ecdsa':
                $signature = '';
                $ok = openssl_sign($input, $signature, $key, $hashAlg);

                if (!$ok) {
                    throw new JWTException('ECDSA signing failed: ' . openssl_error_string());
                }

                // Convert the DER signature produced by OpenSSL into the
                // concatenated R||S format required by the JWT specification.
                return self::derToConcat($signature, $alg === 'ES256' ? 64 : 96);

            default:
                throw new JWTException('Unknown algorithm type.');
        }
    }

    /**
     * @param string|\OpenSSLAsymmetricKey $key
     */
    private static function verify(string $input, string $signature, $key, string $alg): bool
    {
        [$type, $hashAlg] = self::ALGORITHMS[$alg];

        switch ($type) {
            case 'hmac':
                if (!is_string($key)) {
                    throw new JWTException('HMAC key must be a string.');
                }

                $expected = hash_hmac($hashAlg, $input, $key, true);

                // Constant-time comparison to mitigate timing attacks.
                return hash_equals($expected, $signature);

            case 'openssl':
                $result = openssl_verify($input, $signature, $key, $hashAlg);

                if ($result === -1) {
                    throw new JWTException('OpenSSL error: ' . openssl_error_string());
                }

                return $result === 1;

            case 'ecdsa':
                // Convert the concatenated R||S signature back into DER for OpenSSL.
                $der = self::concatToDer($signature);
                $result = openssl_verify($input, $der, $key, $hashAlg);

                if ($result === -1) {
                    throw new JWTException('OpenSSL error (ECDSA): ' . openssl_error_string());
                }

                return $result === 1;

            default:
                throw new JWTException('Unknown algorithm type.');
        }
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
            $offset += (ord($der[$offset]) & 0x7f) + 1;
        } else {
            $offset++;
        }

        $r = self::readDerInteger($der, $offset);
        $s = self::readDerInteger($der, $offset);

        $half = (int) ($length / 2);
        $r = str_pad(ltrim($r, "\x00"), $half, "\x00", STR_PAD_LEFT);
        $s = str_pad(ltrim($s, "\x00"), $half, "\x00", STR_PAD_LEFT);

        return $r . $s;
    }

    private static function readDerInteger(string $der, int &$offset): string
    {
        if (ord($der[$offset++]) !== 0x02) {
            throw new JWTException('Invalid DER integer.');
        }

        $len = ord($der[$offset++]);
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
        $r = substr($sig, 0, $half);
        $s = substr($sig, $half);

        $r = self::encodeDerInteger($r);
        $s = self::encodeDerInteger($s);

        $body = $r . $s;

        return "\x30" . self::encodeDerLength(strlen($body)) . $body;
    }

    private static function encodeDerInteger(string $int): string
    {
        $int = ltrim($int, "\x00");

        if ($int === '') {
            $int = "\x00";
        }

        // If the high bit is set, prepend 0x00 so the integer stays positive.
        if (ord($int[0]) & 0x80) {
            $int = "\x00" . $int;
        }

        return "\x02" . self::encodeDerLength(strlen($int)) . $int;
    }

    private static function encodeDerLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = '';

        while ($length > 0) {
            $bytes = chr($length & 0xff) . $bytes;
            $length >>= 8;
        }

        return chr(0x80 | strlen($bytes)) . $bytes;
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
            throw new JWTException('JSON encoding error: ' . json_last_error_msg());
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
            throw new InvalidTokenException('JSON decoding error: ' . json_last_error_msg());
        }

        return $data;
    }
}
