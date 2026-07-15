<?php

namespace SwanFlutter\NativeJwt;

use SwanFlutter\NativeJwt\Exceptions\JWTException;

/**
 * Holds a key together with the algorithm it is bound to.
 *
 * Binding the algorithm to the key prevents algorithm-confusion attacks,
 * because every trusted key is fixed to a single signing algorithm.
 */
final class Key
{
    /** @var string|\OpenSSLAsymmetricKey */
    private $keyMaterial;

    private string $algorithm;

    /**
     * @param  string|\OpenSSLAsymmetricKey  $keyMaterial
     */
    public function __construct($keyMaterial, string $algorithm)
    {
        if (is_string($keyMaterial) && $keyMaterial === '') {
            throw new JWTException('Key cannot be empty.');
        }

        if (! in_array($algorithm, JWT::SUPPORTED_ALGS, true)) {
            throw new JWTException("Unsupported algorithm: {$algorithm}");
        }

        $this->keyMaterial = $keyMaterial;
        $this->algorithm = $algorithm;
    }

    /**
     * @return string|\OpenSSLAsymmetricKey
     */
    public function getKeyMaterial()
    {
        return $this->keyMaterial;
    }

    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }
}
