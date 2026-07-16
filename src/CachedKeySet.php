<?php

declare(strict_types=1);

namespace SwanFlutter\NativeJwt;

use ArrayAccess;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use SwanFlutter\NativeJwt\Exceptions\InvalidTokenException;
use SwanFlutter\NativeJwt\Exceptions\JWTException;

/**
 * A lazy, PSR-6-cached JWKS key set.
 *
 * Usage:
 *
 *   $keySet = new CachedKeySet(
 *       'https://www.googleapis.com/oauth2/v3/certs',
 *       $httpClient,       // PSR-18 ClientInterface
 *       $requestFactory,   // PSR-17 RequestFactoryInterface
 *       $cachePool,        // PSR-6  CacheItemPoolInterface
 *       3600,              // TTL in seconds (null = use Cache-Control max-age)
 *       true,              // enable rate-limiting (max 10 refreshes/second)
 *   );
 *
 *   $decoded = JWT::decode($token, $keySet);
 *
 * JWT::decode() calls $keySet[$kid], which triggers a fetch + cache on first
 * access.  If an unknown kid is received, the cache is refreshed once to
 * accommodate key rotation.
 *
 * @implements ArrayAccess<string, Key>
 */
final class CachedKeySet implements ArrayAccess
{
    private const CACHE_KEY_PREFIX = 'native_jwt_jwks_';

    /** Maximum in-memory refresh attempts per key lookup to prevent infinite loops. */
    private const MAX_REFRESH_ATTEMPTS = 1;

    /** Maximum HTTP refreshes per second when rate limiting is enabled. */
    private const RATE_LIMIT_MAX_RPS = 10;

    /** @var array<string, Key>|null  in-memory cache of the last fetched key set */
    private ?array $keySet = null;

    /** Whether the key set has already been refreshed once for an unknown kid. */
    private bool $refreshed = false;

    /** Timestamp of the last HTTP fetch (microseconds). */
    private float $lastFetchTime = 0.0;

    /** Counter for rate-limiting. */
    private int $fetchCountThisSecond = 0;

    public function __construct(
        private readonly string $jwksUri,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly CacheItemPoolInterface $cache,
        private readonly ?int $expiresAfter = null,
        private readonly bool $rateLimit = false,
        /** @var array<string, string> */
        private readonly array $defaultAlgorithms = [],
    ) {}

    // -------------------------------------------------------------------------
    //  ArrayAccess — used by JWT::decode() via $keyOrKeys[$kid]
    // -------------------------------------------------------------------------

    /** @param  string  $offset */
    public function offsetExists(mixed $offset): bool
    {
        $this->ensureLoaded($offset);

        return isset($this->keySet[$offset]);
    }

    /**
     * @param  string  $offset
     * @return Key
     */
    public function offsetGet(mixed $offset): mixed
    {
        $this->ensureLoaded($offset);

        if (! isset($this->keySet[$offset])) {
            throw new InvalidTokenException("No key found for kid \"{$offset}\".");
        }

        return $this->keySet[$offset];
    }

    /** @param  string  $offset */
    public function offsetSet(mixed $offset, mixed $value): void
    {
        throw new JWTException('CachedKeySet is read-only.');
    }

    /** @param  string  $offset */
    public function offsetUnset(mixed $offset): void
    {
        throw new JWTException('CachedKeySet is read-only.');
    }

    // -------------------------------------------------------------------------
    //  Internal
    // -------------------------------------------------------------------------

    /**
     * Ensure the key set is loaded and, if the requested kid is unknown,
     * attempt a single cache-busting refresh to support key rotation.
     */
    private function ensureLoaded(string $kid): void
    {
        if ($this->keySet === null) {
            $this->keySet = $this->fetchFromCacheOrRemote();
        }

        // Kid already found — nothing to do.
        if (isset($this->keySet[$kid])) {
            return;
        }

        // Kid not found and we haven't refreshed yet: bust the cache and retry.
        if (! $this->refreshed) {
            $this->refreshed = true;
            $this->keySet = $this->fetchFromRemote(bustCache: true);
        }
    }

    /**
     * Return cached keys or fetch from the remote JWKS URI.
     *
     * @return array<string, Key>
     */
    private function fetchFromCacheOrRemote(): array
    {
        $cacheKey  = $this->buildCacheKey();
        $cacheItem = $this->cache->getItem($cacheKey);

        if ($cacheItem->isHit()) {
            $cached = $cacheItem->get();

            if (is_array($cached) && ! empty($cached)) {
                return $cached;
            }
        }

        return $this->fetchFromRemote();
    }

    /**
     * Fetch the JWKS from the remote URI, parse it, and store it in the cache.
     *
     * @param  bool  $bustCache  when true, forces a new HTTP request even if the cache is warm
     * @return array<string, Key>
     */
    private function fetchFromRemote(bool $bustCache = false): array
    {
        if ($this->rateLimit) {
            $this->enforceRateLimit();
        }

        $request  = $this->requestFactory->createRequest('GET', $this->jwksUri);
        $response = $this->httpClient->sendRequest($request);

        $statusCode = $response->getStatusCode();

        if ($statusCode < 200 || $statusCode >= 300) {
            throw new JWTException(
                "Failed to fetch JWKS from \"{$this->jwksUri}\": HTTP {$statusCode}."
            );
        }

        $body = (string) $response->getBody();
        $jwks = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

        if (! is_array($jwks)) {
            throw new JWTException('JWKS response is not a valid JSON object.');
        }

        $keys = JWK::parseKeySet($jwks, $this->defaultAlgorithms);

        // Determine TTL: explicit setting > Cache-Control max-age > no expiry.
        $ttl = $this->expiresAfter;

        if ($ttl === null) {
            $ttl = $this->parseCacheControlMaxAge($response->getHeaderLine('Cache-Control'));
        }

        $cacheKey  = $this->buildCacheKey();
        $cacheItem = $this->cache->getItem($cacheKey);
        $cacheItem->set($keys);

        if ($ttl !== null) {
            $cacheItem->expiresAfter($ttl);
        }

        $this->cache->save($cacheItem);

        return $keys;
    }

    /**
     * Build a safe PSR-6 cache key from the JWKS URI.
     * PSR-6 forbids {}()/\@: so we hash the URI.
     */
    private function buildCacheKey(): string
    {
        return self::CACHE_KEY_PREFIX.hash('sha256', $this->jwksUri);
    }

    /**
     * Enforce a maximum of RATE_LIMIT_MAX_RPS fetches per second using a
     * simple in-memory token-bucket approximation.
     */
    private function enforceRateLimit(): void
    {
        $now = microtime(true);

        if ((int) $now !== (int) $this->lastFetchTime) {
            // New second: reset counter.
            $this->fetchCountThisSecond = 0;
            $this->lastFetchTime        = $now;
        }

        if ($this->fetchCountThisSecond >= self::RATE_LIMIT_MAX_RPS) {
            throw new JWTException(
                'JWKS refresh rate limit exceeded ('.self::RATE_LIMIT_MAX_RPS.' requests/second).'
            );
        }

        $this->fetchCountThisSecond++;
        $this->lastFetchTime = $now;
    }

    /**
     * Extract max-age from a Cache-Control header value.
     * Returns null if not present or unparseable.
     */
    private function parseCacheControlMaxAge(string $header): ?int
    {
        if (preg_match('/max-age\s*=\s*(\d+)/i', $header, $matches)) {
            return (int) $matches[1];
        }

        return null;
    }
}
