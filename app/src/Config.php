<?php
declare(strict_types=1);

namespace PayLoop;

final class Config
{
    /** Signing secret comes from the environment (secret manager / orchestrator), never from source. */
    public static function tokenSecret(): string
    {
        $secret = getenv('PAYLOOP_TOKEN_SECRET');
        if ($secret === false || strlen($secret) < 32) {
            // Fail closed: refuse to run with a missing or weak secret.
            throw new \RuntimeException('PAYLOOP_TOKEN_SECRET must be set to at least 32 characters');
        }
        return $secret;
    }

    public static function tokenTtl(): int
    {
        return 3600;
    }

    public static function dbPath(): string
    {
        return getenv('PAYLOOP_DB') ?: dirname(__DIR__) . '/var/payloop.sqlite';
    }

    public static function logPath(): string
    {
        return getenv('PAYLOOP_LOG') ?: dirname(__DIR__) . '/var/log/payloop.jsonl';
    }

    public static function receiptsDir(): string
    {
        return dirname(__DIR__) . '/data/receipts';
    }
}
