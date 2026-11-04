<?php
declare(strict_types=1);

namespace PayLoop;

final class Config
{
    // F6: signing secret hard-coded in source and committed to the repository.
    private const TOKEN_SECRET = 'payloop-dev-secret-2024';

    public static function tokenSecret(): string
    {
        return self::TOKEN_SECRET;
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
