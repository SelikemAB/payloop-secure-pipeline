<?php
declare(strict_types=1);

namespace PayLoop;

/** Structured JSON-lines security/audit log. One event per line; never logs request bodies or secrets. */
final class Logger
{
    private static string $rid = '';
    private static string $ip = '0.0.0.0';
    private static ?string $user = null;

    public static function init(string $rid, string $ip): void
    {
        self::$rid = $rid;
        self::$ip = $ip;
    }

    public static function setUser(?string $user): void
    {
        self::$user = $user;
    }

    /** @param array<string,mixed> $fields */
    public static function event(string $event, array $fields = []): void
    {
        $record = array_merge([
            'ts'    => gmdate('Y-m-d\TH:i:s\Z'),
            'app'   => 'payloop',
            'event' => $event,
            'srcip' => self::$ip,
            'rid'   => self::$rid,
            'user'  => self::$user,
        ], $fields);
        $record = array_filter($record, static fn($v) => $v !== null);

        $path = Config::logPath();
        if (!is_dir(dirname($path))) {
            @mkdir(dirname($path), 0750, true);
        }
        @file_put_contents($path, json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL, FILE_APPEND | LOCK_EX);
    }
}
