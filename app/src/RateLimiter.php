<?php
declare(strict_types=1);

namespace PayLoop;

/** Sliding-window failure counter stored in the DB so limits survive restarts and span workers. */
final class RateLimiter
{
    public static function tooMany(string $key, int $max, int $windowSeconds): bool
    {
        $st = Db::pdo()->prepare('SELECT COUNT(*) FROM login_attempts WHERE k = ? AND ts >= ?');
        $st->execute([$key, time() - $windowSeconds]);
        return (int) $st->fetchColumn() >= $max;
    }

    public static function hit(string $key): void
    {
        Db::pdo()->prepare('INSERT INTO login_attempts(k, ts) VALUES (?, ?)')->execute([$key, time()]);
        Db::pdo()->prepare('DELETE FROM login_attempts WHERE ts < ?')->execute([time() - 86400]);
    }
}
