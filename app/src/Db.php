<?php
declare(strict_types=1);

namespace PayLoop;

final class Db
{
    private static ?\PDO $pdo = null;

    public static function pdo(): \PDO
    {
        if (self::$pdo === null) {
            $path = Config::dbPath();
            if (!is_dir(dirname($path))) {
                mkdir(dirname($path), 0750, true);
            }
            $pdo = new \PDO('sqlite:' . $path, null, null, [
                \PDO::ATTR_ERRMODE            => \PDO::ERRMODE_EXCEPTION,
                \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
                \PDO::ATTR_EMULATE_PREPARES   => false,
            ]);
            $pdo->exec('PRAGMA foreign_keys = ON');
            $pdo->exec('PRAGMA busy_timeout = 5000');
            self::$pdo = $pdo;
        }
        return self::$pdo;
    }

    public static function migrate(): void
    {
        self::pdo()->exec((string) file_get_contents(dirname(__DIR__) . '/db/schema.sql'));
    }
}
