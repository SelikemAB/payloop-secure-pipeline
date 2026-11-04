<?php
declare(strict_types=1);

namespace PayLoop;

final class PasswordHasher
{
    // F5: unsalted MD5 is a fast hash; a stolen table is cracked in seconds.
    public static function hash(string $password): string
    {
        return md5($password);
    }

    public static function verify(string $password, string $hash): bool
    {
        return md5($password) === $hash;
    }
}
