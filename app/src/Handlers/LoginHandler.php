<?php
declare(strict_types=1);

namespace PayLoop\Handlers;

use PayLoop\{Auth, Db, HttpException, Logger, PasswordHasher, RateLimiter, Request, Response};

final class LoginHandler
{
    private const WINDOW = 300;      // seconds
    private const MAX_PER_USER = 5;  // failures per username per window
    private const MAX_PER_IP = 20;   // failures per source IP per window
    // Hash of a throwaway string: verifying against it keeps timing similar for unknown users.
    private const DUMMY = '$argon2id$v=19$m=65536,t=4,p=1$dTc3dGhMQ1NKVG1hN3Vyeg$HIf2YSVQQEsr3C+doI+j/BeWVhVK6b8A96oV52SZHSg';

    public static function handle(Request $r): void
    {
        $body = $r->json();
        $username = is_string($body['username'] ?? null) ? strtolower(trim($body['username'])) : '';
        $password = is_string($body['password'] ?? null) ? $body['password'] : '';
        $username = substr($username, 0, 64);

        $ipKey = 'ip:' . $r->ip;
        $userKey = 'user:' . $username;
        if (RateLimiter::tooMany($ipKey, self::MAX_PER_IP, self::WINDOW) || RateLimiter::tooMany($userKey, self::MAX_PER_USER, self::WINDOW)) {
            Logger::event('login_rate_limited', ['username' => $username]);
            header('Retry-After: ' . self::WINDOW);
            throw new HttpException(429, 'too_many_attempts');
        }

        $st = Db::pdo()->prepare('SELECT id, username, pass_hash, role FROM users WHERE username = ?');
        $st->execute([$username]);
        $user = $st->fetch();

        $ok = false;
        if ($user === false) {
            PasswordHasher::verify($password, self::DUMMY);   // equalise timing for unknown users
        } else {
            $ok = PasswordHasher::verify($password, $user['pass_hash']);
        }

        if (!$ok) {
            RateLimiter::hit($ipKey);
            RateLimiter::hit($userKey);
            // The reason is logged for the SOC but never returned to the client.
            Logger::event('login_failed', ['username' => $username, 'reason' => $user === false ? 'unknown_user' : 'bad_password']);
            throw new HttpException(401, 'invalid_credentials');
        }

        Logger::setUser($user['username']);
        Logger::event('login_success', ['username' => $username]);
        Response::json(200, ['token' => Auth::issueToken($user), 'expires_in' => 3600]);
    }
}
