<?php
declare(strict_types=1);

namespace PayLoop\Handlers;

use PayLoop\{Auth, Db, HttpException, Logger, PasswordHasher, Request, Response};

final class LoginHandler
{
    public static function handle(Request $r): void
    {
        $body = $r->json();
        $username = is_string($body['username'] ?? null) ? $body['username'] : '';
        $password = is_string($body['password'] ?? null) ? $body['password'] : '';

        $st = Db::pdo()->prepare('SELECT id, username, pass_hash, role FROM users WHERE username = ?');
        $st->execute([$username]);
        $user = $st->fetch();

        // F7: no throttling, and distinct errors reveal which usernames exist.
        if ($user === false) {
            Logger::event('login_failed', ['username' => $username, 'reason' => 'unknown_user']);
            throw new HttpException(401, 'unknown_user');
        }
        if (!PasswordHasher::verify($password, $user['pass_hash'])) {
            Logger::event('login_failed', ['username' => $username, 'reason' => 'bad_password']);
            throw new HttpException(401, 'wrong_password');
        }

        Logger::setUser($user['username']);
        Logger::event('login_success', ['username' => $username]);
        Response::json(200, ['token' => Auth::issueToken($user), 'expires_in' => 3600]);
    }
}
