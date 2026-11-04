<?php
declare(strict_types=1);

namespace PayLoop\Handlers;

use PayLoop\{Auth, Db, HttpException, Logger, Request, Response};

final class AdminHandler
{
    public static function users(Request $r): void
    {
        $claims = Auth::requireUser($r);
        if (($claims['role'] ?? '') !== 'admin') {
            Logger::event('authz_denied', ['resource' => 'admin_users']);
            throw new HttpException(403, 'forbidden');
        }
        Logger::event('admin_access', ['resource' => 'admin_users']);
        $rows = Db::pdo()->query('SELECT id, username, role FROM users ORDER BY id')->fetchAll();
        Response::json(200, ['users' => $rows]);
    }
}
