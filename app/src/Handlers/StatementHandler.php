<?php
declare(strict_types=1);

namespace PayLoop\Handlers;

use PayLoop\{Auth, Db, HttpException, Request, Response, Wallets};

final class StatementHandler
{
    public static function handle(Request $r): void
    {
        $claims = Auth::requireUser($r);
        $walletId = (int) ($r->query['wallet'] ?? 0);
        Wallets::assertAccess($claims, $walletId);
        $q = (string) ($r->query['q'] ?? '');
        if (strlen($q) > 100) {
            throw new HttpException(400, 'query_too_long');
        }

        // Parameterised query; LIKE wildcards in user input are escaped so they match literally.
        $st = Db::pdo()->prepare(
            'SELECT id, from_wallet, to_wallet, amount_minor, note, created_at FROM transfers '
            . "WHERE (from_wallet = :w OR to_wallet = :w) AND COALESCE(note, '') LIKE :q ESCAPE '\\' "
            . 'ORDER BY id DESC LIMIT 50'
        );
        $st->execute([':w' => $walletId, ':q' => '%' . addcslashes($q, '%_\\') . '%']);

        Response::json(200, ['wallet' => $walletId, 'items' => $st->fetchAll()]);
    }
}
