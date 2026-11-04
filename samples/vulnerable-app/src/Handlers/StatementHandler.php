<?php
declare(strict_types=1);

namespace PayLoop\Handlers;

use PayLoop\{Auth, Db, Request, Response, Wallets};

final class StatementHandler
{
    public static function handle(Request $r): void
    {
        $claims = Auth::requireUser($r);
        $walletId = (int) ($r->query['wallet'] ?? 0);
        Wallets::assertAccess($claims, $walletId);
        $q = (string) ($r->query['q'] ?? '');

        // F1: the search term is concatenated into the SQL string (SQL injection).
        $sql = "SELECT id, from_wallet, to_wallet, amount_minor, note, created_at FROM transfers "
             . "WHERE (from_wallet = $walletId OR to_wallet = $walletId) "
             . "AND COALESCE(note, '') LIKE '%$q%' ORDER BY id DESC LIMIT 50";
        $rows = Db::pdo()->query($sql)->fetchAll();

        Response::json(200, ['wallet' => $walletId, 'items' => $rows]);
    }
}
