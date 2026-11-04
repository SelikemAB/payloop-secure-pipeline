<?php
declare(strict_types=1);

namespace PayLoop\Handlers;

use PayLoop\{Auth, Db, Logger, Request, Response, Wallets};

final class WalletHandler
{
    public static function handle(Request $r): void
    {
        $claims = Auth::requireUser($r);
        $id = (int) ($r->query['id'] ?? 0);

        // Object-level authorisation: only the owner (or an admin) may read a wallet.
        $wallet = Wallets::assertAccess($claims, $id);
        $st = Db::pdo()->prepare('SELECT username FROM users WHERE id = ?');
        $st->execute([$wallet['owner_id']]);
        Logger::event('wallet_view', ['wallet_id' => $id]);
        Response::json(200, [
            'id'            => (int) $wallet['id'],
            'owner'         => $st->fetchColumn(),
            'balance_minor' => (int) $wallet['balance_minor'],
            'currency'      => $wallet['currency'],
        ]);
    }
}
