<?php
declare(strict_types=1);

namespace PayLoop\Handlers;

use PayLoop\{Auth, Db, Logger, Request, Response, Wallets};

final class TransferHandler
{
    public static function handle(Request $r): void
    {
        $claims = Auth::requireUser($r);
        $b = $r->json();
        $from = (int) ($b['from_wallet'] ?? 0);
        $to = (int) ($b['to_wallet'] ?? 0);
        $amount = (int) ($b['amount_minor'] ?? 0);
        $note = isset($b['note']) ? (string) $b['note'] : null;
        $idem = $r->header('idempotency-key');
        Wallets::assertAccess($claims, $from);

        // F8: no amount validation, no balance check, no transaction, idempotency key ignored.
        $pdo = Db::pdo();
        $pdo->prepare('UPDATE wallets SET balance_minor = balance_minor - ? WHERE id = ?')->execute([$amount, $from]);
        $pdo->prepare('UPDATE wallets SET balance_minor = balance_minor + ? WHERE id = ?')->execute([$amount, $to]);
        $pdo->prepare('INSERT INTO transfers(from_wallet, to_wallet, amount_minor, idem_key, note, created_at) VALUES (?, ?, ?, NULL, ?, ?)')
            ->execute([$from, $to, $amount, $note, gmdate('c')]);
        $id = (int) $pdo->lastInsertId();

        Logger::event('transfer', ['from_wallet' => $from, 'to_wallet' => $to, 'amount' => $amount, 'idem_key' => $idem]);
        Response::json(201, ['transfer_id' => $id, 'status' => 'completed']);
    }
}
