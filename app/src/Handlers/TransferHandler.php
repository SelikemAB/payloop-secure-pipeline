<?php
declare(strict_types=1);

namespace PayLoop\Handlers;

use PayLoop\{Auth, Db, HttpException, Logger, Request, Response, Wallets};

final class TransferHandler
{
    private const MAX_AMOUNT_MINOR = 10_000_000;

    public static function handle(Request $r): void
    {
        $claims = Auth::requireUser($r);
        $b = $r->json();
        $from = $b['from_wallet'] ?? null;
        $to = $b['to_wallet'] ?? null;
        $amount = $b['amount_minor'] ?? null;
        $note = $b['note'] ?? null;
        $idem = $r->header('idempotency-key');

        // Strict input validation: integers only, positive, bounded, distinct wallets, key required.
        if (!is_int($from) || !is_int($to) || $from < 1 || $to < 1 || $from === $to) {
            throw self::reject('invalid_wallets', $amount);
        }
        if (!is_int($amount) || $amount < 1 || $amount > self::MAX_AMOUNT_MINOR) {
            throw self::reject('invalid_amount', $amount);
        }
        if ($note !== null && (!is_string($note) || strlen($note) > 140)) {
            throw self::reject('invalid_note', $amount);
        }
        if ($idem === null || preg_match('/^[A-Za-z0-9_-]{8,64}$/', $idem) !== 1) {
            throw self::reject('missing_or_invalid_idempotency_key', $amount);
        }
        Wallets::assertAccess($claims, $from);

        $pdo = Db::pdo();
        $pdo->exec('BEGIN IMMEDIATE');   // takes the write lock: check-then-update is atomic
        try {
            $st = $pdo->prepare('SELECT id, to_wallet, amount_minor FROM transfers WHERE from_wallet = ? AND idem_key = ?');
            $st->execute([$from, $idem]);
            $prior = $st->fetch();
            if ($prior !== false) {
                $pdo->exec('COMMIT');
                Logger::event('transfer_duplicate', ['from_wallet' => $from, 'idem_key' => $idem]);
                if ((int) $prior['to_wallet'] !== $to || (int) $prior['amount_minor'] !== $amount) {
                    throw new HttpException(409, 'idempotency_key_reused');
                }
                Response::json(200, ['transfer_id' => (int) $prior['id'], 'status' => 'completed', 'replayed' => true]);
                return;
            }

            if (Wallets::find($to) === null) {
                throw self::reject('unknown_destination', $amount);
            }
            $st = $pdo->prepare('SELECT balance_minor FROM wallets WHERE id = ?');
            $st->execute([$from]);
            $bal = (int) $st->fetchColumn();
            if ($bal < $amount) {
                throw self::reject('insufficient_funds', $amount, 422, 'insufficient_funds');
            }
            $pdo->prepare('UPDATE wallets SET balance_minor = balance_minor - ? WHERE id = ?')->execute([$amount, $from]);
            $pdo->prepare('UPDATE wallets SET balance_minor = balance_minor + ? WHERE id = ?')->execute([$amount, $to]);
            $pdo->prepare('INSERT INTO transfers(from_wallet, to_wallet, amount_minor, idem_key, note, created_at) VALUES (?, ?, ?, ?, ?, ?)')
                ->execute([$from, $to, $amount, $idem, $note, gmdate('c')]);
            $id = (int) $pdo->lastInsertId();
            $pdo->exec('COMMIT');
        } catch (\Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->exec('ROLLBACK');
            }
            throw $e;
        }

        Logger::event('transfer', ['from_wallet' => $from, 'to_wallet' => $to, 'amount' => $amount, 'idem_key' => $idem]);
        Response::json(201, ['transfer_id' => $id, 'status' => 'completed']);
    }

    private static function reject(string $reason, mixed $amount, int $status = 422, string $code = 'invalid_transfer'): HttpException
    {
        Logger::event('transfer_rejected', [
            'reason' => $reason,
            'amount' => is_scalar($amount) ? (string) $amount : gettype($amount),
        ]);
        return new HttpException($status, $code);
    }
}
