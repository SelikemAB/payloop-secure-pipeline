<?php
declare(strict_types=1);

namespace PayLoop;

final class Wallets
{
    /** @return array<string,mixed>|null */
    public static function find(int $id): ?array
    {
        $st = Db::pdo()->prepare('SELECT id, owner_id, balance_minor, currency FROM wallets WHERE id = ?');
        $st->execute([$id]);
        $row = $st->fetch();
        return $row === false ? null : $row;
    }

    /**
     * Returns the wallet if the caller owns it (or is admin). Otherwise logs and answers 404,
     * so callers cannot distinguish "not yours" from "does not exist".
     *
     * @param  array<string,mixed> $claims
     * @return array<string,mixed>
     */
    public static function assertAccess(array $claims, int $walletId): array
    {
        $w = self::find($walletId);
        if ($w === null || ((int) $w['owner_id'] !== (int) $claims['sub'] && $claims['role'] !== 'admin')) {
            Logger::event('authz_denied', ['resource' => 'wallet', 'wallet_id' => $walletId]);
            throw new HttpException(404, 'not_found');
        }
        return $w;
    }
}
