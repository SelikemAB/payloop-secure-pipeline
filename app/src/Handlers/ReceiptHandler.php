<?php
declare(strict_types=1);

namespace PayLoop\Handlers;

use PayLoop\{Auth, Config, HttpException, Logger, Request, Response};

final class ReceiptHandler
{
    public static function handle(Request $r): void
    {
        Auth::requireUser($r);
        $file = (string) ($r->query['file'] ?? '');

        // 1) strict allow-list on the file name, 2) canonical path must stay inside the receipts dir.
        if (preg_match('/^receipt-[0-9]{1,10}\.txt$/', $file) !== 1) {
            Logger::event('path_blocked', ['file' => substr($file, 0, 120), 'reason' => 'bad_name']);
            throw new HttpException(404, 'not_found');
        }
        $base = realpath(Config::receiptsDir());
        $path = $base === false ? false : realpath($base . '/' . $file);
        if ($path === false || !str_starts_with($path, $base . DIRECTORY_SEPARATOR)) {
            throw new HttpException(404, 'not_found');
        }
        Logger::event('receipt_download', ['file' => $file]);
        Response::json(200, ['file' => $file, 'content' => file_get_contents($path)]);
    }
}
