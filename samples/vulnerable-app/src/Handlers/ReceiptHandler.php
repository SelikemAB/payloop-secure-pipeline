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

        // F3: user input is appended to a directory path with no validation (path traversal).
        $path = Config::receiptsDir() . '/' . $file;
        if (!is_file($path)) {
            throw new HttpException(404, 'not_found');
        }
        Logger::event('receipt_download', ['file' => $file]);
        Response::json(200, ['file' => $file, 'content' => file_get_contents($path)]);
    }
}
