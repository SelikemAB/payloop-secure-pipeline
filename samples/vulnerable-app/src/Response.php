<?php
declare(strict_types=1);

namespace PayLoop;

final class Response
{
    /** @param array<string,mixed> $body */
    public static function json(int $status, array $body): void
    {
        http_response_code($status);
        header('Content-Type: application/json');
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: no-store');
        echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
