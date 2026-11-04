<?php
declare(strict_types=1);

namespace PayLoop\Handlers;

use PayLoop\{Auth, HttpException, Logger, Request, Response};

final class WebhookTestHandler
{
    public static function handle(Request $r): void
    {
        Auth::requireUser($r);
        $b = $r->json();
        $url = is_string($b['url'] ?? null) ? $b['url'] : '';
        $host = (string) (parse_url($url, PHP_URL_HOST) ?? '');
        Logger::event('webhook_fetch', ['target_host' => $host]);

        // F4: the server fetches any URL the caller supplies and echoes the response (SSRF).
        $ctx = stream_context_create(['http' => ['timeout' => 3, 'ignore_errors' => true, 'follow_location' => 1]]);
        $body = @file_get_contents($url, false, $ctx);
        if ($body === false) {
            throw new HttpException(502, 'fetch_failed');
        }
        Response::json(200, [
            'status_line'  => $http_response_header[0] ?? 'n/a',
            'body_preview' => substr($body, 0, 200),
        ]);
    }
}
