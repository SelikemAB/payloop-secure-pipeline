<?php
declare(strict_types=1);

namespace PayLoop\Handlers;

use PayLoop\{Auth, HttpException, Logger, Request, Response, SsrfGuard};

final class WebhookTestHandler
{
    public static function handle(Request $r): void
    {
        Auth::requireUser($r);
        $b = $r->json();
        $url = is_string($b['url'] ?? null) ? $b['url'] : '';
        $host = (string) (parse_url($url, PHP_URL_HOST) ?? '');

        try {
            $t = SsrfGuard::validate($url);
        } catch (\InvalidArgumentException $e) {
            Logger::event('ssrf_blocked', ['target_host' => $host, 'reason' => $e->getMessage()]);
            throw new HttpException(400, 'url_not_allowed');
        }
        Logger::event('webhook_fetch', ['target_host' => $t['host'], 'target_ip' => $t['ip']]);

        // Connect to the vetted IP (no second DNS lookup), keep Host/SNI, never follow redirects, cap the body.
        $ctx = stream_context_create([
            'http' => ['method' => 'GET', 'timeout' => 3, 'follow_location' => 0, 'ignore_errors' => true,
                       'header' => "Host: {$t['host']}\r\nUser-Agent: payloop-webhook-tester\r\n"],
            'ssl'  => ['peer_name' => $t['host'], 'verify_peer' => true, 'verify_peer_name' => true],
        ]);
        $body = @file_get_contents("{$t['scheme']}://{$t['ip']}:{$t['port']}{$t['target']}", false, $ctx, 0, 4096);
        if ($body === false) {
            throw new HttpException(502, 'fetch_failed');
        }
        // Only the status line is returned: the response body is never reflected to the caller.
        Response::json(200, ['status_line' => $http_response_header[0] ?? 'n/a']);
    }
}
